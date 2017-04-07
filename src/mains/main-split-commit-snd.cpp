#include "mains.h"

#include "split-commit/split-commit-snd.h"

int main(int argc, const char* argv[]) {
  ezOptionParser opt;

  opt.overview = "Commit Sender Passing Parameters Guide.";
  opt.syntax = "Commitsnd first second";
  opt.example = "Commitsnd -n 10000 -e 4 -ip 10.11.100.216 -p 28001 \n\n";
  opt.footer = "ezOptionParser 0.1.4  Copyright (C) 2011 Remik Ziemlinski\nThis program is free and without warranty.\n";

  opt.add(
    "", // Default.
    0, // Required?
    0, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Display usage instructions.", // Help description.
    "-h",     // Flag token.
    "-help",  // Flag token.
    "--help", // Flag token.
    "--usage" // Flag token.
  );

  opt.add(
    default_num_commits.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Number of commits to produce and decommit.", // Help description.
    "-n"
  );

  opt.add(
    default_num_commit_execs.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Number of parallel executions to run. These will share the workload.", // Help description.
    "-e" // Flag token.
  );

  opt.add(
    default_ip_address.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "IP Address of Machine running Commitsnd", // Help description.
    "-ip"
  );

  opt.add(
    default_port.c_str(), // Default.
    0, // Required?
    1, // Number of args expected.
    0, // Delimiter if expecting multiple args.
    "Port to listen on/connect to", // Help description.
    "-p"
  );

  //Attempt to parse input
  opt.parse(argc, argv);

  //Check if help was requested and do some basic validation
  if (opt.isSet("-h")) {
    Usage(opt);
    return 1;
  }
  std::vector<std::string> badOptions;
  if (!opt.gotExpected(badOptions)) {
    for (int i = 0; i < badOptions.size(); ++i)
      std::cerr << "ERROR: Got unexpected number of arguments for option " << badOptions[i] << ".\n\n";
    Usage(opt);
    return 1;
  }

  //Copy inputs into the right variables
  int num_commits, num_execs, port, print_special_format;
  std::string ip_address;

  opt.get("-n")->getInt(num_commits);
  opt.get("-e")->getInt(num_execs);
  opt.get("-p")->getInt(port);
  opt.get("-ip")->getString(ip_address);

  osuCrypto::IOService ios(0);
  osuCrypto::Endpoint send_end_point(ios, ip_address, port, osuCrypto::EpMode::Server, "ep");
  osuCrypto::Channel send_ot_channel = send_end_point.addChannel("ot_channel", "ot_channel");

  osuCrypto::PRNG rnd;
  rnd.SetSeed(load_block(constant_seeds[0].data()));
  
  SplitCommitSender base_sender;
  base_sender.SetMsgBitSize(128);

  //Seed OTs
  auto seed_ot_begin = GET_TIME();

  base_sender.ComputeAndSetSeedOTs(rnd, send_ot_channel);
  send_ot_channel.close();

  auto seed_ot_end = GET_TIME();

  std::vector<osuCrypto::Channel> send_channels;
  for (int e = 0; e < num_execs; ++e) {
    send_channels.emplace_back(send_end_point.addChannel("commit_channel_" + std::to_string(e), "commit_channel_" + std::to_string(e)));
  }

  std::vector<SplitCommitSender> senders(num_execs);
  base_sender.GetCloneSenders(num_execs, senders);

  ctpl::thread_pool thread_pool(std::thread::hardware_concurrency());

  std::vector<std::future<void>> futures(num_execs);
  uint32_t exec_num_commits = CEIL_DIVIDE(num_commits, num_execs);

  auto commit_begin = GET_TIME();
  std::vector<std::array<BYTEArrayVector, 2>> send_commit_shares(num_execs, {
    BYTEArrayVector(exec_num_commits, CODEWORD_BYTES),
    BYTEArrayVector(exec_num_commits, CODEWORD_BYTES)
  });

  for (int e = 0; e < num_execs; ++e) {
    futures[e] = thread_pool.push([&send_end_point, &senders, &send_commit_shares, &send_channels, exec_num_commits, e](int id) {


      senders[e].Commit(send_commit_shares[e], send_channels[e]);

    });
  }

  for (std::future<void>& r : futures) {
    r.wait();
  }

  auto commit_end = GET_TIME();

  auto decommit_begin = GET_TIME();
  for (int e = 0; e < num_execs; ++e) {
    futures[e] = thread_pool.push([&send_end_point, &senders, &send_commit_shares, &send_channels, exec_num_commits, e](int id) {


      senders[e].Decommit(send_commit_shares[e], send_channels[e]);

    });
  }

  for (std::future<void>& r : futures) {
    r.wait();
  }

  auto decommit_end = GET_TIME();

  auto batch_decommit_begin = GET_TIME();
  for (int e = 0; e < num_execs; ++e) {
    futures[e] = thread_pool.push([&send_end_point, &senders, &send_commit_shares, &send_channels, exec_num_commits, e](int id) {


      senders[e].BatchDecommit(send_commit_shares[e], send_channels[e]);

    });
  }

  for (std::future<void>& r : futures) {
    r.wait();
  }

  auto batch_decommit_end = GET_TIME();

  for (int e = 0; e < num_execs; ++e) {
    send_channels[e].close();
  }

  send_end_point.stop();
  ios.stop();

  uint64_t seed_ot_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(seed_ot_end - seed_ot_begin).count();
  uint64_t commit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(commit_end - commit_begin).count();
  uint64_t decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(decommit_end - decommit_begin).count();
  uint64_t batch_decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(batch_decommit_end - batch_decommit_begin).count();

    std::cout << "===== Timings for sender doing " << num_commits << " random commits using " << num_execs << " parallel execs " << std::endl;

    std::cout << "OT ms: " << (double) seed_ot_time_nano / 1000000 << std::endl;
    std::cout << "Amortized OT ms: " << (double) seed_ot_time_nano / num_commits / 1000000 << std::endl;
    std::cout << "Commit us (with OT): " << (double) (commit_time_nano + seed_ot_time_nano) / num_commits / 1000 << std::endl;
    std::cout << "Commit us: " << (double) commit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "Commit total ms: " << (double) (commit_time_nano + seed_ot_time_nano) / 1000000 << std::endl;
    std::cout << "Decommit us: " << (double) decommit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "Decommit total ms: " << (double) decommit_time_nano / 1000000 << std::endl;
    std::cout << "BatchDecommit us: " << (double) batch_decommit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "BatchDecommit total ms: " << (double) batch_decommit_time_nano / 1000000 << std::endl;

  return 0;
}