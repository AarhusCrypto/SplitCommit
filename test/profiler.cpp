


#include "mains.h"

#include "split-commit/split-commit-snd.h"
#include "split-commit/split-commit-rec.h"

#include "cryptoTools/Common/Defines.h"
using namespace osuCrypto;
int senderRoutine(std::string ip_address, int port, int num_execs, int num_commits);
int receiverRoutine(std::string ip_address, int port, int num_execs, int num_commits);


int main(int arc, char** argv)
{
    u64 numCommit = u64(1) << 24;

    std::thread thrd([=]() {receiverRoutine("localhost", 1212, 1, numCommit); });

    senderRoutine("localhost", 1212, 1, numCommit);
    
    thrd.join();
}



int senderRoutine(std::string ip_address, int port, int num_execs, int num_commits)
{

    BtIOService ios(0);
    BtEndpoint send_end_point(ios, ip_address, port, true, "ep");
    Channel& chl = send_end_point.addChannel("ot_channel", "ot_channel");

    PRNG rnd;
    rnd.SetSeed(ZeroBlock);

    SplitCommitSender base_sender;
    base_sender.SetMsgBitSize(128);

    //Seed OTs
    auto seed_ot_begin = GET_TIME();

    base_sender.ComputeAndSetSeedOTs(rnd, chl);

    auto seed_ot_end = GET_TIME();

    std::vector<SplitCommitSender> senders(num_execs);
    base_sender.GetCloneSenders(num_execs, senders);


    uint32_t exec_num_commits = CEIL_DIVIDE(num_commits, num_execs);

    auto commit_begin = GET_TIME();
    std::vector<std::array<BYTEArrayVector, 2>> send_commit_shares(num_execs, {
        BYTEArrayVector(exec_num_commits, CODEWORD_BYTES),
        BYTEArrayVector(exec_num_commits, CODEWORD_BYTES)
    });

    for (int e = 0; e < num_execs; ++e)
    {
        senders[e].Commit(send_commit_shares[e], chl);
    }


    auto commit_end = GET_TIME();

    auto decommit_begin = GET_TIME();
    for (int e = 0; e < num_execs; ++e)
    {
        senders[e].Decommit(send_commit_shares[e], chl);
    }


    auto decommit_end = GET_TIME();

    auto batch_decommit_begin = GET_TIME();
    for (int e = 0; e < num_execs; ++e)
    {
        senders[e].BatchDecommit(send_commit_shares[e], chl);
    }

    auto batch_decommit_end = GET_TIME();

    chl.close();
    send_end_point.stop();
    ios.stop();

    uint64_t seed_ot_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(seed_ot_end - seed_ot_begin).count();
    uint64_t commit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(commit_end - commit_begin).count();
    uint64_t decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(decommit_end - decommit_begin).count();
    uint64_t batch_decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(batch_decommit_end - batch_decommit_begin).count();

    std::cout << "===== Timings for sender doing " << num_commits << " random commits using " << num_execs << " parallel execs " << std::endl;

    std::cout << "OT ms: " << (double)seed_ot_time_nano / 1000000 << std::endl;
    std::cout << "Amortized OT ms: " << (double)seed_ot_time_nano / num_commits / 1000000 << std::endl;
    std::cout << "Commit us (with OT): " << (double)(commit_time_nano + seed_ot_time_nano) / num_commits / 1000 << std::endl;
    std::cout << "Commit us: " << (double)commit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "Commit total ms: " << (double)(commit_time_nano + seed_ot_time_nano) / 1000000 << std::endl;
    std::cout << "Decommit us: " << (double)decommit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "Decommit total ms: " << (double)decommit_time_nano / 1000000 << std::endl;
    std::cout << "BatchDecommit us: " << (double)batch_decommit_time_nano / num_commits / 1000 << std::endl;
    std::cout << "BatchDecommit total ms: " << (double)batch_decommit_time_nano / 1000000 << std::endl;

    return 0;
}




int receiverRoutine(std::string ip_address, int port, int num_execs, int num_commits)
{

    BtIOService ios(0);
    BtEndpoint rec_end_point(ios, ip_address, port, false, "ep");
    Channel& chl = rec_end_point.addChannel("ot_channel", "ot_channel");

    PRNG rnd;
    rnd.SetSeed(ZeroBlock);
    SplitCommitReceiver base_receiver;
    base_receiver.SetMsgBitSize(128);

    //Seed OTs
    auto seed_ot_begin = GET_TIME();

    base_receiver.ComputeAndSetSeedOTs(rnd, chl);

    auto seed_ot_end = GET_TIME();

    std::vector<SplitCommitReceiver> receivers(num_execs);
    std::vector<PRNG> exec_rnds(num_execs);

    base_receiver.GetCloneReceivers(num_execs, rnd, receivers, exec_rnds);

    uint32_t exec_num_commits = CEIL_DIVIDE(num_commits, num_execs);

    auto commit_begin = GET_TIME();
    std::vector<BYTEArrayVector> rec_commit_shares(num_execs, BYTEArrayVector(exec_num_commits, CODEWORD_BYTES));
    for (int e = 0; e < num_execs; ++e) {


        receivers[e].Commit(rec_commit_shares[e], exec_rnds[e], chl);

    }


    auto commit_end = GET_TIME();

    auto decommit_begin = GET_TIME();
    BYTEArrayVector tmp(exec_num_commits, CSEC_BYTES);

    for (int e = 0; e < num_execs; ++e)
    {
        receivers[e].Decommit(rec_commit_shares[e], tmp, chl);
    }


    auto decommit_end = GET_TIME();

    auto batch_decommit_begin = GET_TIME();

    for (int e = 0; e < num_execs; ++e) {


        receivers[e].BatchDecommit(rec_commit_shares[e], tmp, exec_rnds[e], chl);

    }

    auto batch_decommit_end = GET_TIME();

    chl.close();
    rec_end_point.stop();
    ios.stop();

    uint64_t seed_ot_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(seed_ot_end - seed_ot_begin).count();
    uint64_t commit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(commit_end - commit_begin).count();
    uint64_t decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(decommit_end - decommit_begin).count();
    uint64_t batch_decommit_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(batch_decommit_end - batch_decommit_begin).count();

    //std::cout << "===== Timings for receiver doing " << num_commits << " random commits using " << num_execs << " parallel execs " << std::endl;

    //std::cout << "OT ms: " << (double)seed_ot_time_nano / 1000000 << std::endl;
    //std::cout << "Amortized OT ms: " << (double)seed_ot_time_nano / num_commits / 1000000 << std::endl;
    //std::cout << "Commit us (with OT): " << (double)(commit_time_nano + seed_ot_time_nano) / num_commits / 1000 << std::endl;
    //std::cout << "Commit us: " << (double)commit_time_nano / num_commits / 1000 << std::endl;
    //std::cout << "Commit total ms: " << (double)(commit_time_nano + seed_ot_time_nano) / 1000000 << std::endl;
    //std::cout << "Decommit us: " << (double)decommit_time_nano / num_commits / 1000 << std::endl;
    //std::cout << "Decommit total ms: " << (double)decommit_time_nano / 1000000 << std::endl;
    //std::cout << "BatchDecommit us: " << (double)batch_decommit_time_nano / num_commits / 1000 << std::endl;
    //std::cout << "BatchDecommit total ms: " << (double)batch_decommit_time_nano / 1000000 << std::endl;

    return 0;
}
