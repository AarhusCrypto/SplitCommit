#include "ezOptionParser/ezOptionParser.hpp"

using namespace ez;

//Hardcoded default values
static std::string default_ip_address("localhost");
static std::string default_port("28001");

static std::string default_num_commits("10000");
static std::string default_num_commit_execs("1");

void Usage(ezOptionParser& opt) {
  std::string usage;
  opt.getUsage(usage);
  std::cout << usage;
};