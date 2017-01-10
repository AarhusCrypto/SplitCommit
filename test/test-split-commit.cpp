#include "test.h"

#include "split-commit/split-commit-snd.h"
#include "split-commit/split-commit-rec.h"

uint32_t num_commits = 5001;
uint32_t num_commits_second = 10000;

class CommitTest : public ::testing::Test {
     
protected:

  std::array<BYTEArrayVector, 2> send_commit_shares;
  BYTEArrayVector rec_commit_shares;
  std::array<BYTEArrayVector, 2> send_commit_shares_second;
  BYTEArrayVector rec_commit_shares_second;

  osuCrypto::PRNG send_rnd, rec_rnd;

  osuCrypto::BtIOService ios;
  osuCrypto::BtEndpoint send_end_point, rec_end_point;

  CommitTest() :
    rec_commit_shares(num_commits, CODEWORD_BYTES),
    rec_commit_shares_second(num_commits_second, CODEWORD_BYTES),
    ios(0),
    send_end_point(ios, default_ip_address, 43701, true, "ep"),
    rec_end_point(ios, default_ip_address, 43701, false, "ep") {

    send_commit_shares = {
      BYTEArrayVector(num_commits, CODEWORD_BYTES),
      BYTEArrayVector(num_commits, CODEWORD_BYTES)
    };

    send_commit_shares_second = {
      BYTEArrayVector(num_commits_second, CODEWORD_BYTES),
      BYTEArrayVector(num_commits_second, CODEWORD_BYTES)
    };

    send_rnd.SetSeed(load_block(constant_seeds[0].data()));
    rec_rnd.SetSeed(load_block(constant_seeds[1].data()));
  };

  ~CommitTest() {
    send_end_point.stop();
    rec_end_point.stop();
    ios.stop();
  }
};

TEST_F(CommitTest, TestBaseOTs) {
  SplitCommitSender commit_snd;
  commit_snd.SetMsgBitSize(128);
  SplitCommitReceiver commit_rec;
  commit_rec.SetMsgBitSize(128);

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    osuCrypto::Channel& send_channel = send_end_point.addChannel("channel", "channel");
    commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);

    send_channel.close();
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    osuCrypto::Channel& rec_channel = rec_end_point.addChannel("channel", "channel");
    commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);

    rec_channel.close();
  });

  ret_snd.wait();
  ret_rec.wait();

  for (int i = 0; i < CODEWORD_BITS; i++) {
    if (commit_rec.seed_ot_choices[i]) {
      ASSERT_TRUE(compare128(commit_snd.ot_rnds[1][i].getSeed(), commit_rec.ot_rnds[i].getSeed()));
    } else {
      ASSERT_TRUE(compare128(commit_snd.ot_rnds[0][i].getSeed(), commit_rec.ot_rnds[i].getSeed()));
    }
  }
}

TEST_F(CommitTest, FullTest) {

  SplitCommitSender commit_snd;
  commit_snd.SetMsgBitSize(128);
  SplitCommitReceiver commit_rec;
  commit_rec.SetMsgBitSize(128);

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    osuCrypto::Channel& send_channel = send_end_point.addChannel("string_channel", "string_channel");
    commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);

    //Test that we can commit multiple times
    commit_snd.Commit(send_commit_shares, send_channel);
    commit_snd.Commit(send_commit_shares_second, send_channel, num_commits_second / 2);

    commit_snd.BatchDecommit(send_commit_shares, send_channel);
    commit_snd.Decommit(send_commit_shares_second, send_channel);

    send_channel.close();
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    osuCrypto::Channel& rec_channel = rec_end_point.addChannel("string_channel", "string_channel");
    commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);

    //Test that we can commit multiple times
    ASSERT_TRUE(commit_rec.Commit(rec_commit_shares, rec_rnd, rec_channel));
    ASSERT_TRUE(commit_rec.Commit(rec_commit_shares_second, rec_rnd, rec_channel, num_commits_second / 2));

    //Test BatchDecommit
    BYTEArrayVector tmp(num_commits, CSEC_BYTES);
    ASSERT_TRUE(commit_rec.BatchDecommit(rec_commit_shares, tmp, rec_rnd, rec_channel));

    BYTEArrayVector tmp_second(num_commits_second, CSEC_BYTES);
    ASSERT_TRUE(commit_rec.Decommit(rec_commit_shares_second, tmp_second, rec_channel));

    rec_channel.close();
  });

  ret_snd.wait();
  ret_rec.wait();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < CODEWORD_BITS; j++) {
      if (commit_rec.seed_ot_choices[j]) {
        ASSERT_EQ(GetBit(j, rec_commit_shares[l]),
                  GetBit(j, send_commit_shares[1][l]));
      } else {
        ASSERT_EQ(GetBit(j, rec_commit_shares[l]),
                  GetBit(j, send_commit_shares[0][l]));
      }
    }
  }

  for (int l = 0; l < num_commits_second; l++) {
    //Test the fixed lsbs
    if (l < (num_commits_second / 2)) {
      ASSERT_FALSE(GetLSB(send_commit_shares_second[0][l]) ^
                   GetLSB(send_commit_shares_second[1][l]));
    } else {
      ASSERT_TRUE(GetLSB(send_commit_shares_second[0][l]) ^
                  GetLSB(send_commit_shares_second[1][l]));
    }

    for (int j = 0; j < CODEWORD_BITS; j++) {
      if (commit_rec.seed_ot_choices[j]) {
        ASSERT_EQ(GetBit(j, rec_commit_shares_second[l]),
                  GetBit(j, send_commit_shares_second[1][l]));
      } else {
        ASSERT_EQ(GetBit(j, rec_commit_shares_second[l]),
                  GetBit(j, send_commit_shares_second[0][l]));
      }
    }
  }
}

class BitCommitTest : public ::testing::Test {

protected:

  std::array<BYTEArrayVector, 2> send_commit_shares;
  BYTEArrayVector rec_commit_shares;
  std::array<BYTEArrayVector, 2> send_commit_shares_second;
  BYTEArrayVector rec_commit_shares_second;

  osuCrypto::PRNG send_rnd, rec_rnd;

  osuCrypto::BtIOService ios;
  osuCrypto::BtEndpoint send_end_point, rec_end_point;

  BitCommitTest() :
    rec_commit_shares(num_commits, BIT_CODEWORD_BYTES),
    rec_commit_shares_second(num_commits_second, BIT_CODEWORD_BYTES),
    ios(0),
    send_end_point(ios, default_ip_address, 43701, true, "ep"),
    rec_end_point(ios, default_ip_address, 43701, false, "ep") {

    send_commit_shares = {
      BYTEArrayVector(num_commits, BIT_CODEWORD_BYTES),
      BYTEArrayVector(num_commits, BIT_CODEWORD_BYTES)
    };

    send_commit_shares_second = {
      BYTEArrayVector(num_commits_second, BIT_CODEWORD_BYTES),
      BYTEArrayVector(num_commits_second, BIT_CODEWORD_BYTES)
    };

    send_rnd.SetSeed(load_block(constant_seeds[0].data()));
    rec_rnd.SetSeed(load_block(constant_seeds[1].data()));
  };

  ~BitCommitTest() {
    send_end_point.stop();
    rec_end_point.stop();
    ios.stop();
  };
};

TEST_F(BitCommitTest, FullTest) {

  SplitCommitSender commit_snd;
  commit_snd.SetMsgBitSize(1);
  SplitCommitReceiver commit_rec;
  commit_rec.SetMsgBitSize(1);

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    osuCrypto::Channel& send_channel = send_end_point.addChannel("bit_channel", "bit_channel");
    commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);

    //Test that we can commit multiple times
    commit_snd.Commit(send_commit_shares, send_channel);
    commit_snd.Commit(send_commit_shares_second, send_channel);

    //Test BatchDecommit
    commit_snd.BatchDecommit(send_commit_shares, send_channel);
    commit_snd.Decommit(send_commit_shares_second, send_channel);

    send_channel.close();
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    osuCrypto::Channel& rec_channel = rec_end_point.addChannel("bit_channel", "bit_channel");
    commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);

    //Test that we can commit multiple times
    ASSERT_TRUE(commit_rec.Commit(rec_commit_shares, rec_rnd, rec_channel));
    ASSERT_TRUE(commit_rec.Commit(rec_commit_shares_second, rec_rnd, rec_channel));

    //Test BatchDecommit
    BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);
    ASSERT_TRUE(commit_rec.BatchDecommit(rec_commit_shares, tmp, rec_rnd, rec_channel));

    BYTEArrayVector tmp_second(BITS_TO_BYTES(num_commits_second), 1);
    ASSERT_TRUE(commit_rec.Decommit(rec_commit_shares_second, tmp_second, rec_channel));

    rec_channel.close();
  });

  ret_snd.wait();
  ret_rec.wait();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < BIT_CODEWORD_BITS; j++) {

      if (commit_rec.seed_ot_choices[j]) {
        ASSERT_EQ(GetBit(j, rec_commit_shares[l]), GetBit(j, send_commit_shares[1][l]));
      } else {
        ASSERT_EQ(GetBit(j, rec_commit_shares[l]), GetBit(j, send_commit_shares[0][l]));
      }
    }
  }

  for (int l = 0; l < num_commits_second; l++) {
    for (int j = 0; j < BIT_CODEWORD_BITS; j++) {
      if (commit_rec.seed_ot_choices[j]) {
        ASSERT_EQ(GetBit(j, rec_commit_shares_second[l]),
                  GetBit(j, send_commit_shares_second[1][l]));
      } else {
        ASSERT_EQ(GetBit(j, rec_commit_shares_second[l]),
                  GetBit(j, send_commit_shares_second[0][l]));
      }
    }
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}