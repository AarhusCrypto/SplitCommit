#ifndef SPLITCOMMIT_SPLITCOMMIT_SND_H_
#define SPLITCOMMIT_SPLITCOMMIT_SND_H_

#include "split-commit/split-commit.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

/**
 * @brief      Class implementing the sender side of the commitment scheme.
 */
class SplitCommitSender : public SplitCommit {
public:

  /**
   * Holds the prngs that are used for generation the commitment messages
   */
  std::array<std::vector<osuCrypto::PRNG>, 2> ot_rnds;
  
  /**
   * @brief      Sets the committed messages bit size. Must be called prior to ComputeAndSetSeedOTs
   *
   * @param[in]  msg_bits  The message bit size. Currently 1 and 128 is supported
   */
  void SetMsgBitSize(uint32_t msg_bits, std::string gen_matrix_path = "");

  /**
   * @brief      Computes and stores the OTs necessary for committing
   *
   * @param      rnd   The prng used for generating randomness
   * @param      chl   The channel used for communicating with the other party
   */
  void ComputeAndSetSeedOTs(osuCrypto::PRNG& rnd, osuCrypto::Channel& chl);

  /**
   * @brief      Allows to set the OTs directly
   *
   * @param[in]  seed_ots  The seed ots
   */
  void SetSeedOTs(std::vector<std::array<osuCrypto::block, 2>> seed_ots);

  /**
   * @brief      Splits the state of the SplitCommitSender into several SplitCommitSender to allow for committing and decomitting using several threads.
   *
   * @param[in]  num_execs  The number of execs to split into
   * @param      senders    Where to store the newly created objects. Senders is assumed to have room for num_execs SplitCommitSenders
   */
  void GetCloneSenders(uint32_t num_execs, std::vector<SplitCommitSender>& senders);

  /**
   * @brief      The function used for committing to random values. Allows for setting the lsb of each commitment with index below set_lsb_start_idx to 0 and to 1 for all above. This is useful for some applications
   *
   * @param      commit_shares      The array to store the resulting commitment shares for the generated random messages. It is assumed that commit_shares is fully initialized. This call will commit to commit_shares[0].num_entries() random commitments.
   * @param      chl                The channel used for communicating with the other party
   * @param[in]  set_lsb_start_idx  The index specifying the cutting point between lsb = 0 and lsb = 1. Defaults to std::numeric_limits<uint32_t>::max(), meaning no bits are fixed
   */
  void Commit(std::array<BYTEArrayVector, 2>& commit_shares, osuCrypto::Channel& chl, uint32_t set_lsb_start_idx = std::numeric_limits<uint32_t>::max(), COMMIT_TYPE commit_type = NORMAL);

  /**
   * @brief      Decommits the commitments defined by the passed shares
   *
   * @param      decommit_shares  The decommit shares
   * @param      chl              The channel used for communicating with the other party
   */
  void Decommit(std::array<BYTEArrayVector, 2>& decommit_shares, osuCrypto::Channel& chl);

  /**
   * @brief      Batch Decommits the commitments defined by the passed shares. Batch Decommitment requires less bandwidth than normal Decommit and is preferrable when decommitting to several values at a time
   *
   * @param      decommit_shares  The decommit shares
   * @param      chl              The channel used for communicating with the other party
   * @param      values_sent  Boolean indicating if the values have already been sent by the sender or not
   */
  void BatchDecommit(std::array<BYTEArrayVector, 2>& decommit_shares, osuCrypto::Channel& chl, bool values_sent = false);

  /**
   * @brief      Batch Decommits the lsb of the commitments defined by the passed shares.
   *
   * @param      decommit_shares  The decommit shares
   * @param      blind_shares     Shares used to blind each of the random linear combinations. Must be of the form R||0 which can be created using Commit
   * @param      chl              The channel used for communicating with the other party
   * @param      values_sent      Boolean indicating if the values have already been sent by the sender or not
   */
  void BatchDecommitLSB(std::array<BYTEArrayVector, 2>& decommit_shares, std::array<BYTEArrayVector, 2>& blind_shares, osuCrypto::Channel& chl, bool values_sent = false);

private:

  /**
   * @brief      Defines the random messages
   *
   * @param      commit_shares  The commit shares
   * @param      blind_shares   Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   */
  void ExpandAndTranspose(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares);

  /**
   * @brief      Turns the commit_shares into shares of codewords instead of random strings
   *
   * @param      commit_shares      The commit shares
   * @param      blind_shares       Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   * @param[in]  set_lsb_start_idx   The index specifying the cutting point between lsb = 0 and lsb = 1.
   * @param      chl                The channel used for communicating with the other party
   */
  void CheckbitCorrection(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares, uint32_t set_lsb_start_idx, osuCrypto::Channel& chl);

  /**
   * @brief      Runs a consistency check to ensure the corrected shares are of codewords
   *
   * @param      commit_shares  The commit shares
   * @param      blind_shares   Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   * @param      chl            The channel used for communicating with the other party
   */
  void ConsistencyCheck(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares, osuCrypto::Channel& chl);

  /**
   * @brief      Calculates random linear combinations of the provided shares
   *
   * @param      commit_shares     The commit shares
   * @param      resulting_shares  The resulting random shares. Will compute resulting_shares[0].entry_size() random linear combinations
   * @param      chl               The channel used for communicating with the other party
   */
  void ComputeShares(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& resulting_shares, osuCrypto::Channel& chl);
};

#endif /* SPLITCOMMIT_SPLITCOMMIT_SND_H_ */