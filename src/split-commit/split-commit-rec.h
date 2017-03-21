#ifndef SPLITCOMMIT_SPLITCOMMIT_REC_H_
#define SPLITCOMMIT_SPLITCOMMIT_REC_H_

#include "split-commit/split-commit.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"

/**
 * @brief      Class implementing the receiver side of the commitment scheme.
 */
class SplitCommitReceiver : public SplitCommit {
public:

  /**
   * Holds the prngs that are used for generation the commitment messages as well as the associated ot_choices
   */
  std::vector<osuCrypto::PRNG> ot_rnds;
  osuCrypto::BitVector seed_ot_choices;

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
  void SetSeedOTs(std::vector<osuCrypto::block> seed_ots, osuCrypto::BitVector seed_ot_choices);

  /**
   * @brief      Splits the state of the SplitCommitReceiver into several SplitCommitReceiver to allow for committing and decomitting using several threads.
   *
   * @param[in]  num_execs  The number of execs to split into
   * @param      senders    Where to store the newly created objects. Senders is assumed to have room for num_execs SplitCommitReceiver
   */
  void GetCloneReceivers(uint32_t num_execs, osuCrypto::PRNG& rnd, std::vector<SplitCommitReceiver>& receivers, std::vector<osuCrypto::PRNG>& exec_rnds);

  /**
   * @brief      The function used for committing to random values. Allows for setting the lsb of each commitment with index below set_lsb_start_idx to 0 and to 1 for all above. This is useful for some applications
   *
   * @param      commit_shares      The array to store the resulting commitment shares for the generated random messages. It is assumed that commit_shares is fully initialized. This call will commit to commit_shares.num_entries() random commitments.
   * @param      rnd                The prng used for randomness generation
   * @param      chl                The channel used for communicating with the other party
   * @param  set_lsb_start_idx  The index specifying the start of commits with lsb = 1. Defaults to std::numeric_limits<uint32_t>::max(), meaning no bits are fixed this way
   *
   * @return     true if commit succeeds, else false
   */
  bool Commit(BYTEArrayVector& commit_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, uint32_t set_lsb_start_idx = std::numeric_limits<uint32_t>::max(), COMMIT_TYPE commit_type = NORMAL);

  /**
   * @brief      Receives and Decommits the specified commitments
   * @param      decommit_shares  The held commit_shares
   * @param      resulting_values Where to store the resulting values if the decommits succeed
   * @param      chl              The channel used for communicating with the other party
   * 
   * @return     true if commit succeeds, else false
   */
  bool Decommit(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_values, osuCrypto::Channel& chl);

  /**
   * @brief      Verifies the provided decommit_shares using the held commit_shares
   *
   * @param      decommit_shares   The decommit shares
   * @param      commit_shares     The commit shares
   * @param      resulting_values  The resulting values
   *
   * @return     true if check succeeds, else false
   */
  bool VerifyDecommits(std::array<BYTEArrayVector, 2>& decommit_shares, BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_values);

  /**
   * @brief      Batch Decommits the commitments defined by the passed shares. Batch Decommitment requires less bandwidth than normal Decommit and is preferrable when decommitting to several values at a time
   *
   * @param      commit_shares     The commit shares
   * @param      resulting_values  Where to store the resulting values if the decommits succeed
   * @param      rnd               The prng used for randomness generation
   * @param      chl               The chl
   * @param      values_received   Boolean indicating if the values have already been sent by the sender or not
   *
   * @return     true if decommit passes, else false
   */
  bool BatchDecommit(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_values, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, bool values_received = false);


  /**
     * @brief      Batch Decommits the lsb of the commitments defined by the passed shares.
     *
     * @param      commit_shares     The commit shares
     * @param      resulting_values  Where to store the resulting values if the decommits succeed
     * @param      blind_shares      Shares used to blind each of the random linear combinations. Must be of the form R||0 which can be created using Commit
     * @param      rnd               The prng used for randomness generation
     * @param      chl               The chl
     * @param      values_received   Boolean indicating if the values have already been sent by the sender or not
     *
     * @return     true if decommit passes, else false
     */
  bool BatchDecommitLSB(BYTEArrayVector& commit_shares, osuCrypto::BitVector& resulting_values, BYTEArrayVector& blind_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, bool values_received = false);

private:

  /**
   * @brief      Defines the random messages
   *
   * @param      commit_shares  The commit shares
   * @param      blind_shares   Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   */
  void ExpandAndTranspose(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares);

  /**
   * @brief      Turns the commit_shares into shares of codewords instead of random strings
   *
   * @param      commit_shares      The commit shares
   * @param      blind_shares       Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   * @param[in]  set_lsb_start_idx  The index specifying the start of commits with lsb = 1.
   * @param       this waychl                The channel used for communicating with the other party
   */
  void CheckbitCorrection(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares, uint32_t set_lsb_start_idx, osuCrypto::Channel& chl);

  /**
   * @brief      Runs a consistency check to ensure the corrected shares are of codewords
   *
   * @param      commit_shares  The commit shares
   * @param      blind_shares   Used to blind the CONSISTENCY random linear combinations that will be decommitted as part of a Commit call
   * @param      rnd            The prng used for randomness generation
   * @param      chl            The channel used for communicating with the other party
   *
   * @return     true if check succeeds, else false
   */
  bool ConsistencyCheck(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, COMMIT_TYPE commit_type);

  /**
   * @brief      Calculates random linear combinations of the provided shares
   *
   * @param      commit_shares            The commit shares
   * @param      resulting_shares         The resulting random shares. Will compute resulting_shares.entry_size() random linear combinations
   * @param      resulting_values         Used if called by BatchDecommit. Computes the same random combination of the provided values
   * @param      resulting_values_shares  Used if called by BatchDecommit. Computes the same random combination of the provided values
   * @param      rnd                      The prng used for randomness generation
   * @param      chl                      The channel used for communicating with the other party
   */
  void ComputeShares(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_shares, BYTEArrayVector& resulting_values, BYTEArrayVector& resulting_values_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl);

  /**
   * @brief      Verifies the provided received_shares towards the provided resulting_shares and that the resulting values are indeed codewords. This call is used by ConsistencyCheck and BatchDecommit to only check the resulting linear combinations
   *
   * @param      received_shares   The received shares
   * @param      commit_shares     The computed commit_shares
   *
   * @return     true if check succeeds, else false
   */
  bool VerifyTransposedDecommits(std::array<BYTEArrayVector, 2>& received_shares, BYTEArrayVector& commit_shares);
};
#endif /* SPLITCOMMIT_SPLITCOMMIT_REC_H_ */