#include "split-commit/split-commit-rec.h"

SplitCommitReceiver::SplitCommitReceiver(uint32_t msg_bits) :
  SplitCommit(msg_bits),
  ot_rnds(std::vector<osuCrypto::PRNG>(cword_bits)),
  seed_ot_choices(cword_bits) {

}

SplitCommitReceiver::SplitCommitReceiver(SplitCommitReceiver&& cp) :
  SplitCommit(std::move(cp)),
  ot_rnds(std::move(cp.ot_rnds)),
  seed_ot_choices(std::move(cp.seed_ot_choices)) {

}

void SplitCommitReceiver::ComputeAndSetSeedOTs(osuCrypto::PRNG& rnd, osuCrypto::Channel& chl) {

  std::vector<std::array<osuCrypto::block, 2>> base_ots(CSEC);

  osuCrypto::NaorPinkas baseOTs;
  baseOTs.send(base_ots, rnd, chl, 1);

  osuCrypto::KosOtExtReceiver kos_receive;
  kos_receive.setBaseOts(base_ots);
  seed_ot_choices.randomize(rnd);
  std::vector<osuCrypto::block> seed_ots(ot_rnds.size());
  kos_receive.receive(seed_ot_choices, seed_ots, rnd, chl);

  for (int i = 0; i < seed_ots.size(); ++i) {
    ot_rnds[i].SetSeed(seed_ots[i]);
  }

  ots_set = true;

}

void SplitCommitReceiver::SetSeedOTs(std::vector<osuCrypto::block> seed_ots, osuCrypto::BitVector seed_ot_choices) {

  for (int i = 0; i < seed_ots.size(); ++i) {
    ot_rnds[i].SetSeed(seed_ots[i]);
  }
  this->seed_ot_choices = seed_ot_choices;

  ots_set = true;
}

std::vector<SplitCommitReceiver> SplitCommitReceiver::GetCloneReceivers(uint32_t num_execs, osuCrypto::PRNG& rnd, std::vector<osuCrypto::PRNG>& exec_rnds) {

  if (!ots_set) {
    throw std::runtime_error("Need to compute OTs before cloning");
    return std::vector<SplitCommitReceiver>();
  }

  uint32_t codeword_length = ot_rnds.size();

  std::vector<osuCrypto::PRNG> rnds(codeword_length);
  for (int i = 0; i < codeword_length; ++i) {
    rnds[i].SetSeed(ot_rnds[i].getSeed());
  }

  std::vector<SplitCommitReceiver> receivers;

  std::array<uint8_t, CSEC_BYTES> tmp;
  for (int e = 0; e < num_execs; ++e) {
    
    receivers.emplace_back(msg_bits);

    std::vector<osuCrypto::block> curr_seed_ots(codeword_length);
    for (int i = 0; i < codeword_length; ++i) {
      rnds[i].get<uint8_t>(tmp.data(), CSEC_BYTES);
      curr_seed_ots[i] = load_block(tmp.data());
    }
    
    receivers[e].SetSeedOTs(curr_seed_ots, seed_ot_choices);

    rnd.get<uint8_t>(tmp.data(), CSEC_BYTES);
    exec_rnds[e].SetSeed(load_block(tmp.data()));
  }

  return receivers;
}

bool SplitCommitReceiver::Commit(BYTEArrayVector& commit_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, uint32_t set_lsb_start_idx, COMMIT_TYPE commit_type) {

  if (!ots_set) {
    throw std::runtime_error("Need to compute and set OTs before committing");
  }

  if (msg_bits == 1 &&
      set_lsb_start_idx != std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("set_lsb does not make sense for bit commit! Do not call Commit with 3 args");
  }

  if (commit_shares.entry_size() != cword_bytes) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (commit_type != NORMAL && msg_bits != 128) {
    throw std::runtime_error("Only supported for k=128!");
  }

  BYTEArrayVector blind_shares(NUM_PAR_CHECKS, cword_bytes);

  ExpandAndTranspose(commit_shares, blind_shares);

  uint32_t num_commits = commit_shares.num_entries();
  bool lsb;
  if (commit_type == ALL_ZERO_LSB_RND) {
    for (int i = 0; i < num_commits; ++i) {
      bool lsb = GetLSB(commit_shares[i]);
      std::fill(commit_shares[i], commit_shares[i] + msg_bytes, 0);
      SetBit(127, lsb, commit_shares[i]);
    }
  } else if (commit_type == ALL_RND_LSB_ZERO) {
    for (int i = 0; i < num_commits; ++i) {
      SetBit(127, 0, commit_shares[i]);
    }
  }

  CheckbitCorrection(commit_shares, blind_shares, set_lsb_start_idx, chl);
  if (ConsistencyCheck(commit_shares, blind_shares, rnd, chl, commit_type)) {
    return true;

  } else {
    return false;
  }
}

bool SplitCommitReceiver::Decommit(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_values, osuCrypto::Channel& chl) {

  if (commit_shares.entry_size() != cword_bytes) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (resulting_values.entry_size() != msg_bytes) {
    throw std::runtime_error("Incorrect msg size provided");
  }

  if (msg_bits == 1 && BITS_TO_BYTES(commit_shares.num_entries()) != resulting_values.num_entries()) {
    throw std::runtime_error("Number of decommit msgs mismatch");
  }

  if (msg_bits != 1 && commit_shares.num_entries() != resulting_values.num_entries()) {
    throw std::runtime_error("Number of decommit msgs mismatch");
  }

  std::array<BYTEArrayVector, 2> decommit_shares = {
    BYTEArrayVector(commit_shares.num_entries(), cword_bytes),
    BYTEArrayVector(commit_shares.num_entries(), cword_bytes)
  };

  chl.recv(decommit_shares[0].data(), decommit_shares[0].size());
  chl.recv(decommit_shares[1].data(), decommit_shares[1].size());

  return VerifyDecommits(decommit_shares, commit_shares, resulting_values);

}

bool SplitCommitReceiver::VerifyDecommits(std::array<BYTEArrayVector, 2>& decommit_shares, BYTEArrayVector& commit_shares, BYTEArrayVector & resulting_values) {

  std::vector<uint8_t> decommited_value(cword_bytes);
  std::vector<uint8_t> check_bits(parity_bytes);
  uint32_t num_values = commit_shares.num_entries();
  for (int j = 0; j < num_values; ++j) {
    //Check value shares
    for (int i = 0; i < msg_bytes; ++i) {
      if ((commit_shares[j][i] ^
           (decommit_shares[1][j][i] &
            seed_ot_choices.data()[i]) ^
           (decommit_shares[0][j][i] &
            ~seed_ot_choices.data()[i])) != 0) {
        return false;
      }
    }
    std::fill(check_bits.begin(), check_bits.end(), 0);

    if (msg_bits == 1) {
      XOR_BitCodeWords(decommited_value.data(), decommit_shares[0][j], decommit_shares[1][j]);
      BitEncode(GetBit(0, decommited_value.data()), check_bits.data());
    } else {
      XOR_CodeWords(decommited_value.data(), decommit_shares[0][j], decommit_shares[1][j]);
      code.encode(decommited_value.data(), check_bits.data());
    }

    //Check checkbit shares
    for (int i = 0; i < parity_bytes; ++i) {
      if ((commit_shares[j][msg_in_cword_offset + i] ^
           (decommit_shares[1][j][msg_in_cword_offset + i] &
            seed_ot_choices.data()[msg_in_cword_offset + i]) ^
           (decommit_shares[0][j][msg_in_cword_offset + i] &
            ~seed_ot_choices.data()[msg_in_cword_offset + i])) != 0 ||
          (check_bits[i] != decommited_value[msg_in_cword_offset + i])) {
        return false;
      }
    }

    if (msg_bits == 1) {
      SetBit(j, GetBit(0, decommited_value.data()), resulting_values.data());
    } else {
      std::copy(decommited_value.data(), decommited_value.data() + msg_in_cword_offset, resulting_values[j]);
    }
  }

  return true; //All checks passed!
}

bool SplitCommitReceiver::BatchDecommit(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_values, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, bool values_received) {

  if (commit_shares.entry_size() != cword_bytes) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (resulting_values.entry_size() != msg_bytes) {
    throw std::runtime_error("Incorrect msg size provided");
  }

  if (msg_bits == 1 && BITS_TO_BYTES(commit_shares.num_entries()) != resulting_values.num_entries()) {
    throw std::runtime_error("Number of decommit msgs mismatch");
  }

  if (msg_bits != 1 && commit_shares.num_entries() != resulting_values.num_entries()) {
    throw std::runtime_error("Number of decommit msgs mismatch");
  }

  //Receive the postulated values
  if (!values_received) {
    chl.recv(resulting_values.data(), resulting_values.size());
  }

  BYTEArrayVector resulting_shares(cword_bits, BATCH_DECOMMIT);
  BYTEArrayVector resulting_values_shares(msg_bits, BATCH_DECOMMIT);
  if (msg_bits == 1) {

    uint32_t num_commits = commit_shares.num_entries();
    BYTEArrayVector resulting_values_in_bytes(num_commits, 1);
    for (int i = 0; i < num_commits; ++i) {
      *resulting_values_in_bytes[i] = GetBit(i, resulting_values.data());
    }

    ComputeShares(commit_shares, resulting_shares, resulting_values_in_bytes, resulting_values_shares, rnd, chl);

  } else {
    ComputeShares(commit_shares, resulting_shares, resulting_values, resulting_values_shares, rnd, chl);
  }

  std::array<BYTEArrayVector, 2> received_shares = {
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT),
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT)
  };

  chl.recv(received_shares[0].data(), received_shares[0].size());
  chl.recv(received_shares[1].data(), received_shares[1].size());

  if (!VerifyTransposedDecommits(received_shares, resulting_shares)) {
    return false; //Decommits didn't match shares
  }

  uint8_t decommit_value[BATCH_DECOMMIT];
  if (msg_bits == 1) {
    XOR_UINT8_T(decommit_value, received_shares[0].data(), received_shares[1].data(), BATCH_DECOMMIT);

    for (int i = 0; i < (BATCH_DECOMMIT * CHAR_BIT); ++i) {
      if (GetBit(i, decommit_value) != GetBit(i, resulting_values_shares.data())) {
        return false; //Values didn't match decommits
      }
    }
  } else {
    for (int i = 0; i < msg_bits; ++i) {
      for (int j = 0; j < BATCH_DECOMMIT; ++j) {
        decommit_value[j] = (received_shares[0][i][j] ^ received_shares[1][i][j]);
      }
      if (!std::equal(decommit_value, decommit_value + BATCH_DECOMMIT, resulting_values_shares[i])) {
        return false; //Values didn't match decommits
      }
    }
  }

  return true;
}

bool SplitCommitReceiver::BatchDecommitLSB(BYTEArrayVector& commit_shares, osuCrypto::BitVector& resulting_values, BYTEArrayVector& blind_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, bool values_received) {

  //Receive the postulated values
  if (!values_received) {
    chl.recv(resulting_values);
  }

  uint32_t num_commits = commit_shares.num_entries();

  BYTEArrayVector resulting_shares(cword_bits, BATCH_DECOMMIT);
  BYTEArrayVector resulting_values_shares(1, BATCH_DECOMMIT);
  BYTEArrayVector resulting_values_in_bytes(num_commits, 1);

  for (int i = 0; i < num_commits; ++i) {
    *resulting_values_in_bytes[i] = resulting_values[i];
  }

  ComputeShares(commit_shares, resulting_shares, resulting_values_in_bytes, resulting_values_shares, rnd, chl);

  osuCrypto::MatrixView<uint8_t> matrix(blind_shares.data(), blind_shares.num_entries(), blind_shares.entry_size());
  osuCrypto::Matrix<uint8_t> trans_matrix(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));

  osuCrypto::sse_transpose(matrix, trans_matrix);

  for (int i = 0; i < cword_bits; ++i) {
    for (int j = 0; j < BATCH_DECOMMIT; ++j) {
      resulting_shares[i][j] ^= trans_matrix[i][j];
    }
  }

  std::array<BYTEArrayVector, 2> received_shares = {
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT),
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT)
  };

  chl.recv(received_shares[0].data(), received_shares[0].size());
  chl.recv(received_shares[1].data(), received_shares[1].size());

  if (!VerifyTransposedDecommits(received_shares, resulting_shares)) {
    return false; //Decommits didn't match shares
  }

  uint8_t decommit_value[BATCH_DECOMMIT];
  XOR_UINT8_T(decommit_value, received_shares[0][127], received_shares[1][127], BATCH_DECOMMIT);

  for (int i = 0; i < (BATCH_DECOMMIT * CHAR_BIT); ++i) {
    if (GetBit(i, decommit_value) != GetBit(i, resulting_values_shares.data())) {
      return false; //Values didn't match decommits
    }
  }

  return true;
}

void SplitCommitReceiver::CheckbitCorrection(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares, uint32_t set_lsb_start_idx, osuCrypto::Channel& chl) {

  uint32_t num_commits = commit_shares.num_entries();
  uint32_t num_total_commits = num_commits + NUM_PAR_CHECKS;

  if (set_lsb_start_idx != std::numeric_limits<uint32_t>::max() &&
      set_lsb_start_idx < num_commits) {
    //Is used to set lsb of specific committed values in a range starting from set_lsb_start_idx. The commits with positions above set_lsb_start_idx will get lsb set to 1

    uint32_t num_corrections = num_commits - set_lsb_start_idx;

    osuCrypto::BitVector lsb_corrections(num_corrections);
    chl.recv(lsb_corrections.data(), lsb_corrections.sizeBytes());

    if (seed_ot_choices[msg_bits - 1]) {
      uint8_t flip_table[] = {REVERSE_BYTE_ORDER[1], 0};
      for (int i = set_lsb_start_idx; i < num_commits; ++i) {
        uint32_t curr_idx = i - set_lsb_start_idx;

        commit_shares[i][msg_bytes - 1] ^= flip_table[lsb_corrections[curr_idx]];
      }
    }
  }

  //Receive correction values
  BYTEArrayVector checkbit_corrections_buf(num_total_commits, parity_bytes);
  chl.recv(checkbit_corrections_buf.data(), checkbit_corrections_buf.size());

  //Run over all commitments and apply the correction to the checkbits. We do this using XOR and AND to do this efficiency. The correction is only applied if we hold the 1-share, so we use byte-wise ANDing to "select" the correction bits in each byte.
  for (int j = 0; j < num_commits; ++j) {
    for (int p = 0; p < parity_bytes; ++p) {
      commit_shares[j][msg_in_cword_offset + p] ^= checkbit_corrections_buf[j][p] & seed_ot_choices.data()[msg_in_cword_offset + p];
    }
  }

  for (int j = 0; j < NUM_PAR_CHECKS; ++j) {
    for (int p = 0; p < parity_bytes; ++p) {
      blind_shares[j][msg_in_cword_offset + p] ^= checkbit_corrections_buf[num_commits + j][p] & seed_ot_choices.data()[msg_in_cword_offset + p];
    }
  }
}

void SplitCommitReceiver::ExpandAndTranspose(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares) {

  uint32_t num_commits = commit_shares.num_entries();

  osuCrypto::Matrix<uint8_t> matrix(cword_bits, BITS_TO_BYTES(num_commits));

  for (int i = 0; i < cword_bits; ++i) {
    ot_rnds[i].get<uint8_t>(matrix[i].data(), matrix.bounds()[1]);
  }

  osuCrypto::MatrixView<uint8_t> trans_matrix(commit_shares.data(), num_commits, cword_bytes);
  osuCrypto::sse_transpose(matrix, trans_matrix);

  //Handle the blinding shares
  osuCrypto::Matrix<uint8_t> blind_matrix(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));

  osuCrypto::MatrixView<uint8_t> trans_blind_matrix(blind_shares.data(), NUM_PAR_CHECKS, cword_bytes);

  for (int i = 0; i < cword_bits; ++i) {
    ot_rnds[i].get<uint8_t>(blind_matrix[i].data(), blind_matrix.bounds()[1]);
  }
  osuCrypto::sse_transpose(blind_matrix, trans_blind_matrix);
}

bool SplitCommitReceiver::ConsistencyCheck(BYTEArrayVector& commit_shares, BYTEArrayVector& blind_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl, COMMIT_TYPE commit_type) {

  BYTEArrayVector resulting_shares(cword_bits, CONSISTENCY);
  BYTEArrayVector dummy0, dummy1;

  ComputeShares(commit_shares, resulting_shares, dummy0, dummy1, rnd, chl);

  osuCrypto::MatrixView<uint8_t> matrix(blind_shares.data(), blind_shares.num_entries(), blind_shares.entry_size());
  osuCrypto::Matrix<uint8_t> trans_matrix(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));

  osuCrypto::sse_transpose(matrix, trans_matrix);

  for (int i = 0; i < cword_bits; ++i) {
    for (int j = 0; j < CONSISTENCY; ++j) {
      resulting_shares[i][j] ^= trans_matrix[i][j];
    }
  }

  std::array<BYTEArrayVector, 2> received_shares = {
    BYTEArrayVector(cword_bits, CONSISTENCY),
    BYTEArrayVector(cword_bits, CONSISTENCY)
  };

  chl.recv(received_shares[0].data(), received_shares[0].size());
  chl.recv(received_shares[1].data(), received_shares[1].size());

  //Check if the decomitted random linear combinations fit the prescribed form.
  if (commit_type == ALL_ZERO_LSB_RND) {
    for (int i = 0; i < 127; ++i) {
      if (seed_ot_choices[i]) {
        if (!std::equal(trans_matrix[i].data(), trans_matrix[i].data() + CONSISTENCY, received_shares[1][i])) {
          return false;
        }
      } else {
        if (!std::equal(trans_matrix[i].data(), trans_matrix[i].data() + CONSISTENCY, received_shares[0][i])) {
          return false;
        }
      }
    }
  } else if (commit_type == ALL_RND_LSB_ZERO) {
    if (seed_ot_choices[127]) {
      if (!std::equal(trans_matrix[127].data(), trans_matrix[127].data() + CONSISTENCY, received_shares[1][127])) {
        return false;
      }
    } else {
      if (!std::equal(trans_matrix[127].data(), trans_matrix[127].data() + CONSISTENCY, received_shares[0][127])) {
        return false;
      }
    }
  }

  if (!VerifyTransposedDecommits(received_shares, resulting_shares)) {
    return false;
  }

  return true;

}

void SplitCommitReceiver::ComputeShares(BYTEArrayVector& commit_shares, BYTEArrayVector& resulting_shares, BYTEArrayVector& resulting_values, BYTEArrayVector& resulting_values_shares, osuCrypto::PRNG& rnd, osuCrypto::Channel& chl) {

  uint32_t num_commits = commit_shares.num_entries();
  uint32_t matrix_stride = PAD_TO_MULTIPLE(num_commits, NUM_PAR_CHECKS); //since we process the commitments in blocks of NUM_PAR_CHECKS

  //Sample and send the consistency check challenge element alpha.
  std::array<uint8_t, CSEC_BYTES> alpha_seed;
  rnd.get<uint8_t>(alpha_seed.data(), CSEC_BYTES);
  chl.send(alpha_seed.data(), CSEC_BYTES);

  uint32_t NUM_CHECKS = resulting_shares.entry_size();
  bool trans_values = (NUM_CHECKS == BATCH_DECOMMIT);

  uint32_t value_bits = 0;
  if (resulting_values.entry_size() == 1) {
    value_bits = 1;
  } else if (resulting_values.entry_size() == 16) {
    value_bits = 128;
  }
  //else {
  //    throw std::runtime_error("bad resulting_values.entry_size() size");
  //}

  osuCrypto::MatrixView<uint8_t> values_matrix;
  osuCrypto::Matrix<uint8_t> values_trans_matrix;

  std::array<std::vector<__m128i>, 2> res_values_tmp = {
    std::vector<__m128i>(value_bits),
    std::vector<__m128i>(value_bits)
  };

  if (trans_values) {
    uint32_t values_matrix_dim = resulting_values_shares.num_entries();

    values_matrix = osuCrypto::MatrixView<uint8_t>(resulting_values.data(), num_commits, resulting_values.entry_size());
    values_trans_matrix.resize(values_matrix_dim, BITS_TO_BYTES(matrix_stride));

    for (int i = 0; i < value_bits; ++i) {
      res_values_tmp[0][i] = _mm_setzero_si128();
      res_values_tmp[1][i] = _mm_setzero_si128();
    }

    osuCrypto::sse_transpose(values_matrix, values_trans_matrix);
  }

  osuCrypto::MatrixView<uint8_t> matrix(commit_shares.data(), num_commits, cword_bytes);

  osuCrypto::Matrix<uint8_t> trans_matrix(cword_bits, BITS_TO_BYTES(matrix_stride));
  osuCrypto::sse_transpose(matrix, trans_matrix);

  //res is twice as large as we do not do degree reduction until the very end, so we need to accumulate a larger intermediate value.
  std::array<std::vector<__m128i>, 2> res = {
    std::vector<__m128i>(cword_bits),
    std::vector<__m128i>(cword_bits)
  };

  __m128i val;
  std::array<__m128i, 2> val_result;

  //Load the initial challenge element
  __m128i alpha = _mm_lddqu_si128((__m128i *) alpha_seed.data());

  uint32_t num_blocks = CEIL_DIVIDE(matrix_stride, NUM_PAR_CHECKS);
  for (int j = 0; j < num_blocks; ++j) {

    auto iter = trans_matrix.data() + j * NUM_PAR_CHECKS_BYTES;
    auto iter_values = values_trans_matrix.data() + j * NUM_PAR_CHECKS_BYTES;

    for (int i = 0; i < cword_bits; ++i) {

      val = _mm_lddqu_si128((__m128i*) iter);

      osuCrypto::mul128(val, alpha, val_result[0], val_result[1]);

      iter += trans_matrix.bounds()[1];

      //Accumulate the val_result into res
      res[0][i] = _mm_xor_si128(res[0][i], val_result[0]);
      res[1][i] = _mm_xor_si128(res[1][i], val_result[1]);

      if (trans_values && (i < value_bits)) {

        val = _mm_lddqu_si128((__m128i*) iter_values);

        osuCrypto::mul128(val, alpha, val_result[0], val_result[1]);

        iter_values += values_trans_matrix.bounds()[1];

        res_values_tmp[0][i] = _mm_xor_si128(res_values_tmp[0][i], val_result[0]);
        res_values_tmp[1][i] = _mm_xor_si128(res_values_tmp[1][i], val_result[1]);
      }
    }

    gfmul128_no_refl(alpha, alpha, alpha);
  }

  //mask is used to select the first NUM_CHECKS linear combinations from res and store in final_result. Needed as we actually produce NUM_PAR_CHECKS linear combinations due to convenience. However we only send and verify NUM_CHECKS of these.
  std::array<uint8_t, CSEC_BYTES> mask = { 0 };
  std::fill(mask.begin(), mask.begin() + NUM_CHECKS, 0xFF);
  __m128i store_mask = _mm_lddqu_si128((__m128i*) mask.data());

  //Reduce and move the NUM_CHECKS first linear combinations into resulting_shares
  for (int i = 0; i < cword_bits; ++i) {

    gfred128_no_refl(res[0][i], res[1][i], res[0][i]);
    _mm_maskmoveu_si128(res[0][i], store_mask, (char*) resulting_shares[i]);

    //Same for values
    if (trans_values && (i < value_bits)) {
      gfred128_no_refl(res_values_tmp[0][i], res_values_tmp[1][i], res_values_tmp[0][i]);
      _mm_maskmoveu_si128(res_values_tmp[0][i], store_mask, (char*) (resulting_values_shares[i]));
    }
  }
}

bool SplitCommitReceiver::VerifyTransposedDecommits(std::array<BYTEArrayVector, 2>& received_shares, BYTEArrayVector& commit_shares) {

  uint32_t NUM_CHECKS = commit_shares.entry_size();
  uint32_t num_values = BYTES_TO_BITS(NUM_CHECKS);

  if (num_values > NUM_PAR_CHECKS) {
    throw std::runtime_error("Unsupported number of values");
  }

  osuCrypto::Matrix<uint8_t> matrix(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));
  osuCrypto::Matrix<uint8_t> trans_matrix(NUM_PAR_CHECKS, BITS_TO_BYTES(cword_bits));

  //Used to select only the first num_values_bytes of each share. Gives us a way of only reading the first NUM_CHECKS linear combinations of an otherwise 128-bit register and zero'ing out the remaining unused bits.
  std::array<uint8_t, CSEC_BYTES> mask = { 0 };
  std::fill(mask.begin(), mask.begin() + NUM_CHECKS, 0xFF);
  __m128i store_mask = _mm_lddqu_si128((__m128i*) mask.data());

  //Read all shares in row-major order and compare choice bits row-wise. We check all num_values in parallel this way. Notice we select only the first num_values bits of each share using store_mask and bit-wise AND.
  __m128i share, share0, share1, tmp;
  for (int i = 0; i < cword_bits; ++i) {
    share = _mm_lddqu_si128((__m128i*) commit_shares[i]);
    share = _mm_and_si128(share, store_mask);

    share0 = _mm_lddqu_si128((__m128i*) received_shares[0][i]);
    share0 = _mm_and_si128(share0, store_mask);

    share1 = _mm_lddqu_si128((__m128i*) received_shares[1][i]);
    share1 = _mm_and_si128(share1, store_mask);

    tmp = _mm_xor_si128(share0, share1);
    _mm_storeu_si128((__m128i*) matrix[i].data(), tmp);

    if (seed_ot_choices[i]) {
      if (!compare128(share, share1)) {
        return false;

      }
    } else {
      if (!compare128(share, share0)) {
        return false;
      }
    }
  }

  //At this point we know that the decommitments match the computed_shares in each position. Next we need to verify that the linear combinations are themselves codewords. Only if both requirements hold we are sure the decommitment is valid.

  //Transpose the decommitted values so we can access them column-wise and thus compute the check-bits.
  osuCrypto::sse_transpose(matrix, trans_matrix);

  std::vector<uint8_t> check_bits(parity_bytes);
  for (int i = 0; i < num_values; ++i) {

    //Reset the check_bits in every check
    std::fill(check_bits.begin(), check_bits.end(), 0);

    if (msg_bits == 1) {
      BitEncode(GetBit(0, trans_matrix[i].data()), check_bits.data());
    } else {
      code.encode(trans_matrix[i].data(), check_bits.data());
    }

    //Ensure that check_bits is actually equal to the checkbits of the column. This ensures that entire column is a codeword.
    if (!std::equal(check_bits.data(), check_bits.data() + parity_bytes, trans_matrix[i].data() + msg_in_cword_offset)) {
      std::cout << "Abort! Linear combination " << i << " is not a codeword" << std::endl;
      return false; //Not a codeword!
    }
  }

  return true; //All checks passed!
}