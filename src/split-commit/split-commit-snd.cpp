#include "split-commit/split-commit-snd.h"

void SplitCommitSender::SetMsgBitSize(uint32_t msg_bits, std::string gen_matrix_path) {

  LoadCode(msg_bits, gen_matrix_path);

  ot_rnds = {
    std::vector<osuCrypto::PRNG>(cword_bits),
    std::vector<osuCrypto::PRNG>(cword_bits)
  };

  msg_size_set = true;
}

void SplitCommitSender::ComputeAndSetSeedOTs(osuCrypto::PRNG& rnd, osuCrypto::Channel& chl) {

  if (!msg_size_set) {
    throw std::runtime_error("Need to set the msg size");
  }

  std::vector<osuCrypto::block> base_ots(CSEC);
  osuCrypto::BitVector base_ot_choices(CSEC);
  base_ot_choices.randomize(rnd);

  osuCrypto::NaorPinkas baseOTs;
  baseOTs.receive(base_ot_choices, base_ots, rnd, chl, 1);

  osuCrypto::KosOtExtSender kos_sender;
  kos_sender.setBaseOts(base_ots, base_ot_choices);
  std::vector<std::array<osuCrypto::block, 2>> seed_ots(ot_rnds[0].size());
  kos_sender.send(seed_ots, rnd, chl);

  for (int i = 0; i < seed_ots.size(); ++i) {
    ot_rnds[0][i].SetSeed(seed_ots[i][0]);
    ot_rnds[1][i].SetSeed(seed_ots[i][1]);
  }

  ots_set = true;
}

void SplitCommitSender::SetSeedOTs(std::vector<std::array<osuCrypto::block, 2>> seed_ots) {

  for (int i = 0; i < seed_ots.size(); ++i) {
    ot_rnds[0][i].SetSeed(seed_ots[i][0]);
    ot_rnds[1][i].SetSeed(seed_ots[i][1]);
  }

  ots_set = true;
}

void SplitCommitSender::GetCloneSenders(uint32_t num_execs, std::vector<SplitCommitSender>& senders) {

  if (!msg_size_set || !ots_set) {
    throw std::runtime_error("Need to set the msg size and compute OTs before cloning");
    return;
  }

  uint32_t codeword_length = ot_rnds[0].size();

  std::array<std::vector<osuCrypto::PRNG>, 2> rnds = {
    std::vector<osuCrypto::PRNG>(codeword_length),
    std::vector<osuCrypto::PRNG>(codeword_length)
  };

  for (int i = 0; i < codeword_length; ++i) {
    rnds[0][i].SetSeed(ot_rnds[0][i].getSeed());
    rnds[1][i].SetSeed(ot_rnds[1][i].getSeed());
  }

  std::array<uint8_t, CSEC_BYTES> tmp;
  for (int e = 0; e < num_execs; ++e) {
    std::vector<std::array<osuCrypto::block, 2>> curr_seed_ots(codeword_length);
    for (int i = 0; i < codeword_length; ++i) {
      rnds[0][i].get<uint8_t>(tmp.data(), CSEC_BYTES);
      curr_seed_ots[i][0] = load_block(tmp.data());

      rnds[1][i].get<uint8_t>(tmp.data(), CSEC_BYTES);
      curr_seed_ots[i][1] = load_block(tmp.data());
    }
    senders[e].SetMsgBitSize(msg_bits, gen_matrix_path);
    senders[e].SetSeedOTs(curr_seed_ots);
  }
}

void SplitCommitSender::Commit(std::array<BYTEArrayVector, 2>& commit_shares, osuCrypto::Channel& chl, uint32_t set_lsb_start_idx) {

  if (!ots_set) {
    throw std::runtime_error("Need to compute and set OTs before committing");
  }

  if (msg_bits == 1 &&
      set_lsb_start_idx != std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("set_lsb does not make sense for bit commit! Do not call Commit with 3 args");
  }

  if ((commit_shares[0].entry_size() != cword_bytes) ||
      (commit_shares[1].entry_size() != cword_bytes)
     ) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (commit_shares[0].num_entries() != commit_shares[1].num_entries()) {
    throw std::runtime_error("Share size mismatch");
  }

  std::array<BYTEArrayVector, 2> blind_shares = {
    BYTEArrayVector(NUM_PAR_CHECKS, cword_bytes),
    BYTEArrayVector(NUM_PAR_CHECKS, cword_bytes)
  };

  ExpandAndTranspose(commit_shares, blind_shares);
  CheckbitCorrection(commit_shares, blind_shares, set_lsb_start_idx, chl);

  ConsistencyCheck(commit_shares, blind_shares, chl);

}

void SplitCommitSender::Decommit(std::array<BYTEArrayVector, 2>& decommit_shares, osuCrypto::Channel& chl) {

  if ((decommit_shares[0].entry_size() != cword_bytes) ||
      (decommit_shares[1].entry_size() != cword_bytes)
     ) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (decommit_shares[0].num_entries() != decommit_shares[1].num_entries()) {
    throw std::runtime_error("Share size mismatch");
  }

  chl.asyncSendCopy(decommit_shares[0].data(), decommit_shares[0].size());
  chl.asyncSendCopy(decommit_shares[1].data(), decommit_shares[1].size());
}

void SplitCommitSender::BatchDecommit(std::array<BYTEArrayVector, 2>& decommit_shares, osuCrypto::Channel& chl, bool values_sent) {

  if ((decommit_shares[0].entry_size() != cword_bytes) ||
      (decommit_shares[1].entry_size() != cword_bytes)
     ) {
    throw std::runtime_error("Incorrect codeword size provided");
  }

  if (decommit_shares[0].num_entries() != decommit_shares[1].num_entries()) {
    throw std::runtime_error("Share size mismatch");
  }

  if (!values_sent) {

    uint32_t num_values = decommit_shares[0].num_entries();

    //Create and send the postulated values
    std::unique_ptr<BYTEArrayVector> decommit_values;
    if (msg_bits == 1) {

      decommit_values = std::make_unique<BYTEArrayVector>(BYTEArrayVector(BITS_TO_BYTES(num_values), 1));
      for (int l = 0; l < num_values; ++l) {
        SetBit(l, GetBit(0, decommit_shares[0][l]), decommit_values->data());
        XORBit(l, GetBit(0, decommit_shares[1][l]), decommit_values->data());
      }
    } else if (msg_bits == 128) {

      decommit_values = std::make_unique<BYTEArrayVector>(BYTEArrayVector(num_values, msg_bytes));
      for (int l = 0; l < num_values; ++l) {
        XOR_128((*decommit_values)[l], decommit_shares[0][l], decommit_shares[1][l]);

      }
    } else {
      throw std::runtime_error("Invalid call to BatchDecommit!");
    }

    chl.asyncSend(std::move(decommit_values));
  }

  std::array<BYTEArrayVector, 2> resulting_shares = {
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT),
    BYTEArrayVector(cword_bits, BATCH_DECOMMIT)
  };

  ComputeShares(decommit_shares, resulting_shares, chl);

  //Convert to unique_ptr for asyncSend
  std::array<std::unique_ptr<BYTEArrayVector>, 2> resulting_shares_ptr = {
    std::make_unique<BYTEArrayVector>(BYTEArrayVector(std::move(resulting_shares[0]))),
    std::make_unique<BYTEArrayVector>(BYTEArrayVector(std::move(resulting_shares[1])))
  };

  //Send the resulting decommitments
  chl.asyncSend(std::move(resulting_shares_ptr[0]));
  chl.asyncSend(std::move(resulting_shares_ptr[1]));
}

void SplitCommitSender::ExpandAndTranspose(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares) {

  uint32_t num_commits = commit_shares[0].num_entries();

  std::array<osuCrypto::MatrixView<uint8_t>, 2> matrix = {
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(num_commits)),
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(num_commits))
  };

  for (int i = 0; i < cword_bits; ++i) {
    ot_rnds[0][i].get<uint8_t>(matrix[0][i].data(), matrix[0].size()[1]);
    ot_rnds[1][i].get<uint8_t>(matrix[1][i].data(), matrix[1].size()[1]);
  }

  std::array<osuCrypto::MatrixView<uint8_t>, 2> trans_matrix = {
    osuCrypto::MatrixView<uint8_t>(commit_shares[0].data(), num_commits, cword_bytes, false),
    osuCrypto::MatrixView<uint8_t>(commit_shares[1].data(), num_commits, cword_bytes, false)
  };

  osuCrypto::sse_transpose(matrix[0], trans_matrix[0]);
  osuCrypto::sse_transpose(matrix[1], trans_matrix[1]);

  //Handle the blinding shares
  matrix[0] = osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));
  matrix[1] = osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS));

  trans_matrix[0] = osuCrypto::MatrixView<uint8_t>(blind_shares[0].data(), NUM_PAR_CHECKS, cword_bytes, false);
  trans_matrix[1] = osuCrypto::MatrixView<uint8_t>(blind_shares[1].data(), NUM_PAR_CHECKS, cword_bytes, false);

  for (int i = 0; i < cword_bits; ++i) {
    ot_rnds[0][i].get<uint8_t>(matrix[0][i].data(), matrix[0].size()[1]);
    ot_rnds[1][i].get<uint8_t>(matrix[1][i].data(), matrix[1].size()[1]);
  }

  osuCrypto::sse_transpose(matrix[0], trans_matrix[0]);
  osuCrypto::sse_transpose(matrix[1], trans_matrix[1]);
}

void SplitCommitSender::CheckbitCorrection(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares, uint32_t set_lsb_start_idx, osuCrypto::Channel & chl) {

  uint32_t num_commits = commit_shares[0].num_entries();
  uint32_t num_total_commits = num_commits + NUM_PAR_CHECKS;

  if (set_lsb_start_idx != std::numeric_limits<uint32_t>::max()) {
    //Is used to set lsb of specific committed values in a range starting from set_lsb_start_idx. The commits with positions below set_lsb_start_idx will get lsb set to 0 and above set to 1

    std::unique_ptr<BYTEArrayVector> lsb_corrections(std::make_unique<BYTEArrayVector>(BITS_TO_BYTES(num_commits), 1));
    uint8_t flip_table[] = {REVERSE_BYTE_ORDER[1], 0};

    for (int i = 0; i < num_commits; ++i) {
      SetBit(i, GetLSB(commit_shares[0][i]) ^ GetLSB(commit_shares[1][i]), lsb_corrections->data());

      if (i < set_lsb_start_idx) {
        commit_shares[1][i][msg_bytes - 1] ^= REVERSE_BYTE_ORDER[GetBit(i, lsb_corrections->data())];
      } else {
        commit_shares[1][i][msg_bytes - 1] ^= flip_table[GetBit(i, lsb_corrections->data())];
      }
    }

    chl.asyncSend(std::move(lsb_corrections));
  }

  //Buffers
  std::unique_ptr<BYTEArrayVector> checkbit_corrections_buf(std::make_unique<BYTEArrayVector>(num_total_commits, parity_bytes));

  std::vector<uint8_t> values_buffer(cword_bytes);
  if (msg_bits == 1) {

    uint8_t value;
    for (int j = 0; j < num_commits; ++j) {
      XOR_BitCodeWords(values_buffer.data(), commit_shares[0][j], commit_shares[1][j]);

      BitEncode(GetBit(0, values_buffer.data()), (*checkbit_corrections_buf)[j]);

      XOR_BitCodeWords(commit_shares[1][j], commit_shares[0][j], (*checkbit_corrections_buf)[j]);
      XOR_BitCodeWords((*checkbit_corrections_buf)[j], values_buffer.data());
    }

    for (int j = 0; j < NUM_PAR_CHECKS; ++j) {
      XOR_BitCodeWords(values_buffer.data(), blind_shares[0][j], blind_shares[1][j]);

      BitEncode(GetBit(0, values_buffer.data()), (*checkbit_corrections_buf)[num_commits + j]);

      XOR_BitCodeWords(blind_shares[1][j], blind_shares[0][j], (*checkbit_corrections_buf)[num_commits + j]);
      XOR_BitCodeWords((*checkbit_corrections_buf)[num_commits + j], values_buffer.data());
    }
  } else {
    for (int j = 0; j < num_commits; ++j) {
      XOR_CodeWords(values_buffer.data(), commit_shares[0][j], commit_shares[1][j]);
      code.encode(values_buffer.data(), (*checkbit_corrections_buf)[j]);

      XOR_CheckBits(commit_shares[1][j] + msg_bytes, commit_shares[0][j] + msg_bytes, (*checkbit_corrections_buf)[j]);
      XOR_CheckBits((*checkbit_corrections_buf)[j], values_buffer.data() + msg_bytes);
    }

    for (int j = 0; j < NUM_PAR_CHECKS; ++j) {
      XOR_CodeWords(values_buffer.data(), blind_shares[0][j], blind_shares[1][j]);
      code.encode(values_buffer.data(), (*checkbit_corrections_buf)[num_commits + j]);

      XOR_CheckBits(blind_shares[1][j] + msg_bytes, blind_shares[0][j] + msg_bytes, (*checkbit_corrections_buf)[num_commits + j]);
      XOR_CheckBits((*checkbit_corrections_buf)[num_commits + j], values_buffer.data() + msg_bytes);
    }
  }

  chl.asyncSend(std::move(checkbit_corrections_buf));
}

void SplitCommitSender::ConsistencyCheck(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& blind_shares, osuCrypto::Channel & chl) {

  std::array<BYTEArrayVector, 2> resulting_shares = {
    BYTEArrayVector(cword_bits, CONSISTENCY),
    BYTEArrayVector(cword_bits, CONSISTENCY)
  };

  ComputeShares(commit_shares, resulting_shares, chl);

  std::array<osuCrypto::MatrixView<uint8_t>, 2> matrix = {
    osuCrypto::MatrixView<uint8_t>(blind_shares[0].data(), blind_shares[0].num_entries(), blind_shares[0].entry_size(), false),
    osuCrypto::MatrixView<uint8_t>(blind_shares[1].data(), blind_shares[1].num_entries(), blind_shares[1].entry_size(), false)
  };

  std::array<osuCrypto::MatrixView<uint8_t>, 2> trans_matrix = {
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS)),
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(NUM_PAR_CHECKS))
  };

  osuCrypto::sse_transpose(matrix[0], trans_matrix[0]);
  osuCrypto::sse_transpose(matrix[1], trans_matrix[1]);

  for (int i = 0; i < cword_bits; ++i) {
    for (int j = 0; j < CONSISTENCY; ++j) {
      resulting_shares[0][i][j] ^= trans_matrix[0][i][j];
      resulting_shares[1][i][j] ^= trans_matrix[1][i][j];
    }
  }

  //Convert to unique_ptr for asyncSend
  std::array<std::unique_ptr<BYTEArrayVector>, 2> resulting_shares_ptr = {
    std::make_unique<BYTEArrayVector>(BYTEArrayVector(std::move(resulting_shares[0]))),
    std::make_unique<BYTEArrayVector>(BYTEArrayVector(std::move(resulting_shares[1])))
  };

  //Send the resulting decommitments
  chl.asyncSend(std::move(resulting_shares_ptr[0]));
  chl.asyncSend(std::move(resulting_shares_ptr[1]));
}

void SplitCommitSender::ComputeShares(std::array<BYTEArrayVector, 2>& commit_shares, std::array<BYTEArrayVector, 2>& resulting_shares, osuCrypto::Channel & chl) {

  uint32_t num_commits = commit_shares[0].num_entries();
  uint32_t matrix_stride = PAD_TO_MULTIPLE(num_commits, NUM_PAR_CHECKS); //since we process the commitments in blocks of NUM_PAR_CHECKS

  std::array<osuCrypto::MatrixView<uint8_t>, 2> trans_matrix = {
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(matrix_stride)),
    osuCrypto::MatrixView<uint8_t>(cword_bits, BITS_TO_BYTES(matrix_stride))
  };

  std::array<osuCrypto::MatrixView<uint8_t>, 2> matrix2 = {
    osuCrypto::MatrixView<uint8_t>(commit_shares[0].data(), num_commits, cword_bytes, false),
    osuCrypto::MatrixView<uint8_t>(commit_shares[1].data(), num_commits, cword_bytes, false)
  };

  osuCrypto::sse_transpose(matrix2[0], trans_matrix[0]);
  osuCrypto::sse_transpose(matrix2[1], trans_matrix[1]);

  //res is twice as large as we do not do degree reduction until the very end, so we need to accumulate a larger intermediate value.
  std::array<std::vector<__m128i>, 4> res = {
    std::vector<__m128i>(cword_bits),
    std::vector<__m128i>(cword_bits),
    std::vector<__m128i>(cword_bits),
    std::vector<__m128i>(cword_bits)
  };

  std::array<__m128i, 2> vals;
  std::array<__m128i, 4> vals_result;

  //Receive challenge seed from receiver and load initial challenge alpha
  std::array<uint8_t, CSEC_BYTES> alpha_seed;
  chl.recv(alpha_seed.data(), CSEC_BYTES);
  __m128i alpha = _mm_lddqu_si128((__m128i *) alpha_seed.data());

  uint32_t num_blocks = CEIL_DIVIDE(matrix_stride, NUM_PAR_CHECKS);
  for (int j = 0; j < num_blocks; ++j) {

    auto iter0 = trans_matrix[0].data() + j * NUM_PAR_CHECKS_BYTES;
    auto iter1 = trans_matrix[1].data() + j * NUM_PAR_CHECKS_BYTES;

    for (int i = 0; i < cword_bits; ++i) {

      vals[0] = _mm_lddqu_si128((__m128i*) iter0);
      vals[1] = _mm_lddqu_si128((__m128i*) iter1);

      osuCrypto::mul128(vals[0], alpha, vals_result[0], vals_result[1]);
      osuCrypto::mul128(vals[1], alpha, vals_result[2], vals_result[3]);

      iter0 += trans_matrix[0].size()[1];
      iter1 += trans_matrix[1].size()[1];

      //Accumulate the vals_result into res
      res[0][i] = _mm_xor_si128(res[0][i], vals_result[0]);
      res[1][i] = _mm_xor_si128(res[1][i], vals_result[1]);
      res[2][i] = _mm_xor_si128(res[2][i], vals_result[2]);
      res[3][i] = _mm_xor_si128(res[3][i], vals_result[3]);
    }
    gfmul128_no_refl(alpha, alpha, alpha);
  }

  //mask is used to select the first NUM_CHECKS linear combinations from res and store in resulting_shares. Needed as we actually produce col_dim_single linear combinations due to convenience. However we only send and verify NUM_CHECKS of these.
  uint32_t NUM_CHECKS = resulting_shares[0].entry_size();
  std::array<uint8_t, CSEC_BYTES> mask = { 0 };
  std::fill(mask.begin(), mask.begin() + NUM_CHECKS, 0xFF);
  __m128i store_mask = _mm_lddqu_si128((__m128i*) mask.data());

  //Reduce and move the NUM_CHECKS first linear combinations into resulting_shares
  for (int i = 0; i < cword_bits; ++i) {
    gfred128_no_refl(res[0][i], res[1][i], res[0][i]);
    _mm_maskmoveu_si128(res[0][i], store_mask, (char*) resulting_shares[0][i]);

    gfred128_no_refl(res[2][i], res[3][i], res[2][i]);
    _mm_maskmoveu_si128(res[2][i], store_mask, (char*) resulting_shares[1][i]);
  }
}