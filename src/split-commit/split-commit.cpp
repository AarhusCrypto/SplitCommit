#include "split-commit/split-commit.h"

SplitCommit::SplitCommit(uint32_t msg_bits) {
  
  if (msg_bits == 1) {
    parity_bytes = 5;
    cword_bytes = 5; //the value bit is included
    msg_in_cword_offset = 0;
  } else if (msg_bits == 128) {
    
    std::stringstream ss(bch_128_134);
    code.loadTxtFile(ss);

    parity_bytes = code.codewordU8Size();
    cword_bytes = code.codewordU8Size() + code.plaintextU8Size();
    msg_in_cword_offset = code.plaintextU8Size();
  } else {
    throw std::runtime_error("Message size not supported at this time");
  }

  this->msg_bits = msg_bits;
  msg_bytes = BITS_TO_BYTES(msg_bits);
  cword_bits = cword_bytes * CHAR_BIT;
  parity_bits = parity_bytes * CHAR_BIT;
}

SplitCommit::SplitCommit(SplitCommit&& cp) :
  code(std::move(cp.code)),
  msg_bits(std::move(cp.msg_bits)),
  msg_bytes(std::move(cp.msg_bytes)),
  cword_bits(std::move(cp.cword_bits)),
  cword_bytes(std::move(cp.cword_bytes)),
  parity_bits(std::move(cp.parity_bits)),
  parity_bytes(std::move(cp.parity_bytes)),
  msg_in_cword_offset(std::move(cp.msg_in_cword_offset)),
  ots_set(std::move(cp.ots_set)) {

}

void SplitCommit::BitEncode(uint8_t data, uint8_t check_bits[]) {
  std::fill(check_bits, check_bits + cword_bytes, BIT_TO_BYTE[data]);
}