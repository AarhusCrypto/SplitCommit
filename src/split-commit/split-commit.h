#ifndef SPLITCOMMIT_SPLITCOMMIT_H_
#define SPLITCOMMIT_SPLITCOMMIT_H_

#include "util/byte-array-vec.h"
#include "util/util.h"

#include "libOTe/Tools/LinearCode.h"

//For libOTe extension
#include "cryptoTools/Network/BtChannel.h"
#include "cryptoTools/Network/BtEndpoint.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "libOTe/Base/naor-pinkas.h"
#include "cryptoTools/Common/MatrixView.h"
#include "libOTe/Tools/Tools.h"

/**
 * @brief      Base class for holding public data shared by both sender and receiver and common functions
 */
class SplitCommit {
public:

  osuCrypto::LinearCode code;

  uint32_t msg_bits;
  uint32_t msg_bytes;
  uint32_t cword_bits;
  uint32_t cword_bytes;
  uint32_t parity_bits;
  uint32_t parity_bytes;
  uint32_t msg_in_cword_offset;
  bool msg_size_set;
  bool ots_set;

  void LoadCode(uint32_t msg_bits);

  void BitEncode(uint8_t data, uint8_t check_bits[]);

};
#endif /* SPLITCOMMIT_SPLITCOMMIT_H_ */