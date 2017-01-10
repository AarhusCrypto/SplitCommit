#ifndef SPLITCOMMIT_GLOBAL_CONSTANTS_H_
#define SPLITCOMMIT_GLOBAL_CONSTANTS_H_

/**
 * Includes the necessary header files and defines various static values used throughout the code
 */

// #include <mmintrin.h>  //MMX
// #include <xmmintrin.h> //SSE
#include <emmintrin.h> //SSE2
// #include <pmmintrin.h> //SSE3
// #include <tmmintrin.h> //SSSE3
// #include <smmintrin.h> //SSE4.1
// #include <nmmintrin.h> //SSE4.2
// #include <ammintrin.h> //SSE4A
#include <wmmintrin.h> //AES
#include <immintrin.h> //AVX
// #include <zmmintrin.h> //AVX512

#include "CTPL/ctpl_stl.h"
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <cstring>
#include <climits>
#include <string>
#include <vector>
#include <array>
#include <future>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>

static std::array<std::array<uint8_t, 16>, 2> constant_seeds = {
  std::array<uint8_t, 16>({0x43, 0x73, 0x98, 0x41, 0x70, 0x12, 0x38, 0x78, 0xAB, 0x45, 0x78, 0xFF, 0xEA, 0xD3, 0xFF, 0x00}),
  std::array<uint8_t, 16>({0x43, 0x73, 0x98, 0x41, 0x70, 0x12, 0x38, 0x78, 0x43, 0x73, 0x98, 0x41, 0x66, 0x19, 0xAA, 0xFE})
};

#define CSEC 128
#define CSEC_BYTES 16
#define SSEC 40
#define SSEC_BYTES 5

// Below used for static XOR functions in util.h
#define BCH_BITS 136
#define BCH_BYTES 17
#define CODEWORD_BITS 264
#define CODEWORD_BYTES 33
#define BIT_CODEWORD_BITS SSEC
#define BIT_CODEWORD_BYTES SSEC_BYTES

enum LIN_CHECK_TYPE {
  CONSISTENCY = 2 * SSEC_BYTES,
  BATCH_DECOMMIT = SSEC_BYTES
};

//Constants
#define NUM_PAR_CHECKS 128 //We process 128 columns at a time with our PCLMULQDQ code.
#define NUM_PAR_CHECKS_BYTES BITS_TO_BYTES(NUM_PAR_CHECKS)

#endif /* SPLITCOMMIT_GLOBAL_CONSTANTS_H_ */
