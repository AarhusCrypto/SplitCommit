#ifndef SPLITCOMMIT_UTIL_UTIL_H_
#define SPLITCOMMIT_UTIL_UTIL_H_

/**
 * Defines various static helper functions used throughout the code
 */

#include "util/global-constants.h"
#include "libOTe/Tools/Tools.h"

#define CEIL_DIVIDE(x, y)     (( ((x) + (y)-1)/(y)))
#define BITS_TO_BYTES(bits) (CEIL_DIVIDE((bits), CHAR_BIT))
#define BYTES_TO_BITS(bytes) (bytes * CHAR_BIT)
#define PAD_TO_MULTIPLE(x, y)     ( CEIL_DIVIDE(x, y) * (y))

#define GET_TIME() std::chrono::high_resolution_clock::now()
#define PRINT_TIME(end,begin,str) std::cout << str << ": " << (double) std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / 1000000 << std::endl;
#define PRINT_TIME_NANO(end,begin,str) std::cout << str << ": " << std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() << std::endl;

#define ThisThreadSleep(sec) std::this_thread::sleep_for(std::chrono::seconds(sec));

//Taken from ALSZ OTExtension library. Used by the below XOR functions
typedef uint8_t BYTE;
static const BYTE MASK_BIT[8] = { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };
static const BYTE BIT[8] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 };
static const BYTE CMASK_BIT[8] = { 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };
static const BYTE MASK_SET_BIT_C[2][8] = { { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };
static const BYTE SET_BIT_C[2][8] = { { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };
static const BYTE C_BIT[8] = { 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F };
static const BYTE REVERSE_BYTE_ORDER[256] = { 0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8,
                                              0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4, 0x0C, 0x8C,
                                              0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2,
                                              0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA, 0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96,
                                              0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1,
                                              0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1, 0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85,
                                              0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD,
                                              0x7D, 0xFD, 0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B,
                                              0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7, 0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF,
                                              0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
                                            };


static uint8_t BIT_TO_BYTE[] = {0x00, 0xFF};

static inline __m128i load_block(uint8_t data[]) {
  return _mm_lddqu_si128((__m128i *) data);
};

static inline void store_block(__m128i block, uint8_t data[]) {
  _mm_storeu_si128((__m128i *) data, block);
};

static inline void XOR_UINT8_T(uint8_t dest[], uint8_t src[], int size = 1) {
  for (int i = 0; i < size; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_UINT8_T(uint8_t dest[], uint8_t src0[], uint8_t src1[], int size) {
  for (int i = 0; i < size; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline void XOR_128(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < CSEC_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_128(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < CSEC_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

//23 bytes
static inline void XOR_CheckBits(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < (CODEWORD_BYTES - CSEC_BYTES); i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_CheckBits(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < (CODEWORD_BYTES - CSEC_BYTES); i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

//39 bytes
static inline void XOR_CodeWords(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < CODEWORD_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_BitCodeWords(uint8_t dest[], uint8_t src[]) {
  for (int i = 0; i < BIT_CODEWORD_BYTES; i++) {
    dest[i] ^= src[i];
  }
};

static inline void XOR_CodeWords(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < CODEWORD_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline void XOR_BitCodeWords(uint8_t dest[], uint8_t src0[], uint8_t src1[]) {
  for (int i = 0; i < BIT_CODEWORD_BYTES; i++) {
    dest[i] = src0[i] ^ src1[i];
  }
};

static inline uint8_t GetBitReversed(int idx, uint8_t array[]) {
  return !!(array[idx >> 3] & MASK_BIT[idx & 0x7]);
};

//MSB has highest index
static inline uint8_t GetBit(int idx, uint8_t array[]) {
  return !!(array[idx >> 3] & BIT[idx & 0x7]);
};

static inline void XORBitReversed(int idx, BYTE b, uint8_t array[]) {
  array[idx >> 3] ^= MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void XORBit(int idx, BYTE b, uint8_t array[]) {
  array[idx >> 3] ^= SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void SetBitReversed(int idx, uint8_t b, uint8_t array[]) {
  array[idx >> 3] = (array[idx >> 3] & CMASK_BIT[idx & 0x7]) | MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void SetBit(int idx, uint8_t b, uint8_t array[]) {
  array[idx >> 3] = (array[idx >> 3] & C_BIT[idx & 0x7]) | SET_BIT_C[!(b & 0x01)][idx & 0x7];
};

static inline void XORBit(int idx, BYTE a, BYTE b, uint8_t array[]) {
  SetBit(idx, a, array);
  XORBit(idx, b, array);
};

static inline uint8_t GetLSB(__m128i s) {
  int r = _mm_movemask_pd(*(__m128d*)& s);
  return (r == 2 || r == 3); //Checks if lsb-1 is set or not. This is only set if lsb(array) is set.
};

//Wrapper
static inline uint8_t GetLSB(uint8_t array[]) {
  __m128i s = _mm_lddqu_si128((__m128i *) (array));
  return GetLSB(s);
};

static inline bool compare128(__m128i a, __m128i b) {
  __m128i c = _mm_xor_si128(a, b);
  return _mm_testz_si128(c, c);
};

//The reduction, taking the two results of Mul28 as input
static inline void gfred128_no_refl(__m128i tmp3, __m128i tmp6, __m128i& res) {
  __m128i tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
  __m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
  tmp7 = _mm_srli_epi32(tmp6, 31);
  tmp8 = _mm_srli_epi32(tmp6, 30);
  tmp9 = _mm_srli_epi32(tmp6, 25);
  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);

  tmp8 = _mm_shuffle_epi32(tmp7, 147);
  tmp7 = _mm_and_si128(XMMMASK, tmp8);
  tmp8 = _mm_andnot_si128(XMMMASK, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp8);
  tmp6 = _mm_xor_si128(tmp6, tmp7);
  tmp10 = _mm_slli_epi32(tmp6, 1);

  tmp3 = _mm_xor_si128(tmp3, tmp10);
  tmp11 = _mm_slli_epi32(tmp6, 2);
  tmp3 = _mm_xor_si128(tmp3, tmp11);
  tmp12 = _mm_slli_epi32(tmp6, 7);
  tmp3 = _mm_xor_si128(tmp3, tmp12);
  res = _mm_xor_si128(tmp3, tmp6);
};

//Convenience function. Do mul and reduction in one go
static inline void gfmul128_no_refl(__m128i a, __m128i b, __m128i& res) {
  __m128i tmp0, tmp1;

  osuCrypto::mul128(a, b, tmp0, tmp1);
  gfred128_no_refl(tmp0, tmp1, res);
};

static inline void PrintHex(uint8_t value[], int num_bytes) {
  for (int i = 0; i < num_bytes; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << (std::hex) << ((unsigned int) value[i]);
  }
  std::cout << (std::dec) << std::endl;
}

static inline void PrintBin(uint8_t value[], int num_bits) {
  for (int i = 0; i < num_bits; ++i) {
    if (i != 0 && i % CHAR_BIT == 0) {
      std::cout << " ";
    }
    std::cout << (unsigned int) GetBit(i, value);
  }
  std::cout << std::endl;
}

static inline void PrintBinMatrix(uint8_t value[], int rows, int cols) {
  for (int i = 0; i < rows; ++i) {
    for (int j = 0; j < cols; ++j) {
      std::cout << (unsigned int) GetBit(i * rows + j, value);
    }
    std::cout << std::endl;
  }
  std::cout << std::endl;
}

static inline void Print128(__m128i val) {
  uint8_t tmp[CSEC_BYTES];
  _mm_storeu_si128((__m128i *) tmp, val);
  PrintHex(tmp, CSEC_BYTES);
}

static inline void PrintTimePerUnit(std::chrono::time_point<std::chrono::high_resolution_clock> begin, std::chrono::time_point<std::chrono::high_resolution_clock> end, uint32_t num_units, std::string msg) {
  uint64_t time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
  std::cout << msg << ": " << (double) time_nano / num_units / pow(10, 6) << std::endl;
}

#endif /* SPLITCOMMIT_UTIL_UTIL_H_ */