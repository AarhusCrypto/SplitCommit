
#include "util/byte-array-vec.h"

BYTEArrayVector::BYTEArrayVector() {

}

BYTEArrayVector::BYTEArrayVector(uint64_t num_entries, uint64_t entry_size) :
  vec(num_entries * entry_size),
  vec_entry_size(entry_size),
  vec_num_entries(num_entries) {
}

uint8_t* BYTEArrayVector::operator[](const uint64_t idx) {
  return vec.data() + idx * vec_entry_size;
}

uint8_t* BYTEArrayVector::data() {
  return vec.data();
}

void BYTEArrayVector::FreeMem() {
  vec.clear();
  vec.shrink_to_fit();
}

uint64_t BYTEArrayVector::size() {
  return vec.size();
}

uint64_t BYTEArrayVector::num_entries() {
  return vec_num_entries;
}

uint64_t BYTEArrayVector::entry_size() {
  return vec_entry_size;
}