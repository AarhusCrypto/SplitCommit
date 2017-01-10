#ifndef SPLITCOMMIT_BYTEARRAYVEC_H_
#define SPLITCOMMIT_BYTEARRAYVEC_H_

#include "util/global-constants.h"

#include "cryptoTools/Network/Channel.h"

/**
 * @brief      A class for easy indexing into a std::vector<uint8_t>
 */
class BYTEArrayVector : public osuCrypto::ChannelBuffer {
private:
  /**
   * The actual data
   */
  std::vector<uint8_t> vec;

  /**
   * Various member variables about the size and state of the BYTEArrayVector
   */
  uint64_t vec_size;
  uint64_t vec_num_entries;
  uint64_t vec_entry_size;
public:

  /**
   * @brief      Default constructor. Necessary as we sometimes do not know the required size at initialization time.
   */
  BYTEArrayVector();

  /**
   * @brief      Constructor
   *
   * @param[in]  num_entries  Number of entires
   * @param[in]  entry_size   Number of bytes of each entry
   */
  BYTEArrayVector(uint64_t num_entries, uint64_t entry_size);

  /**
   * @brief      Access a pointer to the given entry
   *
   * @param[in]  idx   The index of the entry
   *
   * @return     A pointer to the index of the entry
   */
  uint8_t* operator[] (const uint64_t idx);

  /**
   * @brief      Access a pointer to the start of the backed data
   *
   * @return     { description_of_the_return_value }
   */
  uint8_t* data();

  /**
   * @brief      Get the total size of the backed data
   *
   * @return     Total number of bytes stored by the underlying vector
   */
  uint64_t size();

  /**
   * @brief      Get the number of entries the BYTEArrayVector holds
   *
   * @return     Number of entries
   */
  uint64_t num_entries();

  /**
   * @brief      Get the size of an entry in the BYTEArrayVector
   *
   * @return     Size of a single entry
   */
  uint64_t entry_size();

  /**
   * @brief      Allows to free the memory held by std::vector<uint8_t> manually, instead of waiting for the system garbage collector.
   */
  void FreeMem();

//Implements osuCrypto::ChannelBuffer
protected:
  osuCrypto::u8* ChannelBufferData() const override {
    return (uint8_t*) vec.data();
  }
  osuCrypto::u64 ChannelBufferSize() const override {
    return vec.size();
  };
  void ChannelBufferResize(osuCrypto::u64 len) override {
    if (size() != len)
      throw std::invalid_argument("asdsdasfaf ;) ");
  }

};

#endif /* SPLITCOMMIT_BYTEARRAYVEC_H_ */