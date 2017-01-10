set(BYTEARRAYVEC_SRCS util/byte-array-vec.cpp)
add_library(BYTEARRAYVEC ${BYTEARRAYVEC_SRCS})
target_link_libraries(BYTEARRAYVEC libOTe)

set(SPLIT_COMMIT_SRCS split-commit/split-commit.cpp split-commit/split-commit-rec.cpp split-commit/split-commit-snd.cpp)
add_library(SPLIT_COMMIT ${SPLIT_COMMIT_SRCS})
target_link_libraries(SPLIT_COMMIT BYTEARRAYVEC)