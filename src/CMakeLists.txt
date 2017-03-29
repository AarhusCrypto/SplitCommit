set(BYTEARRAYVEC_SRCS util/byte-array-vec.cpp)
add_library(BYTEARRAYVEC ${BYTEARRAYVEC_SRCS})
target_link_libraries(BYTEARRAYVEC libOTe)

set(SPLIT_COMMIT_SRCS split-commit/split-commit.cpp split-commit/split-commit-rec.cpp split-commit/split-commit-snd.cpp)
add_library(SPLIT_COMMIT ${SPLIT_COMMIT_SRCS})
target_link_libraries(SPLIT_COMMIT BYTEARRAYVEC)

add_executable(SplitCommitSender mains/main-split-commit-snd.cpp)
target_link_libraries(SplitCommitSender SPLIT_COMMIT)

add_executable(SplitCommitReceiver mains/main-split-commit-rec.cpp)
target_link_libraries(SplitCommitReceiver SPLIT_COMMIT)