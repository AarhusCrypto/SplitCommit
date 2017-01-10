add_executable(TestSplitCommit test-split-commit.cpp)
target_link_libraries(TestSplitCommit SPLIT_COMMIT gtest_main gtest)

add_executable(SplitCommitSender main-split-commit-snd.cpp)
target_link_libraries(SplitCommitSender SPLIT_COMMIT)

add_executable(SplitCommitReceiver main-split-commit-rec.cpp)
target_link_libraries(SplitCommitReceiver SPLIT_COMMIT)