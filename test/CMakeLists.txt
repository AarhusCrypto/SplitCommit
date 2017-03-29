add_executable(RunAllTests run-all-tests.cpp test-split-commit.cpp)
target_link_libraries(RunAllTests SPLIT_COMMIT gtest_main gtest)