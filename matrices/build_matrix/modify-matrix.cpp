#include "CTPL/ctpl_stl.h"
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <cstring>
#include <climits>
#include <vector>
#include <array>
#include <unordered_map>
#include <map>
#include <thread>
#include <chrono>
#include <algorithm>
#include <numeric>

char* read_text_file(const char* file_name) {
  FILE* file;
  size_t file_size;
  file = fopen(file_name, "r");
  if (file == NULL) {
    printf("ERROR: Could not open text circuit: %s\n", file_name);
    exit(EXIT_FAILURE);
  }
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  rewind(file);

  char* data = new char[file_size + 1];
  size_t size = fread(data, 1, file_size, file);
  if (size != file_size) {
    printf("ERROR while loading file: %s\n", file_name);
    exit(EXIT_FAILURE);
  }
  data[file_size] = EOF;
  if (ferror(file)) {
    printf("ERROR: fread() error\n");
    exit(EXIT_FAILURE);
  }

  fclose(file);

  return data;
}

int main(int argc, const char* argv[]) {

  std::string file_name("matrices/c2.txt");

  char* data = read_text_file(file_name.c_str());
  std::vector<std::vector<uint32_t>> matrix(255, std::vector<uint32_t>(131));

  for (int i = 0; i < 255; ++i) { //rows
    for (int j = 0; j < 131; ++j) { //cols
      if (*data == '1') {
        matrix[i][j] = 1;
      } else {
        matrix[i][j] = 0;
      }
      if (j != 130) {
        data = strchr(data, ' ') + 1;
      }
    }
    data = strchr(data, '\n') + 1;
  }

  std::vector<uint32_t> parity_row(131);
  for (int j = 0; j < 131; ++j) { //cols
    for (int i = 0; i < 255; ++i) { //rows
      parity_row[j] += matrix[i][j];
    }
    std::cout << parity_row[j] % 2;
    if (j != (parity_row.size() - 1)) {
      std::cout << " ";
    }
  }

  return 0;
}