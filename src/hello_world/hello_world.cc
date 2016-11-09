
#include <iostream>
#include <stdio.h>
#include <map>

int main(int argc, char** argv) {
  std::cout << "Hello, world!\n";
  std::map<int, std::string> v;
  
  for (int i = 0; i < argc; ++i) {
    v[i] = argv[i];
    std::cout << argv[i] << std::endl;
  }
  return 0;
}
