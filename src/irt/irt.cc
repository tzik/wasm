
#include <stdint.h>
#include <stdlib.h>

extern "C" uint32_t get_args_buffer_size();
extern "C" void get_args(void*);

extern "C" int main(int, char**);

extern "C" void (*__fini_array_start)() = nullptr;
extern "C" void (*__fini_array_end)() = nullptr;

extern "C" int entry_point() {
  void* args = malloc(get_args_buffer_size());
  get_args(args);

  int* argc_ptr = static_cast<int*>(args);
  int argc = *argc_ptr;
  char** argv = reinterpret_cast<char**>(argc_ptr + 1);
  return main(argc, argv);
}
