
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "env.h"
#include "memory.h"

extern "C" int main(int, char**);

extern "C" int _start() {
  void* args = malloc(env_get_args_buffer_size());
  if (!args)
    abort();
  env_get_args(args);

  int* argc_ptr = static_cast<int*>(args);
  int argc = *argc_ptr;
  char** argv = reinterpret_cast<char**>(argc_ptr + 1);
  return main(argc, argv);
}
