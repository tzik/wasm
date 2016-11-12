
#include <stdarg.h>
#include <stdio.h>

#include "memory.h"
#include "env.h"

namespace irt {

constexpr unsigned long page_size = 0x10000;

unsigned long current_memory() {
  volatile unsigned long ret = 0;
  __asm__ volatile("current_memory %0=" : "=r"(ret));
  return ret;
}

unsigned long grow_memory(unsigned long x) {
  volatile unsigned long ret = 0;
  __asm__ volatile("grow_memory %0=, %1" : "=r"(ret) : "r"(x));
  return ret;
}

long sys_brk(va_list argp) {
  const unsigned long page_size = 64 * 1024;
  unsigned long addr = va_arg(argp, unsigned long);
  if (addr == 0)
    return current_memory() * page_size;
  
  unsigned long grow_to = (addr + page_size - 1) / page_size;
  unsigned long delta = grow_to - current_memory();

  grow_memory(delta);
  return current_memory() * page_size;
}

}  // namespace irt
