
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

namespace irt {
namespace {

constexpr size_t num_blocks = 5;
constexpr size_t block_size = 0x1000;

uint8_t buf[num_blocks * block_size + block_size];
uint8_t* beg;
uint8_t* end;

size_t round_up(size_t p) {
  return (p + block_size - 1) / block_size * block_size;
}

} // namespace

void* allocate(size_t size) {
  if (!beg) {
    size_t p = round_up(reinterpret_cast<size_t>(buf));
    beg = reinterpret_cast<uint8_t*>(p);
    end = buf + sizeof(buf);
  }

  size = round_up(size);
  void* ret = beg;
  uint8_t* p = beg + size;
  if (p > end)
    return nullptr;
  beg = p;

  return ret;
}

void deallocate(void*) {}

} // namespace irt
