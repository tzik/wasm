
#include <termios.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <stdlib.h>
extern "C" {
#include <bits/syscall.h>
#include <syscall_arch.h>
}

extern "C" void env_stdout(const void* buf, size_t length);

namespace irt {

void* allocate(size_t size);

long sys_ioctl(va_list argp) {
  int fd = va_arg(argp, int);
  unsigned long request = va_arg(argp, unsigned long);
  if (fd != 1 || request != TIOCGWINSZ)
    return -ENOSYS;

  winsize* size = va_arg(argp, winsize*);
  size->ws_row = 24;
  size->ws_col = 80;
  return 0;
}

long sys_mmap2(va_list argp) {
  abort();

  void* addr = va_arg(argp, void*);
  size_t length = va_arg(argp, size_t);
  int prot = va_arg(argp, int);
  int flags = va_arg(argp, int);
  int fd = va_arg(argp, int);
  off_t pgoffset = va_arg(argp, off_t);

  if (addr || fd != -1 || pgoffset != 0 ||
      prot != (PROT_READ | PROT_WRITE) ||
      flags != (MAP_PRIVATE | MAP_ANONYMOUS)) {
    return -ENOSYS;
  }

  return reinterpret_cast<long>(allocate(length));
}

long sys_write(va_list argp) {
  int fd = va_arg(argp, int);
  const void* buf = va_arg(argp, const void*);
  size_t count = va_arg(argp, size_t);

  if (fd != 1)
    return -ENOSYS;

  env_stdout(buf, count);
  return count;
}

long sys_writev(va_list argp) {
  int fd = va_arg(argp, int);
  const iovec* iov = va_arg(argp, const iovec*);
  int iovcnt = va_arg(argp, int);

  long ret = 0;
  for (int i = 0; i < iovcnt; ++i) {
    const void* buf = iov[i].iov_base;
    size_t len = iov[i].iov_len;

    long rv = __syscall3(
        SYS_write,
        static_cast<long>(fd),
        reinterpret_cast<long>(buf),
        static_cast<long>(len));
    if (rv < 0)
      return ret > 0 ? ret : rv;

    ret += len;

    if (rv < len)
      break;
  }
  return ret;
}

}  // namespace irt
