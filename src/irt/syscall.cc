
#include <stddef.h>
#include <stdarg.h>

#include <bits/syscall.h>
extern "C" {
#include <syscall_arch.h>
}
#include <sys/uio.h>
#include <sys/mman.h>
#include <errno.h>

extern "C" long env_syscall(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6, long arg7);
extern "C" void dump(long);
extern "C" void unimplemented_syscall(long);
extern "C" void print(const char*);

namespace irt {

long syscall_writev(long arg1, long arg2, long arg3) {
  int fd = static_cast<int>(arg1);
  auto iov = reinterpret_cast<const iovec*>(arg2);
  int iovcnt = static_cast<int>(arg3);

  long ret = 0;
  for (int i = 0; i < iovcnt; ++i) {
    const void* buf = iov[i].iov_base;
    size_t len = iov[i].iov_len;

    long rv = __syscall3(SYS_write, fd, reinterpret_cast<long>(buf), len);
    if (rv < 0)
      return rv;

    ret += len;

    if (rv < len)
      break;
  }
  return ret;
}

void* allocate(size_t size);

long syscall_mmap2(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
  void* addr = reinterpret_cast<void*>(arg1);
  size_t length = static_cast<size_t>(arg2);
  int prot = static_cast<int>(arg3);
  int flags = static_cast<int>(arg4);
  int fd = static_cast<int>(arg5);
  off_t pgoffset = static_cast<off_t>(arg6);

  if (addr || fd != -1 || pgoffset != 0 ||
      prot != (PROT_READ | PROT_WRITE) ||
      flags != (MAP_PRIVATE | MAP_ANONYMOUS)) {
    return env_syscall(SYS_mmap2, arg1, arg2, arg3, arg4, arg5, arg6, 0);
  }

  return reinterpret_cast<long>(allocate(length));
}

long syscall_v(long nr, va_list argp) {
  switch (nr) {
    case SYS_brk: {
      long arg1 = va_arg(argp, long);
      return __syscall1(nr, arg1);
    }
  }

  unimplemented_syscall(nr);
  return -ENOSYS;
}

} // namespace irt

extern "C" long __syscall0(long nr) {
  return env_syscall(nr, 0, 0, 0, 0, 0, 0, 0);
}

extern "C" long __syscall1(long nr, long arg1) {
  return env_syscall(nr, arg1, 0, 0, 0, 0, 0, 0);
}

extern "C" long __syscall2(long nr, long arg1, long arg2) {
  return env_syscall(nr, arg1, arg2, 0, 0, 0, 0, 0);
}

extern "C" long __syscall3(long nr, long arg1, long arg2, long arg3) {
  switch (nr) {
  case SYS_writev:
    return irt::syscall_writev(arg1, arg2, arg3);
  }
  return env_syscall(nr, arg1, arg2, arg3, 0, 0, 0, 0);
}

extern "C" long __syscall4(long nr, long arg1, long arg2, long arg3,
                           long arg4) {
  return env_syscall(nr, arg1, arg2, arg3, arg4, 0, 0, 0);
}

extern "C" long __syscall5(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5) {
  return env_syscall(nr, arg1, arg2, arg3, arg4, arg5, 0, 0);
}

extern "C" long __syscall6(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6) {
  switch (nr) {
  case SYS_mmap2:
    return irt::syscall_mmap2(arg1, arg2, arg3, arg4, arg5, arg6);
  }
  return env_syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, 0);
}

extern "C" long __syscall7(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6, long arg7) {
  return env_syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

extern "C" long __syscall(long nr, ...) {
  va_list argp;
  va_start(argp, nr);
  long ret = irt::syscall_v(nr, argp);
  va_end(argp);
  return ret;
}
