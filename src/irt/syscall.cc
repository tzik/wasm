
#include <stddef.h>

#include <bits/syscall.h>
extern "C" {
#include <syscall_arch.h>
}
#include <sys/uio.h>
#include <errno.h>

extern "C" long __syscall(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5, long arg6, long arg7);

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

} // namespace irt

extern "C" long __syscall0(long nr) {
  return __syscall(nr, 0, 0, 0, 0, 0, 0, 0);
}

extern "C" long __syscall1(long nr, long arg1) {
  return __syscall(nr, arg1, 0, 0, 0, 0, 0, 0);
}

extern "C" long __syscall2(long nr, long arg1, long arg2) {
  return __syscall(nr, arg1, arg2, 0, 0, 0, 0, 0);
}

extern "C" long __syscall3(long nr, long arg1, long arg2, long arg3) {
  switch (nr) {
  case SYS_writev:
    return irt::syscall_writev(arg1, arg2, arg3);
  }
  return __syscall(nr, arg1, arg2, arg3, 0, 0, 0, 0);
}

extern "C" long __syscall4(long nr, long arg1, long arg2, long arg3,
                           long arg4) {
  return __syscall(nr, arg1, arg2, arg3, arg4, 0, 0, 0);
}

extern "C" long __syscall5(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5, 0, 0);
}

extern "C" long __syscall6(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, 0);
}

extern "C" long __syscall7(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6, long arg7) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}
