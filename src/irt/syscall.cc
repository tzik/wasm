
#include <bits/syscall.h>
#include <errno.h>

extern "C" long __syscall(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5, long arg6, long arg7);

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
