
extern "C" {
#include <bits/syscall.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <syscall_arch.h>
}

extern "C" long env_brk(va_list argp);
extern "C" void env_stdout(const void* buf, size_t length);

namespace irt {

long sys_ioctl(va_list argp);
long sys_write(va_list argp);
long sys_writev(va_list argp);
long sys_mmap2(va_list argp);

using syscall_handler_t = long(*)(va_list argp);
syscall_handler_t get_syscall_handler(long nr) {
  switch (nr) {
    case SYS_ioctl: return sys_ioctl;
    case SYS_brk: return env_brk;
    case SYS_write: return sys_write;
    case SYS_writev: return sys_writev;
    case SYS_mmap2: return sys_mmap2;
    default: return nullptr;
  }
}

} // namespace irt

extern "C" long __syscall(long nr, ...) {
  va_list argp;
  va_start(argp, nr);
  irt::syscall_handler_t handler = irt::get_syscall_handler(nr);
  long ret = handler ? handler(argp) : -ENOSYS;
  va_end(argp);
  return ret;
}

extern "C" long __syscall0(long nr) {
  return __syscall(nr);
}

extern "C" long __syscall1(long nr, long arg1) {
  return __syscall(nr, arg1);
}

extern "C" long __syscall2(long nr, long arg1, long arg2) {
  return __syscall(nr, arg1, arg2);
}

extern "C" long __syscall3(long nr, long arg1, long arg2, long arg3) {
  return __syscall(nr, arg1, arg2, arg3);
}

extern "C" long __syscall4(long nr, long arg1, long arg2, long arg3,
                           long arg4) {
  return __syscall(nr, arg1, arg2, arg3, arg4);
}

extern "C" long __syscall5(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5);
}

extern "C" long __syscall6(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

extern "C" long __syscall7(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6, long arg7) {
  return __syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}
