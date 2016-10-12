
function combineEnvObject(...envs) {
  let ret = {};
  for (let env of envs) {
    for (let i in env) {
      ret[i] = env[i];
    }
  }
  return ret;
}

class Timing {
  constructor() {
    this.start = Date.now();
    this.prev_start = this.start;
  }

  emit(msg) {
    let now = Date.now();
    print(msg + ": " + (now - this.prev_start) + "ms");
    this.prev_start = now;
  }
};

class Syscall {
  constructor() {
    this.instance = null;
    this.fd = {};
  }

  unimplemented(msg, ...args) {
    print("unimplemented syscall: ", msg, ...args);
    return -1;
  }

  ioctl_get_window_size(p) {
    let mem = this.instance.exports.memory.buffer;

    // struct winsize
    let s = new Uint16Array(mem, p, 4);
    s[0] = 24; // ws_row
    s[1] = 80; // ws_col
    return 0;
  }

  syscall_restart_syscall(...args) { return this.unimplemented("restart_syscall", ...args); }
  syscall_exit(...args) { return this.unimplemented("exit", ...args); }
  syscall_fork(...args) { return this.unimplemented("fork", ...args); }
  syscall_read(...args) { return this.unimplemented("read", ...args); }

  syscall_write(fd, p, n) {
    if (fd !== 1) {
      return this.unimplemented("write", fd, p, n);
    }
    
    let mem = this.instance.exports.memory.buffer;
    let s = new Uint8Array(mem, p, n);
    let cs = [];
    for (let c of s)
      cs.push(String.fromCharCode(c));
    write(cs.join(''));
    return n;
  }

  syscall_open(...args) { return this.unimplemented("open", ...args); }
  syscall_close(...args) { return this.unimplemented("close", ...args); }
  syscall_waitpid(...args) { return this.unimplemented("waitpid", ...args); }
  syscall_creat(...args) { return this.unimplemented("creat", ...args); }
  syscall_link(...args) { return this.unimplemented("link", ...args); }
  syscall_unlink(...args) { return this.unimplemented("unlink", ...args); }
  syscall_execve(...args) { return this.unimplemented("execve", ...args); }
  syscall_chdir(...args) { return this.unimplemented("chdir", ...args); }
  syscall_time(...args) { return this.unimplemented("time", ...args); }
  syscall_mknod(...args) { return this.unimplemented("mknod", ...args); }
  syscall_chmod(...args) { return this.unimplemented("chmod", ...args); }
  syscall_lchown(...args) { return this.unimplemented("lchown", ...args); }
  syscall_break(...args) { return this.unimplemented("break", ...args); }
  syscall_oldstat(...args) { return this.unimplemented("oldstat", ...args); }
  syscall_lseek(...args) { return this.unimplemented("lseek", ...args); }
  syscall_getpid(...args) { return this.unimplemented("getpid", ...args); }
  syscall_mount(...args) { return this.unimplemented("mount", ...args); }
  syscall_umount(...args) { return this.unimplemented("umount", ...args); }
  syscall_setuid(...args) { return this.unimplemented("setuid", ...args); }
  syscall_getuid(...args) { return this.unimplemented("getuid", ...args); }
  syscall_stime(...args) { return this.unimplemented("stime", ...args); }
  syscall_ptrace(...args) { return this.unimplemented("ptrace", ...args); }
  syscall_alarm(...args) { return this.unimplemented("alarm", ...args); }
  syscall_oldfstat(...args) { return this.unimplemented("oldfstat", ...args); }
  syscall_pause(...args) { return this.unimplemented("pause", ...args); }
  syscall_utime(...args) { return this.unimplemented("utime", ...args); }
  syscall_stty(...args) { return this.unimplemented("stty", ...args); }
  syscall_gtty(...args) { return this.unimplemented("gtty", ...args); }
  syscall_access(...args) { return this.unimplemented("access", ...args); }
  syscall_nice(...args) { return this.unimplemented("nice", ...args); }
  syscall_ftime(...args) { return this.unimplemented("ftime", ...args); }
  syscall_sync(...args) { return this.unimplemented("sync", ...args); }
  syscall_kill(...args) { return this.unimplemented("kill", ...args); }
  syscall_rename(...args) { return this.unimplemented("rename", ...args); }
  syscall_mkdir(...args) { return this.unimplemented("mkdir", ...args); }
  syscall_rmdir(...args) { return this.unimplemented("rmdir", ...args); }
  syscall_dup(...args) { return this.unimplemented("dup", ...args); }
  syscall_pipe(...args) { return this.unimplemented("pipe", ...args); }
  syscall_times(...args) { return this.unimplemented("times", ...args); }
  syscall_prof(...args) { return this.unimplemented("prof", ...args); }

  syscall_brk(p) {
    let mem = this.instance.exports.memory.buffer;
    let reserved_for_mmap = 4096;
    if (p <= mem.byteLength - reserved_for_mmap)
      return 0;
    return -1;
  }

  syscall_setgid(...args) { return this.unimplemented("setgid", ...args); }
  syscall_getgid(...args) { return this.unimplemented("getgid", ...args); }
  syscall_signal(...args) { return this.unimplemented("signal", ...args); }
  syscall_geteuid(...args) { return this.unimplemented("geteuid", ...args); }
  syscall_getegid(...args) { return this.unimplemented("getegid", ...args); }
  syscall_acct(...args) { return this.unimplemented("acct", ...args); }
  syscall_umount2(...args) { return this.unimplemented("umount2", ...args); }
  syscall_lock(...args) { return this.unimplemented("lock", ...args); }

  syscall_ioctl(fd, cmd, ...args) {
    if (fd === 1) {
      switch (cmd) {
      case 0x5413: // TIOCGWINSZ
        return this.ioctl_get_window_size(...args);
      }
    }
    return this.unimplemented("ioctl", ...args);
  }

  syscall_fcntl(...args) { return this.unimplemented("fcntl", ...args); }
  syscall_mpx(...args) { return this.unimplemented("mpx", ...args); }
  syscall_setpgid(...args) { return this.unimplemented("setpgid", ...args); }
  syscall_ulimit(...args) { return this.unimplemented("ulimit", ...args); }
  syscall_oldolduname(...args) { return this.unimplemented("oldolduname", ...args); }
  syscall_umask(...args) { return this.unimplemented("umask", ...args); }
  syscall_chroot(...args) { return this.unimplemented("chroot", ...args); }
  syscall_ustat(...args) { return this.unimplemented("ustat", ...args); }
  syscall_dup2(...args) { return this.unimplemented("dup2", ...args); }
  syscall_getppid(...args) { return this.unimplemented("getppid", ...args); }
  syscall_getpgrp(...args) { return this.unimplemented("getpgrp", ...args); }
  syscall_setsid(...args) { return this.unimplemented("setsid", ...args); }
  syscall_sigaction(...args) { return this.unimplemented("sigaction", ...args); }
  syscall_sgetmask(...args) { return this.unimplemented("sgetmask", ...args); }
  syscall_ssetmask(...args) { return this.unimplemented("ssetmask", ...args); }
  syscall_setreuid(...args) { return this.unimplemented("setreuid", ...args); }
  syscall_setregid(...args) { return this.unimplemented("setregid", ...args); }
  syscall_sigsuspend(...args) { return this.unimplemented("sigsuspend", ...args); }
  syscall_sigpending(...args) { return this.unimplemented("sigpending", ...args); }
  syscall_sethostname(...args) { return this.unimplemented("sethostname", ...args); }
  syscall_setrlimit(...args) { return this.unimplemented("setrlimit", ...args); }
  syscall_getrlimit(...args) { return this.unimplemented("getrlimit", ...args); }
  syscall_getrusage(...args) { return this.unimplemented("getrusage", ...args); }
  syscall_gettimeofday(...args) { return this.unimplemented("gettimeofday", ...args); }
  syscall_settimeofday(...args) { return this.unimplemented("settimeofday", ...args); }
  syscall_getgroups(...args) { return this.unimplemented("getgroups", ...args); }
  syscall_setgroups(...args) { return this.unimplemented("setgroups", ...args); }
  syscall_select(...args) { return this.unimplemented("select", ...args); }
  syscall_symlink(...args) { return this.unimplemented("symlink", ...args); }
  syscall_oldlstat(...args) { return this.unimplemented("oldlstat", ...args); }
  syscall_readlink(...args) { return this.unimplemented("readlink", ...args); }
  syscall_uselib(...args) { return this.unimplemented("uselib", ...args); }
  syscall_swapon(...args) { return this.unimplemented("swapon", ...args); }
  syscall_reboot(...args) { return this.unimplemented("reboot", ...args); }
  syscall_readdir(...args) { return this.unimplemented("readdir", ...args); }
  syscall_mmap(...args) { return this.unimplemented("mmap", ...args); }
  syscall_munmap(...args) { return this.unimplemented("munmap", ...args); }
  syscall_truncate(...args) { return this.unimplemented("truncate", ...args); }
  syscall_ftruncate(...args) { return this.unimplemented("ftruncate", ...args); }
  syscall_fchmod(...args) { return this.unimplemented("fchmod", ...args); }
  syscall_fchown(...args) { return this.unimplemented("fchown", ...args); }
  syscall_getpriority(...args) { return this.unimplemented("getpriority", ...args); }
  syscall_setpriority(...args) { return this.unimplemented("setpriority", ...args); }
  syscall_profil(...args) { return this.unimplemented("profil", ...args); }
  syscall_statfs(...args) { return this.unimplemented("statfs", ...args); }
  syscall_fstatfs(...args) { return this.unimplemented("fstatfs", ...args); }
  syscall_ioperm(...args) { return this.unimplemented("ioperm", ...args); }
  syscall_socketcall(...args) { return this.unimplemented("socketcall", ...args); }
  syscall_syslog(...args) { return this.unimplemented("syslog", ...args); }
  syscall_setitimer(...args) { return this.unimplemented("setitimer", ...args); }
  syscall_getitimer(...args) { return this.unimplemented("getitimer", ...args); }
  syscall_stat(...args) { return this.unimplemented("stat", ...args); }
  syscall_lstat(...args) { return this.unimplemented("lstat", ...args); }
  syscall_fstat(...args) { return this.unimplemented("fstat", ...args); }
  syscall_olduname(...args) { return this.unimplemented("olduname", ...args); }
  syscall_iopl(...args) { return this.unimplemented("iopl", ...args); }
  syscall_vhangup(...args) { return this.unimplemented("vhangup", ...args); }
  syscall_idle(...args) { return this.unimplemented("idle", ...args); }
  syscall_vm86old(...args) { return this.unimplemented("vm86old", ...args); }
  syscall_wait4(...args) { return this.unimplemented("wait4", ...args); }
  syscall_swapoff(...args) { return this.unimplemented("swapoff", ...args); }
  syscall_sysinfo(...args) { return this.unimplemented("sysinfo", ...args); }
  syscall_ipc(...args) { return this.unimplemented("ipc", ...args); }
  syscall_fsync(...args) { return this.unimplemented("fsync", ...args); }
  syscall_sigreturn(...args) { return this.unimplemented("sigreturn", ...args); }
  syscall_clone(...args) { return this.unimplemented("clone", ...args); }
  syscall_setdomainname(...args) { return this.unimplemented("setdomainname", ...args); }
  syscall_uname(...args) { return this.unimplemented("uname", ...args); }
  syscall_modify_ldt(...args) { return this.unimplemented("modify_ldt", ...args); }
  syscall_adjtimex(...args) { return this.unimplemented("adjtimex", ...args); }
  syscall_mprotect(...args) { return this.unimplemented("mprotect", ...args); }
  syscall_sigprocmask(...args) { return this.unimplemented("sigprocmask", ...args); }
  syscall_create_module(...args) { return this.unimplemented("create_module", ...args); }
  syscall_init_module(...args) { return this.unimplemented("init_module", ...args); }
  syscall_delete_module(...args) { return this.unimplemented("delete_module", ...args); }
  syscall_get_kernel_syms(...args) { return this.unimplemented("get_kernel_syms", ...args); }
  syscall_quotactl(...args) { return this.unimplemented("quotactl", ...args); }
  syscall_getpgid(...args) { return this.unimplemented("getpgid", ...args); }
  syscall_fchdir(...args) { return this.unimplemented("fchdir", ...args); }
  syscall_bdflush(...args) { return this.unimplemented("bdflush", ...args); }
  syscall_sysfs(...args) { return this.unimplemented("sysfs", ...args); }
  syscall_personality(...args) { return this.unimplemented("personality", ...args); }
  syscall_afs_syscall(...args) { return this.unimplemented("afs_syscall", ...args); }
  syscall_setfsuid(...args) { return this.unimplemented("setfsuid", ...args); }
  syscall_setfsgid(...args) { return this.unimplemented("setfsgid", ...args); }
  syscall__llseek(...args) { return this.unimplemented("_llseek", ...args); }
  syscall_getdents(...args) { return this.unimplemented("getdents", ...args); }
  syscall__newselect(...args) { return this.unimplemented("_newselect", ...args); }
  syscall_flock(...args) { return this.unimplemented("flock", ...args); }
  syscall_msync(...args) { return this.unimplemented("msync", ...args); }
  syscall_readv(...args) { return this.unimplemented("readv", ...args); }

  syscall_writev(fd, p, n) {
    let mem = this.instance.exports.memory.buffer;

    let ret = 0;
    for (let i = 0; i < n; ++i) {
      // struct iovec
      // sizeof(iovec) == sizeof(size_t) + sizeof(void*) == 8
      let s = new Uint32Array(mem, p + i * 8, 2);
      let iov_base = s[0]; // iov_base
      let iov_len = s[1];
      let res = this.syscall_write(fd, iov_base, iov_len);
      if (res < 0)
        return res;
      ret += res;
      if (res < iov_len)
        return ret;
    }
    return ret;
  }

  syscall_getsid(...args) { return this.unimplemented("getsid", ...args); }
  syscall_fdatasync(...args) { return this.unimplemented("fdatasync", ...args); }
  syscall__sysctl(...args) { return this.unimplemented("_sysctl", ...args); }
  syscall_mlock(...args) { return this.unimplemented("mlock", ...args); }
  syscall_munlock(...args) { return this.unimplemented("munlock", ...args); }
  syscall_mlockall(...args) { return this.unimplemented("mlockall", ...args); }
  syscall_munlockall(...args) { return this.unimplemented("munlockall", ...args); }
  syscall_sched_setparam(...args) { return this.unimplemented("sched_setparam", ...args); }
  syscall_sched_getparam(...args) { return this.unimplemented("sched_getparam", ...args); }
  syscall_sched_setscheduler(...args) { return this.unimplemented("sched_setscheduler", ...args); }
  syscall_sched_getscheduler(...args) { return this.unimplemented("sched_getscheduler", ...args); }
  syscall_sched_yield(...args) { return this.unimplemented("sched_yield", ...args); }
  syscall_sched_get_priority_max(...args) { return this.unimplemented("sched_get_priority_max", ...args); }
  syscall_sched_get_priority_min(...args) { return this.unimplemented("sched_get_priority_min", ...args); }
  syscall_sched_rr_get_interval(...args) { return this.unimplemented("sched_rr_get_interval", ...args); }
  syscall_nanosleep(...args) { return this.unimplemented("nanosleep", ...args); }
  syscall_mremap(...args) { return this.unimplemented("mremap", ...args); }
  syscall_setresuid(...args) { return this.unimplemented("setresuid", ...args); }
  syscall_getresuid(...args) { return this.unimplemented("getresuid", ...args); }
  syscall_vm86(...args) { return this.unimplemented("vm86", ...args); }
  syscall_query_module(...args) { return this.unimplemented("query_module", ...args); }
  syscall_poll(...args) { return this.unimplemented("poll", ...args); }
  syscall_nfsservctl(...args) { return this.unimplemented("nfsservctl", ...args); }
  syscall_setresgid(...args) { return this.unimplemented("setresgid", ...args); }
  syscall_getresgid(...args) { return this.unimplemented("getresgid", ...args); }
  syscall_prctl(...args) { return this.unimplemented("prctl", ...args); }
  syscall_rt_sigreturn(...args) { return this.unimplemented("rt_sigreturn", ...args); }
  syscall_rt_sigaction(...args) { return this.unimplemented("rt_sigaction", ...args); }
  syscall_rt_sigprocmask(...args) { return this.unimplemented("rt_sigprocmask", ...args); }
  syscall_rt_sigpending(...args) { return this.unimplemented("rt_sigpending", ...args); }
  syscall_rt_sigtimedwait(...args) { return this.unimplemented("rt_sigtimedwait", ...args); }
  syscall_rt_sigqueueinfo(...args) { return this.unimplemented("rt_sigqueueinfo", ...args); }
  syscall_rt_sigsuspend(...args) { return this.unimplemented("rt_sigsuspend", ...args); }
  syscall_pread64(...args) { return this.unimplemented("pread64", ...args); }
  syscall_pwrite64(...args) { return this.unimplemented("pwrite64", ...args); }
  syscall_chown(...args) { return this.unimplemented("chown", ...args); }
  syscall_getcwd(...args) { return this.unimplemented("getcwd", ...args); }
  syscall_capget(...args) { return this.unimplemented("capget", ...args); }
  syscall_capset(...args) { return this.unimplemented("capset", ...args); }
  syscall_sigaltstack(...args) { return this.unimplemented("sigaltstack", ...args); }
  syscall_sendfile(...args) { return this.unimplemented("sendfile", ...args); }
  syscall_getpmsg(...args) { return this.unimplemented("getpmsg", ...args); }
  syscall_putpmsg(...args) { return this.unimplemented("putpmsg", ...args); }
  syscall_vfork(...args) { return this.unimplemented("vfork", ...args); }
  syscall_ugetrlimit(...args) { return this.unimplemented("ugetrlimit", ...args); }

  syscall_mmap2(addr, length, prot, flags, fd, pgoffset) {
    // PROT_READ | PROT_WRITE == 3
    // MAP_PRIVATE | MAP_ANON == 0x22
    if (addr !== 0 || fd !== -1 || pgoffset !== 0 ||
        prot !== 3 || flags !== 0x22) {
      return this.unimplemented("mmap2", ...arguments);
    }

    // this.instance.exports.memory.grow() is not implemented yet.

    if (length !== 4096 || this.not_first) {
      return this.unimplemented("mmap2", ...arguments);
    }
    this.not_first = true;

    let mem = this.instance.exports.memory.buffer;
    let reserved_for_mmap = 4096;
    return mem.byteLength - reserved_for_mmap;
  }

  syscall_truncate64(...args) { return this.unimplemented("truncate64", ...args); }
  syscall_ftruncate64(...args) { return this.unimplemented("ftruncate64", ...args); }
  syscall_stat64(...args) { return this.unimplemented("stat64", ...args); }
  syscall_lstat64(...args) { return this.unimplemented("lstat64", ...args); }
  syscall_fstat64(...args) { return this.unimplemented("fstat64", ...args); }
  syscall_lchown32(...args) { return this.unimplemented("lchown32", ...args); }
  syscall_getuid32(...args) { return this.unimplemented("getuid32", ...args); }
  syscall_getgid32(...args) { return this.unimplemented("getgid32", ...args); }
  syscall_geteuid32(...args) { return this.unimplemented("geteuid32", ...args); }
  syscall_getegid32(...args) { return this.unimplemented("getegid32", ...args); }
  syscall_setreuid32(...args) { return this.unimplemented("setreuid32", ...args); }
  syscall_setregid32(...args) { return this.unimplemented("setregid32", ...args); }
  syscall_getgroups32(...args) { return this.unimplemented("getgroups32", ...args); }
  syscall_setgroups32(...args) { return this.unimplemented("setgroups32", ...args); }
  syscall_fchown32(...args) { return this.unimplemented("fchown32", ...args); }
  syscall_setresuid32(...args) { return this.unimplemented("setresuid32", ...args); }
  syscall_getresuid32(...args) { return this.unimplemented("getresuid32", ...args); }
  syscall_setresgid32(...args) { return this.unimplemented("setresgid32", ...args); }
  syscall_getresgid32(...args) { return this.unimplemented("getresgid32", ...args); }
  syscall_chown32(...args) { return this.unimplemented("chown32", ...args); }
  syscall_setuid32(...args) { return this.unimplemented("setuid32", ...args); }
  syscall_setgid32(...args) { return this.unimplemented("setgid32", ...args); }
  syscall_setfsuid32(...args) { return this.unimplemented("setfsuid32", ...args); }
  syscall_setfsgid32(...args) { return this.unimplemented("setfsgid32", ...args); }
  syscall_pivot_root(...args) { return this.unimplemented("pivot_root", ...args); }
  syscall_mincore(...args) { return this.unimplemented("mincore", ...args); }
  syscall_madvise(...args) { return this.unimplemented("madvise", ...args); }
  syscall_madvise1(...args) { return this.unimplemented("madvise1", ...args); }
  syscall_getdents64(...args) { return this.unimplemented("getdents64", ...args); }
  syscall_fcntl64(...args) { return this.unimplemented("fcntl64", ...args); }
  syscall_gettid(...args) { return this.unimplemented("gettid", ...args); }
  syscall_readahead(...args) { return this.unimplemented("readahead", ...args); }
  syscall_setxattr(...args) { return this.unimplemented("setxattr", ...args); }
  syscall_lsetxattr(...args) { return this.unimplemented("lsetxattr", ...args); }
  syscall_fsetxattr(...args) { return this.unimplemented("fsetxattr", ...args); }
  syscall_getxattr(...args) { return this.unimplemented("getxattr", ...args); }
  syscall_lgetxattr(...args) { return this.unimplemented("lgetxattr", ...args); }
  syscall_fgetxattr(...args) { return this.unimplemented("fgetxattr", ...args); }
  syscall_listxattr(...args) { return this.unimplemented("listxattr", ...args); }
  syscall_llistxattr(...args) { return this.unimplemented("llistxattr", ...args); }
  syscall_flistxattr(...args) { return this.unimplemented("flistxattr", ...args); }
  syscall_removexattr(...args) { return this.unimplemented("removexattr", ...args); }
  syscall_lremovexattr(...args) { return this.unimplemented("lremovexattr", ...args); }
  syscall_fremovexattr(...args) { return this.unimplemented("fremovexattr", ...args); }
  syscall_tkill(...args) { return this.unimplemented("tkill", ...args); }
  syscall_sendfile64(...args) { return this.unimplemented("sendfile64", ...args); }
  syscall_futex(...args) { return this.unimplemented("futex", ...args); }
  syscall_sched_setaffinity(...args) { return this.unimplemented("sched_setaffinity", ...args); }
  syscall_sched_getaffinity(...args) { return this.unimplemented("sched_getaffinity", ...args); }
  syscall_set_thread_area(...args) { return this.unimplemented("set_thread_area", ...args); }
  syscall_get_thread_area(...args) { return this.unimplemented("get_thread_area", ...args); }
  syscall_io_setup(...args) { return this.unimplemented("io_setup", ...args); }
  syscall_io_destroy(...args) { return this.unimplemented("io_destroy", ...args); }
  syscall_io_getevents(...args) { return this.unimplemented("io_getevents", ...args); }
  syscall_io_submit(...args) { return this.unimplemented("io_submit", ...args); }
  syscall_io_cancel(...args) { return this.unimplemented("io_cancel", ...args); }
  syscall_fadvise64(...args) { return this.unimplemented("fadvise64", ...args); }
  syscall_exit_group(...args) { return this.unimplemented("exit_group", ...args); }
  syscall_lookup_dcookie(...args) { return this.unimplemented("lookup_dcookie", ...args); }
  syscall_epoll_create(...args) { return this.unimplemented("epoll_create", ...args); }
  syscall_epoll_ctl(...args) { return this.unimplemented("epoll_ctl", ...args); }
  syscall_epoll_wait(...args) { return this.unimplemented("epoll_wait", ...args); }
  syscall_remap_file_pages(...args) { return this.unimplemented("remap_file_pages", ...args); }
  syscall_set_tid_address(...args) { return this.unimplemented("set_tid_address", ...args); }
  syscall_timer_create(...args) { return this.unimplemented("timer_create", ...args); }
  syscall_timer_settime(...args) { return this.unimplemented("timer_settime", ...args); }
  syscall_timer_gettime(...args) { return this.unimplemented("timer_gettime", ...args); }
  syscall_timer_getoverrun(...args) { return this.unimplemented("timer_getoverrun", ...args); }
  syscall_timer_delete(...args) { return this.unimplemented("timer_delete", ...args); }
  syscall_clock_settime(...args) { return this.unimplemented("clock_settime", ...args); }
  syscall_clock_gettime(...args) { return this.unimplemented("clock_gettime", ...args); }
  syscall_clock_getres(...args) { return this.unimplemented("clock_getres", ...args); }
  syscall_clock_nanosleep(...args) { return this.unimplemented("clock_nanosleep", ...args); }
  syscall_statfs64(...args) { return this.unimplemented("statfs64", ...args); }
  syscall_fstatfs64(...args) { return this.unimplemented("fstatfs64", ...args); }
  syscall_tgkill(...args) { return this.unimplemented("tgkill", ...args); }
  syscall_utimes(...args) { return this.unimplemented("utimes", ...args); }
  syscall_fadvise64_64(...args) { return this.unimplemented("fadvise64_64", ...args); }
  syscall_vserver(...args) { return this.unimplemented("vserver", ...args); }
  syscall_mbind(...args) { return this.unimplemented("mbind", ...args); }
  syscall_get_mempolicy(...args) { return this.unimplemented("get_mempolicy", ...args); }
  syscall_set_mempolicy(...args) { return this.unimplemented("set_mempolicy", ...args); }
  syscall_mq_open(...args) { return this.unimplemented("mq_open", ...args); }
  syscall_mq_unlink(...args) { return this.unimplemented("mq_unlink", ...args); }
  syscall_mq_timedsend(...args) { return this.unimplemented("mq_timedsend", ...args); }
  syscall_mq_timedreceive(...args) { return this.unimplemented("mq_timedreceive", ...args); }
  syscall_mq_notify(...args) { return this.unimplemented("mq_notify", ...args); }
  syscall_mq_getsetattr(...args) { return this.unimplemented("mq_getsetattr", ...args); }
  syscall_kexec_load(...args) { return this.unimplemented("kexec_load", ...args); }
  syscall_waitid(...args) { return this.unimplemented("waitid", ...args); }
  syscall_add_key(...args) { return this.unimplemented("add_key", ...args); }
  syscall_request_key(...args) { return this.unimplemented("request_key", ...args); }
  syscall_keyctl(...args) { return this.unimplemented("keyctl", ...args); }
  syscall_ioprio_set(...args) { return this.unimplemented("ioprio_set", ...args); }
  syscall_ioprio_get(...args) { return this.unimplemented("ioprio_get", ...args); }
  syscall_inotify_init(...args) { return this.unimplemented("inotify_init", ...args); }
  syscall_inotify_add_watch(...args) { return this.unimplemented("inotify_add_watch", ...args); }
  syscall_inotify_rm_watch(...args) { return this.unimplemented("inotify_rm_watch", ...args); }
  syscall_migrate_pages(...args) { return this.unimplemented("migrate_pages", ...args); }
  syscall_openat(...args) { return this.unimplemented("openat", ...args); }
  syscall_mkdirat(...args) { return this.unimplemented("mkdirat", ...args); }
  syscall_mknodat(...args) { return this.unimplemented("mknodat", ...args); }
  syscall_fchownat(...args) { return this.unimplemented("fchownat", ...args); }
  syscall_futimesat(...args) { return this.unimplemented("futimesat", ...args); }
  syscall_fstatat64(...args) { return this.unimplemented("fstatat64", ...args); }
  syscall_unlinkat(...args) { return this.unimplemented("unlinkat", ...args); }
  syscall_renameat(...args) { return this.unimplemented("renameat", ...args); }
  syscall_linkat(...args) { return this.unimplemented("linkat", ...args); }
  syscall_symlinkat(...args) { return this.unimplemented("symlinkat", ...args); }
  syscall_readlinkat(...args) { return this.unimplemented("readlinkat", ...args); }
  syscall_fchmodat(...args) { return this.unimplemented("fchmodat", ...args); }
  syscall_faccessat(...args) { return this.unimplemented("faccessat", ...args); }
  syscall_pselect6(...args) { return this.unimplemented("pselect6", ...args); }
  syscall_ppoll(...args) { return this.unimplemented("ppoll", ...args); }
  syscall_unshare(...args) { return this.unimplemented("unshare", ...args); }
  syscall_set_robust_list(...args) { return this.unimplemented("set_robust_list", ...args); }
  syscall_get_robust_list(...args) { return this.unimplemented("get_robust_list", ...args); }
  syscall_splice(...args) { return this.unimplemented("splice", ...args); }
  syscall_sync_file_range(...args) { return this.unimplemented("sync_file_range", ...args); }
  syscall_tee(...args) { return this.unimplemented("tee", ...args); }
  syscall_vmsplice(...args) { return this.unimplemented("vmsplice", ...args); }
  syscall_move_pages(...args) { return this.unimplemented("move_pages", ...args); }
  syscall_getcpu(...args) { return this.unimplemented("getcpu", ...args); }
  syscall_epoll_pwait(...args) { return this.unimplemented("epoll_pwait", ...args); }
  syscall_utimensat(...args) { return this.unimplemented("utimensat", ...args); }
  syscall_signalfd(...args) { return this.unimplemented("signalfd", ...args); }
  syscall_timerfd_create(...args) { return this.unimplemented("timerfd_create", ...args); }
  syscall_eventfd(...args) { return this.unimplemented("eventfd", ...args); }
  syscall_fallocate(...args) { return this.unimplemented("fallocate", ...args); }
  syscall_timerfd_settime(...args) { return this.unimplemented("timerfd_settime", ...args); }
  syscall_timerfd_gettime(...args) { return this.unimplemented("timerfd_gettime", ...args); }
  syscall_signalfd4(...args) { return this.unimplemented("signalfd4", ...args); }
  syscall_eventfd2(...args) { return this.unimplemented("eventfd2", ...args); }
  syscall_epoll_create1(...args) { return this.unimplemented("epoll_create1", ...args); }
  syscall_dup3(...args) { return this.unimplemented("dup3", ...args); }
  syscall_pipe2(...args) { return this.unimplemented("pipe2", ...args); }
  syscall_inotify_init1(...args) { return this.unimplemented("inotify_init1", ...args); }
  syscall_preadv(...args) { return this.unimplemented("preadv", ...args); }
  syscall_pwritev(...args) { return this.unimplemented("pwritev", ...args); }
  syscall_rt_tgsigqueueinfo(...args) { return this.unimplemented("rt_tgsigqueueinfo", ...args); }
  syscall_perf_event_open(...args) { return this.unimplemented("perf_event_open", ...args); }
  syscall_recvmmsg(...args) { return this.unimplemented("recvmmsg", ...args); }
  syscall_fanotify_init(...args) { return this.unimplemented("fanotify_init", ...args); }
  syscall_fanotify_mark(...args) { return this.unimplemented("fanotify_mark", ...args); }
  syscall_prlimit64(...args) { return this.unimplemented("prlimit64", ...args); }
  syscall_name_to_handle_at(...args) { return this.unimplemented("name_to_handle_at", ...args); }
  syscall_open_by_handle_at(...args) { return this.unimplemented("open_by_handle_at", ...args); }
  syscall_clock_adjtime(...args) { return this.unimplemented("clock_adjtime", ...args); }
  syscall_syncfs(...args) { return this.unimplemented("syncfs", ...args); }
  syscall_sendmmsg(...args) { return this.unimplemented("sendmmsg", ...args); }
  syscall_setns(...args) { return this.unimplemented("setns", ...args); }
  syscall_process_vm_readv(...args) { return this.unimplemented("process_vm_readv", ...args); }
  syscall_process_vm_writev(...args) { return this.unimplemented("process_vm_writev", ...args); }
  syscall_kcmp(...args) { return this.unimplemented("kcmp", ...args); }
  syscall_finit_module(...args) { return this.unimplemented("finit_module", ...args); }
  syscall_sched_setattr(...args) { return this.unimplemented("sched_setattr", ...args); }
  syscall_sched_getattr(...args) { return this.unimplemented("sched_getattr", ...args); }
  syscall_renameat2(...args) { return this.unimplemented("renameat2", ...args); }
  syscall_seccomp(...args) { return this.unimplemented("seccomp", ...args); }
  syscall_getrandom(...args) { return this.unimplemented("getrandom", ...args); }
  syscall_memfd_create(...args) { return this.unimplemented("memfd_create", ...args); }
  syscall_bpf(...args) { return this.unimplemented("bpf", ...args); }
  syscall_execveat(...args) { return this.unimplemented("execveat", ...args); }
  syscall_socket(...args) { return this.unimplemented("socket", ...args); }
  syscall_socketpair(...args) { return this.unimplemented("socketpair", ...args); }
  syscall_bind(...args) { return this.unimplemented("bind", ...args); }
  syscall_connect(...args) { return this.unimplemented("connect", ...args); }
  syscall_listen(...args) { return this.unimplemented("listen", ...args); }
  syscall_accept4(...args) { return this.unimplemented("accept4", ...args); }
  syscall_getsockopt(...args) { return this.unimplemented("getsockopt", ...args); }
  syscall_setsockopt(...args) { return this.unimplemented("setsockopt", ...args); }
  syscall_getsockname(...args) { return this.unimplemented("getsockname", ...args); }
  syscall_getpeername(...args) { return this.unimplemented("getpeername", ...args); }
  syscall_sendto(...args) { return this.unimplemented("sendto", ...args); }
  syscall_sendmsg(...args) { return this.unimplemented("sendmsg", ...args); }
  syscall_recvfrom(...args) { return this.unimplemented("recvfrom", ...args); }
  syscall_recvmsg(...args) { return this.unimplemented("recvmsg", ...args); }
  syscall_shutdown(...args) { return this.unimplemented("shutdown", ...args); }
  syscall_userfaultfd(...args) { return this.unimplemented("userfaultfd", ...args); }
  syscall_membarrier(...args) { return this.unimplemented("membarrier", ...args); }
  syscall_mlock2(...args) { return this.unimplemented("mlock2", ...args); }
  syscall_copy_file_range(...args) { return this.unimplemented("copy_file_range", ...args); }
  syscall_preadv2(...args) { return this.unimplemented("preadv2", ...args); }
  syscall_pwritev2(...args) { return this.unimplemented("pwritev2", ...args); }

  syscall(nr, ...args) {
    switch (nr) {
    case 0: return this.syscall_restart_syscall(...args);
    case 1: return this.syscall_exit(...args);
    case 2: return this.syscall_fork(...args);
    case 3: return this.syscall_read(...args);
    case 4: return this.syscall_write(...args);
    case 5: return this.syscall_open(...args);
    case 6: return this.syscall_close(...args);
    case 7: return this.syscall_waitpid(...args);
    case 8: return this.syscall_creat(...args);
    case 9: return this.syscall_link(...args);
    case 10: return this.syscall_unlink(...args);
    case 11: return this.syscall_execve(...args);
    case 12: return this.syscall_chdir(...args);
    case 13: return this.syscall_time(...args);
    case 14: return this.syscall_mknod(...args);
    case 15: return this.syscall_chmod(...args);
    case 16: return this.syscall_lchown(...args);
    case 17: return this.syscall_break(...args);
    case 18: return this.syscall_oldstat(...args);
    case 19: return this.syscall_lseek(...args);
    case 20: return this.syscall_getpid(...args);
    case 21: return this.syscall_mount(...args);
    case 22: return this.syscall_umount(...args);
    case 23: return this.syscall_setuid(...args);
    case 24: return this.syscall_getuid(...args);
    case 25: return this.syscall_stime(...args);
    case 26: return this.syscall_ptrace(...args);
    case 27: return this.syscall_alarm(...args);
    case 28: return this.syscall_oldfstat(...args);
    case 29: return this.syscall_pause(...args);
    case 30: return this.syscall_utime(...args);
    case 31: return this.syscall_stty(...args);
    case 32: return this.syscall_gtty(...args);
    case 33: return this.syscall_access(...args);
    case 34: return this.syscall_nice(...args);
    case 35: return this.syscall_ftime(...args);
    case 36: return this.syscall_sync(...args);
    case 37: return this.syscall_kill(...args);
    case 38: return this.syscall_rename(...args);
    case 39: return this.syscall_mkdir(...args);
    case 40: return this.syscall_rmdir(...args);
    case 41: return this.syscall_dup(...args);
    case 42: return this.syscall_pipe(...args);
    case 43: return this.syscall_times(...args);
    case 44: return this.syscall_prof(...args);
    case 45: return this.syscall_brk(...args);
    case 46: return this.syscall_setgid(...args);
    case 47: return this.syscall_getgid(...args);
    case 48: return this.syscall_signal(...args);
    case 49: return this.syscall_geteuid(...args);
    case 50: return this.syscall_getegid(...args);
    case 51: return this.syscall_acct(...args);
    case 52: return this.syscall_umount2(...args);
    case 53: return this.syscall_lock(...args);
    case 54: return this.syscall_ioctl(...args);
    case 55: return this.syscall_fcntl(...args);
    case 56: return this.syscall_mpx(...args);
    case 57: return this.syscall_setpgid(...args);
    case 58: return this.syscall_ulimit(...args);
    case 59: return this.syscall_oldolduname(...args);
    case 60: return this.syscall_umask(...args);
    case 61: return this.syscall_chroot(...args);
    case 62: return this.syscall_ustat(...args);
    case 63: return this.syscall_dup2(...args);
    case 64: return this.syscall_getppid(...args);
    case 65: return this.syscall_getpgrp(...args);
    case 66: return this.syscall_setsid(...args);
    case 67: return this.syscall_sigaction(...args);
    case 68: return this.syscall_sgetmask(...args);
    case 69: return this.syscall_ssetmask(...args);
    case 70: return this.syscall_setreuid(...args);
    case 71: return this.syscall_setregid(...args);
    case 72: return this.syscall_sigsuspend(...args);
    case 73: return this.syscall_sigpending(...args);
    case 74: return this.syscall_sethostname(...args);
    case 75: return this.syscall_setrlimit(...args);
    case 76: return this.syscall_getrlimit(...args);
    case 77: return this.syscall_getrusage(...args);
    case 78: return this.syscall_gettimeofday(...args);
    case 79: return this.syscall_settimeofday(...args);
    case 80: return this.syscall_getgroups(...args);
    case 81: return this.syscall_setgroups(...args);
    case 82: return this.syscall_select(...args);
    case 83: return this.syscall_symlink(...args);
    case 84: return this.syscall_oldlstat(...args);
    case 85: return this.syscall_readlink(...args);
    case 86: return this.syscall_uselib(...args);
    case 87: return this.syscall_swapon(...args);
    case 88: return this.syscall_reboot(...args);
    case 89: return this.syscall_readdir(...args);
    case 90: return this.syscall_mmap(...args);
    case 91: return this.syscall_munmap(...args);
    case 92: return this.syscall_truncate(...args);
    case 93: return this.syscall_ftruncate(...args);
    case 94: return this.syscall_fchmod(...args);
    case 95: return this.syscall_fchown(...args);
    case 96: return this.syscall_getpriority(...args);
    case 97: return this.syscall_setpriority(...args);
    case 98: return this.syscall_profil(...args);
    case 99: return this.syscall_statfs(...args);
    case 100: return this.syscall_fstatfs(...args);
    case 101: return this.syscall_ioperm(...args);
    case 102: return this.syscall_socketcall(...args);
    case 103: return this.syscall_syslog(...args);
    case 104: return this.syscall_setitimer(...args);
    case 105: return this.syscall_getitimer(...args);
    case 106: return this.syscall_stat(...args);
    case 107: return this.syscall_lstat(...args);
    case 108: return this.syscall_fstat(...args);
    case 109: return this.syscall_olduname(...args);
    case 110: return this.syscall_iopl(...args);
    case 111: return this.syscall_vhangup(...args);
    case 112: return this.syscall_idle(...args);
    case 113: return this.syscall_vm86old(...args);
    case 114: return this.syscall_wait4(...args);
    case 115: return this.syscall_swapoff(...args);
    case 116: return this.syscall_sysinfo(...args);
    case 117: return this.syscall_ipc(...args);
    case 118: return this.syscall_fsync(...args);
    case 119: return this.syscall_sigreturn(...args);
    case 120: return this.syscall_clone(...args);
    case 121: return this.syscall_setdomainname(...args);
    case 122: return this.syscall_uname(...args);
    case 123: return this.syscall_modify_ldt(...args);
    case 124: return this.syscall_adjtimex(...args);
    case 125: return this.syscall_mprotect(...args);
    case 126: return this.syscall_sigprocmask(...args);
    case 127: return this.syscall_create_module(...args);
    case 128: return this.syscall_init_module(...args);
    case 129: return this.syscall_delete_module(...args);
    case 130: return this.syscall_get_kernel_syms(...args);
    case 131: return this.syscall_quotactl(...args);
    case 132: return this.syscall_getpgid(...args);
    case 133: return this.syscall_fchdir(...args);
    case 134: return this.syscall_bdflush(...args);
    case 135: return this.syscall_sysfs(...args);
    case 136: return this.syscall_personality(...args);
    case 137: return this.syscall_afs_syscall(...args);
    case 138: return this.syscall_setfsuid(...args);
    case 139: return this.syscall_setfsgid(...args);
    case 140: return this.syscall__llseek(...args);
    case 141: return this.syscall_getdents(...args);
    case 142: return this.syscall__newselect(...args);
    case 143: return this.syscall_flock(...args);
    case 144: return this.syscall_msync(...args);
    case 145: return this.syscall_readv(...args);
    case 146: return this.syscall_writev(...args);
    case 147: return this.syscall_getsid(...args);
    case 148: return this.syscall_fdatasync(...args);
    case 149: return this.syscall__sysctl(...args);
    case 150: return this.syscall_mlock(...args);
    case 151: return this.syscall_munlock(...args);
    case 152: return this.syscall_mlockall(...args);
    case 153: return this.syscall_munlockall(...args);
    case 154: return this.syscall_sched_setparam(...args);
    case 155: return this.syscall_sched_getparam(...args);
    case 156: return this.syscall_sched_setscheduler(...args);
    case 157: return this.syscall_sched_getscheduler(...args);
    case 158: return this.syscall_sched_yield(...args);
    case 159: return this.syscall_sched_get_priority_max(...args);
    case 160: return this.syscall_sched_get_priority_min(...args);
    case 161: return this.syscall_sched_rr_get_interval(...args);
    case 162: return this.syscall_nanosleep(...args);
    case 163: return this.syscall_mremap(...args);
    case 164: return this.syscall_setresuid(...args);
    case 165: return this.syscall_getresuid(...args);
    case 166: return this.syscall_vm86(...args);
    case 167: return this.syscall_query_module(...args);
    case 168: return this.syscall_poll(...args);
    case 169: return this.syscall_nfsservctl(...args);
    case 170: return this.syscall_setresgid(...args);
    case 171: return this.syscall_getresgid(...args);
    case 172: return this.syscall_prctl(...args);
    case 173: return this.syscall_rt_sigreturn(...args);
    case 174: return this.syscall_rt_sigaction(...args);
    case 175: return this.syscall_rt_sigprocmask(...args);
    case 176: return this.syscall_rt_sigpending(...args);
    case 177: return this.syscall_rt_sigtimedwait(...args);
    case 178: return this.syscall_rt_sigqueueinfo(...args);
    case 179: return this.syscall_rt_sigsuspend(...args);
    case 180: return this.syscall_pread64(...args);
    case 181: return this.syscall_pwrite64(...args);
    case 182: return this.syscall_chown(...args);
    case 183: return this.syscall_getcwd(...args);
    case 184: return this.syscall_capget(...args);
    case 185: return this.syscall_capset(...args);
    case 186: return this.syscall_sigaltstack(...args);
    case 187: return this.syscall_sendfile(...args);
    case 188: return this.syscall_getpmsg(...args);
    case 189: return this.syscall_putpmsg(...args);
    case 190: return this.syscall_vfork(...args);
    case 191: return this.syscall_ugetrlimit(...args);
    case 192: return this.syscall_mmap2(...args);
    case 193: return this.syscall_truncate64(...args);
    case 194: return this.syscall_ftruncate64(...args);
    case 195: return this.syscall_stat64(...args);
    case 196: return this.syscall_lstat64(...args);
    case 197: return this.syscall_fstat64(...args);
    case 198: return this.syscall_lchown32(...args);
    case 199: return this.syscall_getuid32(...args);
    case 200: return this.syscall_getgid32(...args);
    case 201: return this.syscall_geteuid32(...args);
    case 202: return this.syscall_getegid32(...args);
    case 203: return this.syscall_setreuid32(...args);
    case 204: return this.syscall_setregid32(...args);
    case 205: return this.syscall_getgroups32(...args);
    case 206: return this.syscall_setgroups32(...args);
    case 207: return this.syscall_fchown32(...args);
    case 208: return this.syscall_setresuid32(...args);
    case 209: return this.syscall_getresuid32(...args);
    case 210: return this.syscall_setresgid32(...args);
    case 211: return this.syscall_getresgid32(...args);
    case 212: return this.syscall_chown32(...args);
    case 213: return this.syscall_setuid32(...args);
    case 214: return this.syscall_setgid32(...args);
    case 215: return this.syscall_setfsuid32(...args);
    case 216: return this.syscall_setfsgid32(...args);
    case 217: return this.syscall_pivot_root(...args);
    case 218: return this.syscall_mincore(...args);
    case 219: return this.syscall_madvise(...args);
    case 219: return this.syscall_madvise1(...args);
    case 220: return this.syscall_getdents64(...args);
    case 221: return this.syscall_fcntl64(...args);
    case 224: return this.syscall_gettid(...args);
    case 225: return this.syscall_readahead(...args);
    case 226: return this.syscall_setxattr(...args);
    case 227: return this.syscall_lsetxattr(...args);
    case 228: return this.syscall_fsetxattr(...args);
    case 229: return this.syscall_getxattr(...args);
    case 230: return this.syscall_lgetxattr(...args);
    case 231: return this.syscall_fgetxattr(...args);
    case 232: return this.syscall_listxattr(...args);
    case 233: return this.syscall_llistxattr(...args);
    case 234: return this.syscall_flistxattr(...args);
    case 235: return this.syscall_removexattr(...args);
    case 236: return this.syscall_lremovexattr(...args);
    case 237: return this.syscall_fremovexattr(...args);
    case 238: return this.syscall_tkill(...args);
    case 239: return this.syscall_sendfile64(...args);
    case 240: return this.syscall_futex(...args);
    case 241: return this.syscall_sched_setaffinity(...args);
    case 242: return this.syscall_sched_getaffinity(...args);
    case 243: return this.syscall_set_thread_area(...args);
    case 244: return this.syscall_get_thread_area(...args);
    case 245: return this.syscall_io_setup(...args);
    case 246: return this.syscall_io_destroy(...args);
    case 247: return this.syscall_io_getevents(...args);
    case 248: return this.syscall_io_submit(...args);
    case 249: return this.syscall_io_cancel(...args);
    case 250: return this.syscall_fadvise64(...args);
    case 252: return this.syscall_exit_group(...args);
    case 253: return this.syscall_lookup_dcookie(...args);
    case 254: return this.syscall_epoll_create(...args);
    case 255: return this.syscall_epoll_ctl(...args);
    case 256: return this.syscall_epoll_wait(...args);
    case 257: return this.syscall_remap_file_pages(...args);
    case 258: return this.syscall_set_tid_address(...args);
    case 259: return this.syscall_timer_create(...args);
    case 260: return this.syscall_timer_settime(...args);
    case 261: return this.syscall_timer_gettime(...args);
    case 262: return this.syscall_timer_getoverrun(...args);
    case 263: return this.syscall_timer_delete(...args);
    case 264: return this.syscall_clock_settime(...args);
    case 265: return this.syscall_clock_gettime(...args);
    case 266: return this.syscall_clock_getres(...args);
    case 267: return this.syscall_clock_nanosleep(...args);
    case 268: return this.syscall_statfs64(...args);
    case 269: return this.syscall_fstatfs64(...args);
    case 270: return this.syscall_tgkill(...args);
    case 271: return this.syscall_utimes(...args);
    case 272: return this.syscall_fadvise64_64(...args);
    case 273: return this.syscall_vserver(...args);
    case 274: return this.syscall_mbind(...args);
    case 275: return this.syscall_get_mempolicy(...args);
    case 276: return this.syscall_set_mempolicy(...args);
    case 277: return this.syscall_mq_open(...args);
    case 278: return this.syscall_mq_unlink(...args);
    case 279: return this.syscall_mq_timedsend(...args);
    case 280: return this.syscall_mq_timedreceive(...args);
    case 281: return this.syscall_mq_notify(...args);
    case 282: return this.syscall_mq_getsetattr(...args);
    case 283: return this.syscall_kexec_load(...args);
    case 284: return this.syscall_waitid(...args);
    case 286: return this.syscall_add_key(...args);
    case 287: return this.syscall_request_key(...args);
    case 288: return this.syscall_keyctl(...args);
    case 289: return this.syscall_ioprio_set(...args);
    case 290: return this.syscall_ioprio_get(...args);
    case 291: return this.syscall_inotify_init(...args);
    case 292: return this.syscall_inotify_add_watch(...args);
    case 293: return this.syscall_inotify_rm_watch(...args);
    case 294: return this.syscall_migrate_pages(...args);
    case 295: return this.syscall_openat(...args);
    case 296: return this.syscall_mkdirat(...args);
    case 297: return this.syscall_mknodat(...args);
    case 298: return this.syscall_fchownat(...args);
    case 299: return this.syscall_futimesat(...args);
    case 300: return this.syscall_fstatat64(...args);
    case 301: return this.syscall_unlinkat(...args);
    case 302: return this.syscall_renameat(...args);
    case 303: return this.syscall_linkat(...args);
    case 304: return this.syscall_symlinkat(...args);
    case 305: return this.syscall_readlinkat(...args);
    case 306: return this.syscall_fchmodat(...args);
    case 307: return this.syscall_faccessat(...args);
    case 308: return this.syscall_pselect6(...args);
    case 309: return this.syscall_ppoll(...args);
    case 310: return this.syscall_unshare(...args);
    case 311: return this.syscall_set_robust_list(...args);
    case 312: return this.syscall_get_robust_list(...args);
    case 313: return this.syscall_splice(...args);
    case 314: return this.syscall_sync_file_range(...args);
    case 315: return this.syscall_tee(...args);
    case 316: return this.syscall_vmsplice(...args);
    case 317: return this.syscall_move_pages(...args);
    case 318: return this.syscall_getcpu(...args);
    case 319: return this.syscall_epoll_pwait(...args);
    case 320: return this.syscall_utimensat(...args);
    case 321: return this.syscall_signalfd(...args);
    case 322: return this.syscall_timerfd_create(...args);
    case 323: return this.syscall_eventfd(...args);
    case 324: return this.syscall_fallocate(...args);
    case 325: return this.syscall_timerfd_settime(...args);
    case 326: return this.syscall_timerfd_gettime(...args);
    case 327: return this.syscall_signalfd4(...args);
    case 328: return this.syscall_eventfd2(...args);
    case 329: return this.syscall_epoll_create1(...args);
    case 330: return this.syscall_dup3(...args);
    case 331: return this.syscall_pipe2(...args);
    case 332: return this.syscall_inotify_init1(...args);
    case 333: return this.syscall_preadv(...args);
    case 334: return this.syscall_pwritev(...args);
    case 335: return this.syscall_rt_tgsigqueueinfo(...args);
    case 336: return this.syscall_perf_event_open(...args);
    case 337: return this.syscall_recvmmsg(...args);
    case 338: return this.syscall_fanotify_init(...args);
    case 339: return this.syscall_fanotify_mark(...args);
    case 340: return this.syscall_prlimit64(...args);
    case 341: return this.syscall_name_to_handle_at(...args);
    case 342: return this.syscall_open_by_handle_at(...args);
    case 343: return this.syscall_clock_adjtime(...args);
    case 344: return this.syscall_syncfs(...args);
    case 345: return this.syscall_sendmmsg(...args);
    case 346: return this.syscall_setns(...args);
    case 347: return this.syscall_process_vm_readv(...args);
    case 348: return this.syscall_process_vm_writev(...args);
    case 349: return this.syscall_kcmp(...args);
    case 350: return this.syscall_finit_module(...args);
    case 351: return this.syscall_sched_setattr(...args);
    case 352: return this.syscall_sched_getattr(...args);
    case 353: return this.syscall_renameat2(...args);
    case 354: return this.syscall_seccomp(...args);
    case 355: return this.syscall_getrandom(...args);
    case 356: return this.syscall_memfd_create(...args);
    case 357: return this.syscall_bpf(...args);
    case 358: return this.syscall_execveat(...args);
    case 359: return this.syscall_socket(...args);
    case 360: return this.syscall_socketpair(...args);
    case 361: return this.syscall_bind(...args);
    case 362: return this.syscall_connect(...args);
    case 363: return this.syscall_listen(...args);
    case 364: return this.syscall_accept4(...args);
    case 365: return this.syscall_getsockopt(...args);
    case 366: return this.syscall_setsockopt(...args);
    case 367: return this.syscall_getsockname(...args);
    case 368: return this.syscall_getpeername(...args);
    case 369: return this.syscall_sendto(...args);
    case 370: return this.syscall_sendmsg(...args);
    case 371: return this.syscall_recvfrom(...args);
    case 372: return this.syscall_recvmsg(...args);
    case 373: return this.syscall_shutdown(...args);
    case 374: return this.syscall_userfaultfd(...args);
    case 375: return this.syscall_membarrier(...args);
    case 376: return this.syscall_mlock2(...args);
    case 377: return this.syscall_copy_file_range(...args);
    case 378: return this.syscall_preadv2(...args);
    case 379: return this.syscall_pwritev2(...args);
    default: return this.syscall_unknown(nr, ...args);
    }
  }

  syscall_unknown() {
    print("Unknown syscall: " + arguments.join(' '));
    quit(1);
  }

  makeEnvObject() {
    return {
      __syscall: this.syscall.bind(this)
    };
  }
}

class PThread {
  constructor() {
    this.instance = null;
  }

  pthread_self() {
    return 1;
  }

  makeEnvObject() {
    return {};
  }
}
  
class Runtime {
  constructor() {
    this.instance = null;
  }

  a_and() { print("unimplemented: a_and"); quit(1); }

  a_or(p, v) {
    let mem = this.instance.exports.memory.buffer;
    let s = new Int32Array(mem, p, 1);
    s[0] |= v;
  }

  a_cas() { print("unimplemented: a_cas"); quit(1); }
  a_dec() { print("unimplemented: a_dec"); quit(1); }
  a_inc() { print("unimplemented: a_inc"); quit(1); }
  a_spin() { print("unimplemented: a_spin"); quit(1); }
  a_store() { print("unimplemented: a_store"); quit(1); }
  a_swap() { print("unimplemented: a_swap"); quit(1); }
  a_crash() { print("unimplemented: a_crash"); quit(1); }
  a_ctz_64() { print("unimplemented: a_ctz_64"); quit(1); }

  printn(p, n) {
    let mem = this.instance.exports.memory.buffer;
    let s = new Uint8Array(mem, p, n);
    let cs = [];
    for (let c of s)
      cs.push(String.fromCharCode(c));
    print(cs.join(''));
  }

  get_args_buffer_size() {
    return 4;
  }
  
  get_args(p) {
    let mem = this.instance.exports.memory.buffer;
    let s = new Uint32Array(mem, p, 1);
    s[0] = 0;
  }

  makeEnvObject() {
    return {
      printn: this.printn.bind(this),
      a_and: this.a_and.bind(this),
      a_or: this.a_or.bind(this),
      a_cas: this.a_cas.bind(this),
      a_dec: this.a_dec.bind(this),
      a_inc: this.a_inc.bind(this),
      a_spin: this.a_spin.bind(this),
      a_store: this.a_store.bind(this),
      a_swap: this.a_swap.bind(this),
      a_crash: this.a_crash.bind(this),
      a_ctz_64: this.a_ctz_64.bind(this),
      get_args_buffer_size: this.get_args_buffer_size.bind(this),
      get_args: this.get_args.bind(this)
    };
  }
}

(async function(program_file, ...args) {
  let timing = new Timing();
  let binary = readbuffer(program_file);
  timing.emit("load");
  
  let module = await WebAssembly.compile(binary);
  timing.emit("compile");
  
  let runtime = new Runtime;
  let syscall = new Syscall;
  let pthread = new PThread;
  let env = combineEnvObject(
    runtime.makeEnvObject(),
    syscall.makeEnvObject(),
    pthread.makeEnvObject());

  let instance = new WebAssembly.Instance(module, {env});
  runtime.instance = instance;
  syscall.instance = instance;
  pthread.instance = instance;
  timing.emit("instantiate");

  // TODO(tzik): Pass args.
  let rv = instance.exports.entry_point();
  timing.emit("execute");
  quit(rv);
})(...arguments).catch(e => {
  print(e);
  quit(1);
});
