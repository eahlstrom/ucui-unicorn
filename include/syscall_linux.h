#ifndef _syscall_linux_h
#define _syscall_linux_h

// generic linux syscall list used by linux_syscall_printw
enum linux_syscall {
  SYS_EXIT = 1000,
  SYS_READ,
  SYS_OPEN,
  SYS_WRITE,
  SYS_CHMOD,
  SYS_SIGNAL,
  SYS_IOCTL,
  SYS_SETUID,
  SYS_SETGID,
  SYS_SETREUID,
  SYS_CLOSE,
  SYS_ALARM,
  SYS_NICE,
  SYS_KILL,
  SYS_DUP,
  SYS_UMASK,
  SYS_DUP2,
  SYS_SSETMASK,
  SYS_GETPRIORITY,
  SYS_SETPRIORITY,
  SYS_FSYNC,
  SYS_FCHDIR,
  SYS_FLOCK,
  SYS_FDATASYNC,
  SYS_MLOCKALL,
  SYS_SCHED_GET_PRIORITY_MAX,
  SYS_SCHED_GET_PRIORITY_MIN,
  SYS_EXECVE,
};

// Syscall mapping's between generic and arch number.
enum linux_syscall * linux_syscall_map_x86(void);

// Generic syscall printer for x86, x64 and ARM
int32_t linux_syscall_printw(WINDOW *w, uc_engine *uc, enum linux_syscall scnum, void *arg0, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);

// Syscall handlers for different arch's
void hook_intr_x86_linux(uc_engine *uc, uint32_t intno, void *user_data);
void hook_intr_x64_linux(uc_engine *uc, uint32_t intno, void *user_data);
void hook_intr_arm_linux(uc_engine *uc, uint32_t intno, void *user_data);

#endif
