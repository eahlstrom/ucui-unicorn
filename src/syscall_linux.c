#include "ucui.h"
#include "syscall.h"

//
// Mapping between generic syscall and x86 syscall number
//
enum linux_syscall * linux_syscall_map_x86(void)
{
    enum linux_syscall *sm = NULL;
    size_t size;

    size = (sizeof(enum linux_syscall) * 190) + 1;
    sm = xmalloc(size);
    memset(sm, 0, size);

    sm[1] = SYS_EXIT;
    sm[3] = SYS_READ;
    sm[4] = SYS_WRITE;
    sm[5] = SYS_OPEN;
    sm[6] = SYS_CLOSE;
    sm[11] = SYS_EXECVE;
    sm[15] = SYS_CHMOD;
    sm[23] = SYS_SETUID;
    sm[24] = SYS_SETGID;
    sm[27] = SYS_ALARM;
    sm[34] = SYS_NICE;
    sm[37] = SYS_KILL;
    sm[41] = SYS_DUP;
    sm[48] = SYS_SIGNAL;
    sm[54] = SYS_IOCTL;
    sm[60] = SYS_UMASK;
    sm[63] = SYS_DUP2;
    sm[69] = SYS_SSETMASK;
    sm[70] = SYS_SETREUID;
    sm[96] = SYS_GETPRIORITY;
    sm[97] = SYS_SETPRIORITY;
    sm[118] = SYS_FSYNC;
    sm[133] = SYS_FCHDIR;
    sm[143] = SYS_FLOCK;
    sm[148] = SYS_FDATASYNC;
    sm[152] = SYS_MLOCKALL;
    sm[159] = SYS_SCHED_GET_PRIORITY_MAX;
    sm[160] = SYS_SCHED_GET_PRIORITY_MIN;

    return(sm);
}

//
// Mapping between generic syscall and x64 syscall number
//
enum linux_syscall * linux_syscall_map_x64(void)
{
    enum linux_syscall *sm = NULL;
    size_t size;

    size = (sizeof(enum linux_syscall) * 322) + 1;
    sm = xmalloc(size);
    memset(sm, 0, size);

    sm[1] = SYS_WRITE;
    sm[59] = SYS_EXECVE;
    sm[60] = SYS_EXIT;

    return(sm);
}


//
// x86 syscall descrambler
//
void hook_intr_x86_linux(uc_engine *uc, uint32_t intno, void *user_data)
{
    struct x86_regs *r;
    enum linux_syscall *syscall_map = NULL;
    int32_t ret;

    syscall_map = linux_syscall_map_x86();

    r = read_x86_registers(uc);
    consw_info("%08x: syscall %-3d ", r->eip, r->eax);
    if (r->eax > 190 || syscall_map[r->eax] == 0) {
        consw("invalid linux syscall\n");
    } else {
        ret = linux_syscall_printw(consw, uc, syscall_map[r->eax], &r->ebx, &r->ecx, &r->edx, &r->edx, &r->esi, &r->edi);
        uc_reg_write(uc, UC_X86_REG_EAX, &ret);
    }
    xfree(syscall_map);
}

//
// x64 syscall descrambler
//
void hook_intr_x64_linux(uc_engine *uc, uint32_t intno, void *user_data)
{
    struct x64_regs *r;
    enum linux_syscall *syscall_map;
    int64_t ret;

    syscall_map = linux_syscall_map_x64();

    r = read_x64_registers(uc);
    wprintw(consw, ">>> %08x: syscall %-03d ", r->rip, r->rax);

    if (r->rax > 322 || syscall_map[r->rax] == 0) {
        wprintw(consw, "unhandled syscall\n");
        wrefresh(consw);
        return;
    } else {
        ret = linux_syscall_printw(consw, uc, syscall_map[r->rax], &r->rdi, &r->rsi, &r->rdx, &r->r10, &r->r8, &r->r9);
        uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    }
    xfree(syscall_map);
}

//
// arm syscall descrambler
//
void hook_intr_arm_linux(uc_engine *uc, uint32_t intno, void *user_data)
{
    struct arm_regs *r;
    enum linux_syscall *syscall_map;
    int32_t ret;

    // syscall map for 32bits ARM seems to be the same as x86
    syscall_map = linux_syscall_map_x86();

    r = read_arm_registers(uc);
    consw_info("%08x: syscall %-03d", r->pc, r->r7);
    if (r->r7 > 190 || syscall_map[r->r7] == 0) {
        consw("unhandled syscall\n");
        return;
    } else {
        ret = linux_syscall_printw(consw, uc, syscall_map[r->r7], &r->r0, &r->r1, &r->r2, &r->r3, &r->r4, &r->r5);
        uc_reg_write(uc, UC_ARM_REG_R0, &ret);
    }
    xfree(syscall_map);
}


//
// Generic syscall printer for x86, x64 and ARM
//
int32_t linux_syscall_printw(
        WINDOW *w, uc_engine *uc, enum linux_syscall scnum, 
        void *arg0, void *arg1, void *arg2, 
        void *arg3, void *arg4, void *arg5)
{
    int32_t ret = 0;
    char *s1=0, *s2=0, *s3=0;

    switch(scnum) {
        default:
            consw("unknown syscall\n");
            break;

        case SYS_EXIT:
            consw("SYS_EXIT(%d)\n", *((int*)arg0));
            consw_info("SYS_EXIT: Stopping emulation.\n");
            uc_emu_stop(uc);
            break;

        case SYS_READ:
            ret = *((uint32_t*)arg2);
            consw("SYS_READ(%d, %p, %u) = %u\n", *((uint8_t*)arg0), *((uint32_t*)arg1), *((uint32_t*)arg2), ret);
            break;

        case SYS_OPEN:
            s1 = uc_mem_read_string(uc, *((uint32_t*)arg0), 255, true);
            ret = rand() & 0xff;
            consw("SYS_OPEN(\"%s\", 0x%x, 0x%x) = %d\n", s1, *((int*)arg1), *((int*)arg2), ret);
            break;

        case SYS_WRITE:
            s1 = uc_mem_read_string(uc, *((uint32_t*)arg1), *((uint32_t*)arg2), false);
            ret = *((uint32_t*)arg2);
            consw("SYS_WRITE(%d, \"%s\", %u) = %u\n", *((uint8_t*)arg0), s1, *((uint32_t*)arg2), ret);
            break;

        case SYS_EXECVE:
            s1 = uc_mem_read_string(uc, *((uint32_t*)arg0), 255, true);
            s2 = const_char_array_string(uc, arg1);
            s3 = const_char_array_string(uc, arg2);
            consw("SYS_EXECVE(\"%s\", %s, %s)\n", s1, s2, s3);
            consw_info("SYS_EXECVE: Stopping emulation.\n");
            uc_emu_stop(uc);
            break;

        case SYS_IOCTL:
            consw("SYS_IOCTL(%u, %u, 0x%lx)\n", *((uint32_t*)arg0), *((uint32_t*)arg1), *((uint32_t*)arg2));
            break;

        case SYS_SIGNAL:
            consw("SYS_SIGNAL(%u, 0x%lx)\n", *((uint32_t*)arg0), *((uint32_t*)arg1));
            break;

        case SYS_CHMOD:
            s1 = uc_mem_read_string(uc, *((uint32_t*)arg0), 255, true);
            consw("SYS_CHMOD(\"%s\", 0%o)\n", s1, *((mode_t*)arg1));
            break;

        case SYS_SETREUID:
            consw("SYS_SETREUID(%d, %d)\n", *((uid_t*)arg0), *((uid_t*)arg1));
            break;

        case SYS_SETUID:
            consw("SYS_SETUID(%d)\n", *((int*)arg0));
            break;

        case SYS_SETGID:
            consw("SYS_SETGID(%d)\n", *((int*)arg0));
            break;

        case SYS_CLOSE:
            consw("SYS_CLOSE(%d)\n", *((int*)arg0));
            break;

        case SYS_ALARM:
            consw("SYS_ALARM(%d)\n", *((int*)arg0));
            break;

        case SYS_NICE:
            consw("SYS_NICE(%d)\n", *((int*)arg0));
            break;

        case SYS_KILL:
            consw("SYS_KILL(%d, %d)\n", *((int*)arg0), *((int*)arg1));
            break;

        case SYS_DUP:
            consw("SYS_DUP(%d)\n", *((int*)arg0));
            break;

        case SYS_UMASK:
            consw("SYS_UMASK(%d)\n", *((int*)arg0));
            break;

        case SYS_DUP2:
            consw("SYS_DUP2(%d, %d)\n", *((int*)arg0), *((int*)arg1));
            break;

        case SYS_SSETMASK:
            consw("SYS_SSETMASK(%d)\n", *((int*)arg0));
            break;

        case SYS_GETPRIORITY:
            consw("SYS_GETPRIORITY(%d, %d)\n", *((int*)arg0), *((int*)arg1));
            break;

        case SYS_SETPRIORITY:
            consw("SYS_SETPRIORITY(%d, %d, %d)\n", *((int*)arg0), *((int*)arg1), *((int*)arg2));
            break;

        case SYS_FSYNC:
            consw("SYS_FSYNC(%d)\n", *((int*)arg0));
            break;

        case SYS_FCHDIR:
            consw("SYS_FCHDIR(%d)\n", *((int*)arg0));
            break;

        case SYS_FLOCK:
            consw("SYS_FLOCK(%d, %d)\n", *((int*)arg0), *((int*)arg1));
            break;

        case SYS_FDATASYNC:
            consw("SYS_FDATASYNC(%d)\n", *((int*)arg0));
            break;

        case SYS_MLOCKALL:
            consw("SYS_MLOCKALL(%d)\n", *((int*)arg0));
            break;

        case SYS_SCHED_GET_PRIORITY_MAX:
            consw("SYS_SCHED_GET_PRIORITY_MAX(%d)\n", *((int*)arg0));
            break;

        case SYS_SCHED_GET_PRIORITY_MIN:
            consw("SYS_SCHED_GET_PRIORITY_MIN(%d)\n", *((int*)arg0));
            break;

    }

    xfree(s1);
    xfree(s2);
    xfree(s3);
    wrefresh(w);
    return(ret);
}
