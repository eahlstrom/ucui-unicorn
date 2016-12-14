#include "ucui.h"

struct arm_regs * read_arm_registers(uc_engine *uc)
{
    struct arm_regs *r;
    r = xmalloc(sizeof(struct arm_regs));
    uc_reg_read(uc, UC_ARM_REG_R0, &r->r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r->r1);
    uc_reg_read(uc, UC_ARM_REG_R2, &r->r2);
    uc_reg_read(uc, UC_ARM_REG_R3, &r->r3);
    uc_reg_read(uc, UC_ARM_REG_R4, &r->r4);
    uc_reg_read(uc, UC_ARM_REG_R5, &r->r5);
    uc_reg_read(uc, UC_ARM_REG_R6, &r->r6);
    uc_reg_read(uc, UC_ARM_REG_R7, &r->r7);
    uc_reg_read(uc, UC_ARM_REG_R8, &r->r8);
    uc_reg_read(uc, UC_ARM_REG_SB, &r->sb);
    uc_reg_read(uc, UC_ARM_REG_SL, &r->sl);
    uc_reg_read(uc, UC_ARM_REG_FP, &r->fp);
    uc_reg_read(uc, UC_ARM_REG_IP, &r->ip);
    uc_reg_read(uc, UC_ARM_REG_SP, &r->sp);
    uc_reg_read(uc, UC_ARM_REG_LR, &r->lr);
    uc_reg_read(uc, UC_ARM_REG_PC, &r->pc);
    uc_reg_read(uc, UC_ARM_REG_CPSR, &r->cpsr);
    return(r);
}


void printregs_arm(uc_engine *uc)
{
    struct arm_regs *r;
    short hl, dl;
    r = read_arm_registers(uc);

    if (prev_regs_arm == NULL) {
        prev_regs_arm = r;
    }

    hl = 1;
    dl = 2;
    mvwprintw(regsw, hl, 2, "R0          R1          R2          R3          R4");
    mvwprintw(regsw, dl, 2, "0x%08x  0x%08x  0x%08x  0x%08x  0x%08x", r->r0, r->r1, r->r2, r->r3, r->r4);
    if (r->r0 != prev_regs_arm->r0)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->r1 != prev_regs_arm->r1)
        mvwchgat(regsw, dl, 14, 10, A_BOLD, 0, NULL);
    if (r->r2 != prev_regs_arm->r2)
        mvwchgat(regsw, dl, 26, 10, A_BOLD, 0, NULL);
    if (r->r3 != prev_regs_arm->r3)
        mvwchgat(regsw, dl, 38, 10, A_BOLD, 0, NULL);
    if (r->r4 != prev_regs_arm->r4)
        mvwchgat(regsw, dl, 50, 10, A_BOLD, 0, NULL);

    hl = 3;
    dl = 4;
    mvwprintw(regsw, hl, 2, "R5          R6          R7          R8          SB(R9)");
    mvwprintw(regsw, dl, 2, "0x%08x  0x%08x  0x%08x  0x%08x  0x%08x", r->r5, r->r6, r->r7, r->r8, r->sb);
    if (r->r5 != prev_regs_arm->r5)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->r6 != prev_regs_arm->r6)
        mvwchgat(regsw, dl, 14, 10, A_BOLD, 0, NULL);
    if (r->r7 != prev_regs_arm->r7)
        mvwchgat(regsw, dl, 26, 10, A_BOLD, 0, NULL);
    if (r->r8 != prev_regs_arm->r8)
        mvwchgat(regsw, dl, 38, 10, A_BOLD, 0, NULL);
    if (r->sb != prev_regs_arm->sb)
        mvwchgat(regsw, dl, 50, 10, A_BOLD, 0, NULL);

    hl = 5;
    dl = 6;
    mvwprintw(regsw, hl, 2, "SL(R10)     FP(R11)     IP(R12)     SP(R13)     LR(R14)");
    mvwprintw(regsw, dl, 2, "0x%08x  0x%08x  0x%08x  0x%08x  0x%08x", r->sl, r->fp, r->ip, r->sp, r->lr);
    if (r->sl != prev_regs_arm->sl)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->fp != prev_regs_arm->fp)
        mvwchgat(regsw, dl, 14, 10, A_BOLD, 0, NULL);
    if (r->ip != prev_regs_arm->ip)
        mvwchgat(regsw, dl, 26, 10, A_BOLD, 0, NULL);
    if (r->sp != prev_regs_arm->sp)
        mvwchgat(regsw, dl, 38, 10, A_BOLD, 0, NULL);
    if (r->lr != prev_regs_arm->lr)
        mvwchgat(regsw, dl, 50, 10, A_BOLD, 0, NULL);

    hl = 7;
    dl = 8;
    mvwprintw(regsw, hl, 2, "PC(R15)     CPSR(FLAGS)");
    mvwprintw(regsw, dl, 2, "0x%08x  0x%08x                                       ", r->pc, r->cpsr);
    mvwprintw(regsw, dl, 25, "%s", (CHECK_BIT(r->cpsr, 5) ? "T ":""));
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 24) ? "J ":""));   // Java state bit
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 27) ? "Q ":""));   // Sticky overflow bit
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 28) ? "V ":""));   // overflow bit
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 29) ? "C ":""));   // carry/borrow/extend bit
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 30) ? "Z ":""));   // Zero bit
    wprintw(regsw, "%s", (CHECK_BIT(r->cpsr, 31) ? "N ":""));   // negative/less than bit
    if (r->cpsr != prev_regs_arm->cpsr)
        mvwchgat(regsw, dl, 14, 10, A_BOLD, 0, NULL);

    wrefresh(regsw);

    if (r != prev_regs_arm) {
        xfree(prev_regs_arm);
        prev_regs_arm = r;
    }
}

void printstack_arm(uc_engine *uc) {
    uint8_t tmp[16];
    uint32_t r_sp;
    uint32_t *t = (uint32_t*) tmp;
    int i, j;
    uc_err ret;

    uc_reg_read(uc, UC_ARM_REG_SP, &r_sp);
    for (i=0; i<(stackwl.nlines-2); i++) {
        mvwprintw(stackw, i+1, 2, "%08lx  ", r_sp+(i*4));
        // if (uc_mem_read(uc, r_sp+(i*4), tmp, 4) == UC_ERR_OK) {
        ret = uc_mem_read(uc, r_sp+(i*4), tmp, 4);
        if (ret == UC_ERR_OK) {
            wprintw(stackw, "%08lx  ", *t);
            for(j=3; j>=0; j--) {
                wprintw(stackw, "%c", (tmp[j] > 32 && tmp[j] < 126) ? tmp[j] : '.');
            }
        } else {
            wprintw(stackw, "?? %s", uc_strerror(ret));
        }
    }
    wrefresh(stackw);
}

// callback for tracing instruction
static void hook_code_arm(uc_engine *uc, uint64_t ip, uint64_t size, void *user_data)
{
    printregs_arm(uc);
    printstack_arm(uc);
    if (should_break(ip) == false)
        return;
    handle_keyboard(uc, ip);
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr_arm(uc_engine *uc, uint32_t intno, void *user_data)
{
    if (opts->os == LINUX) {
        hook_intr_arm_linux(uc, intno, user_data);
    } else {
        uint32_t r_pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &r_pc);
        consw_info("%08x syscall: %d no os handler defined for syscall descrambling\n", r_pc, intno);
    }
}


int unicorn_arm(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    struct arm_regs *r;
    bool regs_from_file = false;

    if (opts->initial_regs) {
        regs_from_file = true;
        r = opts->initial_regs;
        if (r->pc == 0)
            r->pc = baseaddress;
        if (r->sp == 0)
            r->sp = baseaddress + 0x200000;
    } else {
        r = xmalloc(sizeof(struct arm_regs));
        memset(r, 0, sizeof(struct arm_regs));
        r->sp = baseaddress + 0x200000;
        r->pc = baseaddress;
    }

    consw_info("Emulate ARM 32bits code\n");

    // Initialize emulator
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        consw_err("uc_open() error %u: %s\n", err, uc_strerror(err));
        goto error;
    }

    map_and_write_memory(uc, opts->mmap);

    // initialize machine registers
    if (r->r0 != 0) { uc_reg_write(uc, UC_ARM_REG_R0, &r->r0); }
    if (r->r1 != 0) { uc_reg_write(uc, UC_ARM_REG_R1, &r->r1); }
    if (r->r2 != 0) { uc_reg_write(uc, UC_ARM_REG_R2, &r->r2); }
    if (r->r3 != 0) { uc_reg_write(uc, UC_ARM_REG_R3, &r->r3); }
    if (r->r4 != 0) { uc_reg_write(uc, UC_ARM_REG_R4, &r->r4); }
    if (r->r5 != 0) { uc_reg_write(uc, UC_ARM_REG_R5, &r->r5); }
    if (r->r6 != 0) { uc_reg_write(uc, UC_ARM_REG_R6, &r->r6); }
    if (r->r7 != 0) { uc_reg_write(uc, UC_ARM_REG_R7, &r->r7); }
    if (r->r8 != 0) { uc_reg_write(uc, UC_ARM_REG_R8, &r->r8); }
    if (r->sb != 0) { uc_reg_write(uc, UC_ARM_REG_SB, &r->sb); }
    if (r->sl != 0) { uc_reg_write(uc, UC_ARM_REG_SL, &r->sl); }
    if (r->fp != 0) { uc_reg_write(uc, UC_ARM_REG_FP, &r->fp); }
    if (r->ip != 0) { uc_reg_write(uc, UC_ARM_REG_IP, &r->ip); }
    if (r->sp != 0) { uc_reg_write(uc, UC_ARM_REG_SP, &r->sp); }
    if (r->lr != 0) { uc_reg_write(uc, UC_ARM_REG_LR, &r->lr); }
    if (r->pc != 0) { uc_reg_write(uc, UC_ARM_REG_PC, &r->pc); }


    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_arm, NULL, 1, 0);

    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, hook_intr_arm, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, r->pc, baseaddress + len, 0, 0);
    if (err) {
        consw_err("");
        if (prev_regs_x86 != NULL && prev_regs_arm->pc != 0) {
            consw("0x%08x: ", prev_regs_arm->pc);
        }
        consw("uc_emu_start() error %u: %s\n", err, uc_strerror(err));
        goto finish;
    }

finish:
    if (!regs_from_file)
        xfree(r);
    uc_running = false;
    consw_info("Emulation done.\n");

    // Give the user a change to browse around in the asm window before restart
    r = read_arm_registers(uc);
    stepmode = STEP;
    printregs_arm(uc);
    printstack_arm(uc);
    handle_keyboard(uc, r->pc);

    uc_close(uc);
    xfree(prev_regs_arm);
    xfree(r);

    return(0);

error:
    getch();
    endwin();
    exit(1);
}
