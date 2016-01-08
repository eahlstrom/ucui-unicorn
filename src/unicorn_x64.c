#include "ucui.h"

struct x64_regs * read_x64_registers(uc_engine *uc)
{
    struct x64_regs *r;
    r = xmalloc(sizeof(struct x64_regs));
    uc_reg_read(uc, UC_X86_REG_RAX, &r->rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &r->rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &r->rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &r->rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &r->rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &r->rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &r->rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &r->rsp);
    uc_reg_read(uc, UC_X86_REG_RIP, &r->rip);
    uc_reg_read(uc, UC_X86_REG_R8, &r->r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r->r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r->r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r->r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r->r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r->r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r->r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r->r15);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &r->eflags);
    return(r);
}


void printregs_x64(uc_engine *uc)
{
    struct x64_regs *r;
    short hl, dl;

    r = read_x64_registers(uc);

    if (prev_regs_x64 == NULL) {
        prev_regs_x64 = r;
    }

    hl = 1;
    dl = 2;
    mvwprintw(regsw, hl, 2, "RAX                 RBX                 RCX");
    mvwprintw(regsw, dl, 2, "0x%016llx  0x%016llx  0x%016llx", r->rax, r->rbx, r->rcx);
    if (r->rax != prev_regs_x64->rax)
        mvwchgat(regsw, dl, 2, 18, A_BOLD, 0, NULL);
    if (r->rbx != prev_regs_x64->rbx)
        mvwchgat(regsw, dl, 22, 18, A_BOLD, 0, NULL);
    if (r->rcx != prev_regs_x64->rcx)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);

    hl += 2;
    dl += 2;
    mvwprintw(regsw, hl, 2, "RDX                 RSI                 RDI");
    mvwprintw(regsw, dl, 2, "0x%016llx  0x%016llx  0x%016llx", r->rdx, r->rsi, r->rdi);
    if (r->rdx != prev_regs_x64->rdx)
        mvwchgat(regsw, dl, 2, 18, A_BOLD, 0, NULL);
    if (r->rsi != prev_regs_x64->rsi)
        mvwchgat(regsw, dl, 22, 18, A_BOLD, 0, NULL);
    if (r->rdi != prev_regs_x64->rdi)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);

    hl += 2;
    dl += 2;
    mvwprintw(regsw, hl, 2, "R8                  R9                  R10");
    mvwprintw(regsw, dl, 2, "0x%016llx  0x%016llx  0x%016llx", r->r8, r->r9, r->r10);
    if (r->r8 != prev_regs_x64->r8)
        mvwchgat(regsw, dl, 2, 18, A_BOLD, 0, NULL);
    if (r->r9 != prev_regs_x64->r9)
        mvwchgat(regsw, dl, 22, 18, A_BOLD, 0, NULL);
    if (r->r10 != prev_regs_x64->r10)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);

    hl += 2;
    dl += 2;
    mvwprintw(regsw, hl, 2, "R11                 R12                 R13");
    mvwprintw(regsw, dl, 2, "0x%016llx  0x%016llx  0x%016llx", r->r11, r->r12, r->r13);
    if (r->r11 != prev_regs_x64->r11)
        mvwchgat(regsw, dl, 2, 18, A_BOLD, 0, NULL);
    if (r->r12 != prev_regs_x64->r12)
        mvwchgat(regsw, dl, 22, 18, A_BOLD, 0, NULL);
    if (r->r13 != prev_regs_x64->r13)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);

    hl += 2;
    dl += 2;
    mvwprintw(regsw, hl, 2, "R14                 R15                 RBP");
    mvwprintw(regsw, dl, 2, "0x%016llx  0x%016llx  0x%016llx", r->r14, r->r15, r->rbp);
    if (r->r14 != prev_regs_x64->r14)
        mvwchgat(regsw, dl, 2, 18, A_BOLD, 0, NULL);
    if (r->r15 != prev_regs_x64->r15)
        mvwchgat(regsw, dl, 22, 18, A_BOLD, 0, NULL);
    if (r->rbp != prev_regs_x64->rbp)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);

    hl += 2;
    dl += 2;
    mvwprintw(regsw, hl, 2, "EFLAGS              RIP                 RSP");
    mvwprintw(regsw, dl, 2, "0x%08lx          0x%016llx  0x%016llx", r->eflags, r->rip, r->rsp);
    if (r->eflags != prev_regs_x64->eflags)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->rsp != prev_regs_x64->rsp)
        mvwchgat(regsw, dl, 42, 18, A_BOLD, 0, NULL);
    dl++;
    wmove(regsw, dl, 2);
    wclrtoeol(regsw);
    box(regsw, 0, 0);
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 0) ? "CF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 2) ? "PF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 4) ? "AF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 6) ? "ZF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 7) ? "SF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 8) ? "TF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 9) ? "IF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 10) ? "DF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 11) ? "OF ":"");

    wrefresh(regsw);

    if (r != prev_regs_x64) {
        xfree(prev_regs_x64);
        prev_regs_x64 = r;
    }
}

void printstack_x64(uc_engine *uc) {
    uint8_t tmp[16];
    uint64_t r_rsp;
    uint64_t *t64 = (uint64_t*) tmp;
    int i, j;

    uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    for (i=0; i<(stackwl.nlines-2); i++) {
        mvwprintw(stackw, i+1, 2, "%016llx  ", r_rsp+(i*8));
        if (uc_mem_read(uc, r_rsp+(i*8), tmp, 8) == UC_ERR_OK) {
            wprintw(stackw, "%016llx  ", *t64);
            for(j=7; j>=0; j--) {
                wprintw(stackw, "%c", (tmp[j] > 32 && tmp[j] < 126) ? tmp[j] : '.');
            }
        } else {
            wprintw(stackw, "?? err: %d    ", uc_errno(uc));    
        }
    }
    wrefresh(stackw);
}

// callback for tracing instruction
static void hook_code_x64(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    uint64_t r_rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
    printregs_x64(uc);
    printstack_x64(uc);

    if (should_break(r_rip) == false)
        return;
    handle_keyboard(uc, address, size, user_data);
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr_x64(uc_engine *uc, uint32_t intno, void *user_data)
{
    uint64_t r_rip;

    if (opts->os == LINUX) {
        hook_intr_x64_linux(uc, intno, user_data);
    } else {
        uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
        consw_info("%08x syscall: no os handler defined for syscall descrambling\n", r_rip);
    }
}


int unicorn_x64(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    struct x64_regs *r;

    int r_rsp = baseaddress + 0x200000;  // ESP register

    wprintw(consw, "Emulate x86 64bits code\n"); wrefresh(consw);

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        wprintw(consw, "Failed on uc_open() with error returned: %u\n", err); wrefresh(consw);
        return(1);
    }

    // map 4MB memory for this emulation
    uc_mem_map(uc, baseaddress, 4 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, baseaddress, code, len)) {
        wprintw(consw, "Failed to write emulation code to memory, quit!\n"); wrefresh(consw);
        return(1);
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_x64, NULL, 1, 0);

    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INSN, hook_intr_x64, NULL, UC_X86_INS_SYSENTER);

    wprintw(consw, "\n>>> Start tracing this Linux code\n"); wrefresh(consw);
    // emulate machine code in infinite time
    // err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF), 0, 12); <--- emulate only 12 instructions
    err = uc_emu_start(uc, baseaddress, baseaddress + len, 0, 0);
    if (err) {
        wprintw(consw, "Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err)); 
        wrefresh(consw);
    }

    wprintw(consw, "\n>>> Emulation done.\n"); wrefresh(consw);

    // Give the user a change to browse around in the asm window before restart
    r = read_x64_registers(uc);
    stepmode = STEP;
    hook_code_x64(uc, r->rip, len, code);

    uc_close(uc);
    xfree(prev_regs_x64);

    return(0);
}
