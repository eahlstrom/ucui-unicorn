#include "ucui.h"

struct x86_regs * read_x86_registers(uc_engine *uc)
{
    struct x86_regs *r;
    r = xmalloc(sizeof(struct x86_regs));
    uc_reg_read(uc, UC_X86_REG_EAX, &r->eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &r->ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &r->ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r->edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &r->esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &r->edi);
    uc_reg_read(uc, UC_X86_REG_EBP, &r->ebp);
    uc_reg_read(uc, UC_X86_REG_ESP, &r->esp);
    uc_reg_read(uc, UC_X86_REG_CS, &r->cs);
    uc_reg_read(uc, UC_X86_REG_DS, &r->ds);
    uc_reg_read(uc, UC_X86_REG_FS, &r->fs);
    uc_reg_read(uc, UC_X86_REG_EIP, &r->eip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &r->eflags);
    return(r);
}


void printregs_x86(uc_engine *uc)
{
    struct x86_regs *r;
    short hl, dl;

    r = read_x86_registers(uc);

    if (prev_regs_x86 == NULL) {
        prev_regs_x86 = r;
    }

    hl = 1;
    dl = 2;
    mvwprintw(regsw, hl, 2, "EAX        EBX        ECX        EDX         SS      CS");
    mvwprintw(regsw, dl, 2, "0x%08x 0x%08x 0x%08x 0x%08x  0x%04x  0x%04x", r->eax, r->ebx, r->ecx, r->edx, r->ss, r->cs);
    if (r->eax != prev_regs_x86->eax)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->ebx != prev_regs_x86->ebx)
        mvwchgat(regsw, dl, 13, 10, A_BOLD, 0, NULL);
    if (r->ecx != prev_regs_x86->ecx)
        mvwchgat(regsw, dl, 24, 10, A_BOLD, 0, NULL);
    if (r->edx != prev_regs_x86->edx)
        mvwchgat(regsw, dl, 35, 10, A_BOLD, 0, NULL);
    if (r->ss != prev_regs_x86->ss)
        mvwchgat(regsw, dl, 47, 6, A_BOLD, 0, NULL);
    if (r->cs != prev_regs_x86->cs)
        mvwchgat(regsw, dl, 55, 6, A_BOLD, 0, NULL);

    hl = 3;
    dl = 4;
    mvwprintw(regsw, hl, 2, "ESI        EDI        ESP        EBP         DS      ES");
    mvwprintw(regsw, dl, 2, "0x%08x 0x%08x 0x%08x 0x%08x  0x%04x  0x%04x", r->esi, r->edi, r->esp, r->ebp, r->ds, r->es);
    if (r->esi != prev_regs_x86->esi)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->edi != prev_regs_x86->edi)
        mvwchgat(regsw, dl, 13, 10, A_BOLD, 0, NULL);
    if (r->esp != prev_regs_x86->esp)
        mvwchgat(regsw, dl, 24, 10, A_BOLD, 0, NULL);
    if (r->ebp != prev_regs_x86->ebp)
        mvwchgat(regsw, dl, 35, 10, A_BOLD, 0, NULL);
    if (r->ds != prev_regs_x86->ds)
        mvwchgat(regsw, dl, 47, 6, A_BOLD, 0, NULL);
    if (r->es != prev_regs_x86->es)
        mvwchgat(regsw, dl, 55, 6, A_BOLD, 0, NULL);

    hl = 5;
    dl = 6;
    mvwprintw(regsw, hl, 2, "EFLAGS                           EIP         FS      GS");
    mvwprintw(regsw, dl, 2, "0x%08x                       0x%08x  0x%04x  0x%04x", r->eflags, r->eip, r->fs, r->gs);
    wmove(regsw, dl, 13);
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 0) ? "CF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 2) ? "PF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 4) ? "AF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 6) ? "ZF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 7) ? "SF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 8) ? "TF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 9) ? "IF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 10) ? "DF ":"");
    wprintw(regsw, "%s", CHECK_BIT(r->eflags, 11) ? "OF ":"");
    if (r->eflags != prev_regs_x86->eflags)
        mvwchgat(regsw, dl, 2, 10, A_BOLD, 0, NULL);
    if (r->fs != prev_regs_x86->fs)
        mvwchgat(regsw, dl, 47, 6, A_BOLD, 0, NULL);
    if (r->gs != prev_regs_x86->gs)
        mvwchgat(regsw, dl, 55, 6, A_BOLD, 0, NULL);

    wrefresh(regsw);

    if (r != prev_regs_x86) {
        xfree(prev_regs_x86);
        prev_regs_x86 = r;
    }
}

void printstack_x86(uc_engine *uc) {
    uint8_t tmp[16];
    uint32_t r_esp;
    uint32_t *t32 = (uint32_t*) tmp;
    int i, j;

    uc_reg_read(uc, UC_X86_REG_ESP, &r_esp);
    for (i=0; i<(stackwl.nlines-2); i++) {
        mvwprintw(stackw, i+1, 2, "%08x  ", r_esp+(i*4));
        if (uc_mem_read(uc, r_esp+(i*4), tmp, 8) == UC_ERR_OK) {
            wprintw(stackw, "%08x  ", *t32);
            for(j=3; j>=0; j--) {
                wprintw(stackw, "%c", (tmp[j] > 32 && tmp[j] < 126) ? tmp[j] : '.');
            }
        } else {
            wprintw(stackw, "?? err: %d    ", uc_errno(uc));    
        }
    }
    wrefresh(stackw);
}

// callback for tracing instruction
static void hook_code_x86(uc_engine *uc, uint64_t ip, uint32_t size, void *user_data)
{
    printregs_x86(uc);
    printstack_x86(uc);
    if (should_break(ip) == false)
        return;
    handle_keyboard(uc, ip);
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr_x86(uc_engine *uc, uint32_t intno, void *user_data)
{

    if (intno == 0x80 && opts->os == LINUX) {
        hook_intr_x86_linux(uc, intno, user_data);
    } else {
        uint32_t r_eip;
        uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
        consw_info("%08x INT 0x%02x - ", r_eip, intno);
        switch(intno) {
            case 0x0d:
                consw("General Protection Fault\n");
                break;
            default:
                consw("Unknown interupt\n");
        }
    }
}


int unicorn_x86(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    struct x86_regs *r;
    bool regs_from_file = false;

    if (opts->initial_regs) {
        regs_from_file = true;
        r = opts->initial_regs;
        if (r->eip == 0)
            r->eip = baseaddress;
        if (r->esp == 0)
            r->esp = baseaddress + 0x200000;
    } else {
        r = xmalloc(sizeof(struct x86_regs));
        memset(r, 0, sizeof(struct x86_regs));
        r->esp = baseaddress + 0x200000;
        r->eip = baseaddress;
    }

    consw_info("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        consw_err("uc_open() error %u: %s\n", err, uc_strerror(err));
        goto error;
    }

    // TODO: FS for windows
    /*
    if ((err = uc_mem_map(uc, 0x0, 1 * 1024 * 1024, UC_PROT_ALL)) != UC_ERR_OK) {
        consw_err("uc_mem_map() error %u: %s\n", err, uc_strerror(err));
        goto error;
    }
    if (uc_mem_write(uc, 0x0, code, len)) {
        consw_err("uc_mem_write() error %u: %s\n", err, uc_strerror(err));
        goto error;
    }
    */

    map_and_write_memory(uc, opts->mmap);

    // initialize machine registers
    if (r->eax != 0) { uc_reg_write(uc, UC_X86_REG_EAX, &r->eax); }
    if (r->ebx != 0) { uc_reg_write(uc, UC_X86_REG_EBX, &r->ebx); }
    if (r->ecx != 0) { uc_reg_write(uc, UC_X86_REG_ECX, &r->ecx); }
    if (r->edx != 0) { uc_reg_write(uc, UC_X86_REG_EDX, &r->edx); }
    if (r->esi != 0) { uc_reg_write(uc, UC_X86_REG_ESI, &r->esi); }
    if (r->edi != 0) { uc_reg_write(uc, UC_X86_REG_EDI, &r->edi); }
    if (r->ebp != 0) { uc_reg_write(uc, UC_X86_REG_EBP, &r->ebp); }
    if (r->esp != 0) { uc_reg_write(uc, UC_X86_REG_ESP, &r->esp); }
    if (r->eflags != 0) { uc_reg_write(uc, UC_X86_REG_EFLAGS, &r->eflags); }

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_x86, NULL, 1, 0);

    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, hook_intr_x86, NULL);

    uc_running = true;
    // emulate machine code in infinite time
    // uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
    err = uc_emu_start(uc, r->eip, baseaddress + len, 0, 0);
    if (err) {
        consw_err("uc_emu_start() error %u: %s\n", err, uc_strerror(err));
        goto finish;
    }


finish:
    if (!regs_from_file)
        xfree(r);
    uc_running = false;
    consw_info("Emulation done.\n");

    // Give the user a change to browse around in the asm window before restart
    r = read_x86_registers(uc);
    stepmode = STEP;
    printregs_x86(uc);
    printstack_x86(uc);
    handle_keyboard(uc, r->eip);

    uc_close(uc);
    xfree(prev_regs_x86);
    xfree(r);

    return(0);

error:
    getch();
    endwin();
    exit(1);
}
