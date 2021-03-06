#include "ucui.h"

struct disassembly * disass(uint8_t *code, unsigned int len, uint64_t baseaddr, cs_arch arch, cs_mode mode)
{
    csh handle = 0;
    struct disassembly *d = NULL;
    cs_err err;

    if ((err = cs_open(arch, mode, &handle)) != CS_ERR_OK) {
        consw_err("disassemble 0x%08llx: cs_open() error returned: %u\n", baseaddr, err);
        getch();
        endwin();
        exit(1);
    }

    d = malloc(sizeof(struct disassembly));
    d->count = cs_disasm(handle, code, len, baseaddr, 0, &d->insn);
    if (d->count == 0) {
        consw_err("Unable to disassemble code @ 0x%08llx\n", baseaddr);
    }

    cs_close(&handle);
    return(d);
}

void verify_visible_ip(uint64_t ip)
{
    size_t i;

    for(i=0; i < diss->count; i++) {
        if (diss->insn[i].address >= ip)
            break;
    }

    if (i > (spos + asswl.nlines-3)) {
        spos = MAX(i - (asswl.nlines-3), 0);
    } else if (i < spos) {
        spos = i;
    }
}

bool ip_aligned_to_disassembly(uint64_t ip)
{
    int i;

    for(i=0; i < diss->count; i++) {
        if (diss->insn[i].address == ip)
            return(true);
    }
    return(false);
}

void printwass(unsigned int startpos, unsigned int lines, uint64_t ip) 
{
    unsigned int i, j, endpos, wline;
    uint64_t *bp;

    if (diss->count == 0)
        return;

    startpos = MIN(diss->count, startpos);
    endpos = MIN(diss->count, startpos+lines) - 1;

    wclear(assw);

    // instruction pointer highlight
    init_pair(1, COLOR_BLACK, COLOR_WHITE);

    for (i=startpos, wline=1; i <= endpos; i++, wline++) {
        if (ip==diss->insn[i].address)
            wattron(assw, COLOR_PAIR(1));

        bp = breakpoints;
        if (bp != 0) {
            while(*bp != 0) {
                if (*(bp++) == diss->insn[i].address) {
                    mvwprintw(assw, wline, 2, "*");
                }
            }
        }

        mvwprintw(assw, wline, 2, "%-03d 0x%08lx ", i+1, diss->insn[i].address);
        for (j=0; j < 6; j++) {
            if (j < diss->insn[i].size) {
                wprintw(assw, "%02X", (uint8_t) diss->insn[i].bytes[j]);
            } else {
                wprintw(assw, "  ");
            }
        }
        wprintw(assw, "\t%-6s %s", diss->insn[i].mnemonic, diss->insn[i].op_str);
        if (ip==diss->insn[i].address)
            wattroff(assw, COLOR_PAIR(1));
    }

    box(assw, 0, 0);
    mvwprintw(assw, 0, 2, " Disassembly ");
    wrefresh(assw);
}

