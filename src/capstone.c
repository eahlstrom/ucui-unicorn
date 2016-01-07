#include "ucui.h"

struct disassembly * disass(uint8_t *code, unsigned int len, uint64_t baseaddr, cs_arch arch, cs_mode mode)
{
    csh handle = 0;
    struct disassembly *diss;

    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return NULL;

    diss = malloc(sizeof(struct disassembly));
    diss->count = cs_disasm(handle, code, len, baseaddr, 0, &diss->insn);

    cs_close(&handle);
    return diss;
}

void verify_visible_eip(uint32_t eip)
{
    int i;

    // wprintw(consw, "diss->count: %d\n", diss->count);
    for(i=0; i < diss->count; i++) {
        // wprintw(consw, "%d - addr: %08x ip: %08x\n", i, diss->insn[i].address, eip);
        if (diss->insn[i].address >= eip)
            break;
    }

    // wprintw(consw, "i: %d spos+asswl.nlines-3 = %d\n", i, (spos + asswl.nlines-3));
    // wrefresh(consw);
    if (i > (spos + asswl.nlines-3)) {
        spos = MAX(i - (asswl.nlines-3), 0);
    } else if (i < spos) {
        spos = i;
    }
}

void printwass(unsigned int startpos, unsigned int lines, uint64_t ip) 
{
    unsigned int i, j, endpos, wline;
    uint64_t *bp;

    startpos = MIN(diss->count, startpos);
    endpos = MIN(diss->count, startpos+lines) - 1;

    wclear(assw);
    box(assw, 0, 0);

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

        mvwprintw(assw, wline, 3, "%-03d 0x%08lx ", i+1, diss->insn[i].address);
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
    wrefresh(assw);
}

