#include "ucui.h"

void hexdump(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;

    for (i=0; i<len; i+=16) {
        consw("%08lx  ", (i+baseaddress));
        for (j=0; j<16; j++) {
            if ((i+j) >= len) {
                consw("   ");
            } else {
                consw("%02x ", code[i+j]);
            }
            if (j == 7)
                consw(" ");
        }
        for (j=0; j<16; j++) {
            if (j==0)
                consw(" |");
            if (code[i+j] >= 33 && code[i+j] <= 126) {
                consw("%c", code[i+j]);
            } else {
                consw(".");
            }
            if ((i+j) >= len)
                break;
        }
        consw("|\n");
    }
}
