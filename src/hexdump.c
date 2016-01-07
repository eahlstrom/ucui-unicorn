#include "ucui.h"

void hexdump(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;

    for (i=0; i<len; i+=16) {
        printf("%08lx  ", (i+baseaddress));
        for (j=0; j<16; j++) {
            if ((i+j) >= len) {
                printf("   ");
            } else {
                printf("%02x ", code[i+j]);
            }
            if (j == 7)
                printf(" ");
        }
        for (j=0; j<16; j++) {
            if (j==0)
                printf(" |");
            if (code[i+j] >= 33 && code[i+j] <= 126) {
                printf("%c", code[i+j]);
            } else {
                printf(".");
            }
            if ((i+j) >= len)
                break;
        }
        printf("|\n");
    }
}
