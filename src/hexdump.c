#include "ucui.h"

void hexdump_uint8(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;

    for (i=0; i<len; i+=16) {
        conswnf("%08lx:  ", (i+baseaddress));
        for (j=0; j<16; j++) {
            if ((i+j) >= len) {
                conswnf("   ");
            } else {
                conswnf("%02x ", code[i+j]);
            }
            if (j == 7)
                conswnf(" ");
        }
        for (j=0; j<16; j++) {
            if (j==0)
                conswnf(" |");
            if (code[i+j] >= 33 && code[i+j] <= 126) {
                conswnf("%c", code[i+j]);
            } else {
                conswnf(".");
            }
            if ((i+j) >= len)
                break;
        }
        conswnf("|\n");
    }
    consw("\n");
}

void hexdump_uint16(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;
    uint16_t *p;

    for (i=0; i < (len-1); i+=16) {
        conswnf("%08lx:  ", (i+baseaddress));
        p = (void*) code + i;
        for(j=0; j < 8; j++) {
            if ((i+(j*2)) >= (len-1))
                break;
            conswnf("%04x ", *p++);
            if (j == 3)
                conswnf(" ");
        }
        conswnf("\n");
    }
    consw("\n");
}

void hexdump_uint32(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;
    uint32_t *p;

    for (i=0; i < (len-1); i+=16) {
        conswnf("%08lx:  ", (i+baseaddress));
        p = (void*) code + i;
        for(j=0; j < 4; j++) {
            if ((i+(j*4)) >= (len-1))
                break;
            conswnf("%08lx ", *p++);
            if (j == 1)
                conswnf(" ");
        }
        conswnf("\n");
    }
    consw("\n");
}

void hexdump_uint64(uint8_t *code, unsigned int len, uint64_t baseaddress)
{
    uint64_t i, j;
    uint64_t *p;

    for (i=0; i < (len-1); i+=16) {
        conswnf("%08lx:  ", (i+baseaddress));
        p = (void*) code + i;
        for(j=0; j < 2; j++) {
            if ((i+(j*8)) >= (len-1))
                break;
            conswnf("%016llx ", *p++);
            if (j == 0)
                conswnf(" ");
        }
        conswnf("\n");
    }
    consw("\n");
}
