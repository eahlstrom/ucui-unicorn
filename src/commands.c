#include "ucui.h"

static void chomp_strip(char *str)
{
    int i;

    for (i=strlen(str); i != 0; i--) {
        switch(str[i]) {
            case 0:
            case '\t':
            case '\n':
            case ' ':
                str[i] = 0;
                break;
            default:
                return;
        }
    }
}

void runcmd(char *command)
{
    char *arg0, *arg1, *arg2;
    int n;

    chomp_strip(command);

    n = sscanf(command, "%ms %ms %ms", &arg0, &arg1, &arg2);
    if (n == EOF)
        return;

    if (strcmp(arg0, "help") == 0) {
        consw("Valid commands:\n");
        consw(" mmap         - print memory map\n");
        // consw(" hx address   - hexdumps address\n");
        consw(" help         - this help\n");
        return;
    } else if (strcmp(arg0, "mmap") == 0) {
        print_memory_map(opts->mmap);
        return;

    } else if (strcmp(arg0, "hx") == 0) {
        if (n != 2) {
            consw("hx: need an address!\n");
            return;
        }
        uint64_t addr;
        addr = strtoul(arg1, NULL, 16);
        consw("hexdump! 0x%llx\n", addr);
        return;
    }
}
