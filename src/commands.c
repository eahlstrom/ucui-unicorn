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

static void cmd_usage(void)
{
    consw("Valid commands:\n");
    consw(" s            - step instruction\n");
    consw(" c            - continue to next bp or end\n");
    consw(" clear        - clear console window\n");
    consw(" M            - print memory map\n");
    consw(" D            - re-disassemble code\n");
    // consw(" hx address   - hexdumps address\n");
    consw(" help         - this help\n");
}

enum command_state runcmd(uc_engine *uc, uint64_t ip, char *command)
{
    char *arg0, *arg1, *arg2;
    int n;

    chomp_strip(command);
    // consw("cmd: <%s> <%x> len: %d\n", command, command, strlen(command));

    n = sscanf(command, "%ms %ms %ms", &arg0, &arg1, &arg2);
    if (n == EOF) {
        cmd_usage();
        return(MORE_COMMANDS);
    }

    if (strcmp(arg0, "help") == 0) {
        cmd_usage();

    } else if (strcmp(arg0, "clear") == 0) {
        wclear(consw);
        wrefresh(consw);

    } else if (n == 1 && strcmp(arg0, "s") == 0) {
        return(DONE_PROCESSING);

    } else if (n == 1 && strcmp(arg0, "c") == 0) {
        stepmode = RUN;
        return(DONE_PROCESSING);

    } else if (n == 1 && strcmp(arg0, "D") == 0) {
        struct memory_map *m;
        consw_info("Re-disassembling code... ");
        if ((m = mmap_for_address(ip)) != NULL) {
            consw("\n");
            redisassemble_code(uc, m->baseaddr, m->rf->len);
            verify_visible_ip(ip);
            printwass(spos, (asswl.nlines-2), ip);
        } else {
            consw("failed to find memory map for ip 0x%08x\n", ip);
        }

    } else if (strcmp(arg0, "M") == 0) {
        print_memory_map(opts->mmap);

    } else if (strcmp(arg0, "hx") == 0) {
        if (n != 2) {
            consw("hx: need an address!\n");
            return(MORE_COMMANDS);
        }
        uint64_t addr;
        addr = strtoul(arg1, NULL, 16);
        consw("hexdump! 0x%llx\n", addr);

    } else if (strcmp(arg0, "pd") == 0) { // TODO
        size_t assw_lines = asswl.nlines - 2;
        size_t smax = diss->count - assw_lines;

        if ((spos+assw_lines) < smax) {
            spos += assw_lines;
        } else {
            spos = smax;
        }
        printwass(spos, (asswl.nlines-2), ip);

    } else if (strcmp(arg0, "pu") == 0) { // TODO
        if (spos > 0 && (spos-((asswl.nlines-2)) >= 0)) {
            spos -= (asswl.nlines - 2);
            consw("set spos to: %d\n", spos);
            printwass(spos, (asswl.nlines-2), ip);
        }

    } else if (strcmp(arg0, "down") == 0) {
        if ((spos+(asswl.nlines-2)) < diss->count)
            spos++;
        printwass(spos, (asswl.nlines-2), ip);

    } else if (strcmp(arg0, "up") == 0) {
        if (spos > 0)
            spos--;
        printwass(spos, (asswl.nlines-2), ip);

    } else {
        consw("%s: invalid command!\n", command);
        cmd_usage();
    }

    return(MORE_COMMANDS);
}
