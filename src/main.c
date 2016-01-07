#include "ucui.h"

void sigint(int signal)
{
    endwin();
    exit(0);
}

void ncurses_init(void)
{
    signal(SIGINT, sigint);

    initscr();
    if (LINES < 50 || COLS < 140) {
        endwin();
        fprintf(stderr, "To small window! lines: %d, cols: %d. Need 50/140\n", LINES, COLS);
        exit(1);
    }
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, true);
    curs_set(0);

    asswl.nlines = LINES / 3;
    asswl.ncols = COLS-65;
    asswl.begin_y = 1;
    asswl.begin_x = 0;

    regswl.nlines = asswl.nlines;
    regswl.ncols = COLS-asswl.ncols-1;
    regswl.begin_y = asswl.begin_y;
    regswl.begin_x = asswl.ncols + asswl.begin_x + 1;

    stackwl.nlines = LINES - regswl.nlines - 1;
    stackwl.ncols = regswl.ncols;
    stackwl.begin_y = asswl.begin_y + asswl.nlines ;
    stackwl.begin_x = regswl.begin_x;

    conswl.nlines = LINES - asswl.nlines - 1;
    conswl.ncols = COLS - stackwl.ncols;
    conswl.begin_y = asswl.nlines + 1;
    conswl.begin_x = 0;

    assw = newwin(asswl.nlines, asswl.ncols, asswl.begin_y, asswl.begin_x);
    box(assw, 0, 0);

    regsw = newwin(regswl.nlines, regswl.ncols, regswl.begin_y, regswl.begin_x);
    box(regsw, 0, 0);

    consw = newwin(conswl.nlines, conswl.ncols, conswl.begin_y, asswl.begin_x);
    // box(consw, 0, 0);
    scrollok(consw, true);
    wsetscrreg(consw, 0, conswl.nlines);

    stackw = newwin(stackwl.nlines, stackwl.ncols, stackwl.begin_y, stackwl.begin_x);
    box(stackw, 0, 0);

    mvwprintw(assw, 0, 2, " Disassembly ");
    mvwprintw(regsw, 0, 2, " Registers ");
    mvwprintw(stackw, 0, 2, " Stack ");

    refresh();
    wrefresh(assw);
    wrefresh(regsw);
    wrefresh(consw);
    wrefresh(stackw);
    spos = 0;
}

bool should_break(uint64_t ip)
{
    uint64_t *p;

    if (stepmode == STEP)
        return(true);

    p = breakpoints;
    if (p == NULL && stepmode == RUN) {
        return(false);
    }

    while(*p != 0) {
        if (*(p++) == ip) {
            stepmode = STEP;
            return(true);
        }
    }
    return(false);
}

void redissasemle_code(uc_engine *uc)
{
    uint8_t *new_code;

    new_code = xmalloc(rf->len);
    if (uc_mem_read(uc, baseaddr, new_code, rf->len) == UC_ERR_OK) {
        if (opts->arch == X86 && opts->mode == MODE_32) {
            diss = disass(new_code, rf->len, baseaddr, CS_ARCH_X86, CS_MODE_32);
        } else if (opts->arch == X86 && opts->mode == MODE_64) {
            diss = disass(new_code, rf->len, baseaddr, CS_ARCH_X86, CS_MODE_64);
        } else if (opts->arch == ARM && opts->mode == MODE_32) {
            diss = disass(rf->bytes, rf->len, baseaddr, CS_ARCH_ARM, CS_MODE_ARM);
        } else {
            consw_err("unknown arch and mode\n");
        }
    } else {
        consw_err("redisassm failed\n");
    }
    xfree(new_code);
}

void handle_keyboard(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int ch;

    while(true) {
        printwass(spos, (asswl.nlines-2), address);
        ch = getch();
        switch(ch) {
            case KEY_DOWN:
                if ((spos+(asswl.nlines-2)) < diss->count)
                    spos++;
                break;
            case KEY_UP:
                if (spos > 0)
                    spos--;
                break;
            case 'D':
                consw_info("Re-disassembling code...\n");
                redissasemle_code(uc);
                verify_visible_eip(address);
                break;
            case KEY_F(7):
            case KEY_F(8):
            case KEY_ENTER:
            case 10:
                stepmode = STEP;
                return;
            case KEY_F(9):
                stepmode = RUN;
                return;
            default:
                wprintw(stdscr, "              ");
        }
        mvwprintw(stdscr, 0, 15, "key: 0%o(%d)  spos: %d, %d   ", ch, ch, spos, (asswl.nlines-2)+spos);
        wrefresh(stdscr);
    }
}

void usage(void)
{
    printf("%s [OPTION]... file\n", BINNAME);
    printf("\n");
    printf(" -a ARCH (x86 or ARM. Default: x86)\n");
    printf(" -m MODE (32 or 64. Default: 32)\n");
    printf(" -B BASEADDR (Default: 0x400000)\n");
    printf(" -O OS (linux or FreeBSD). Default: linux)\n");
    printf(" -b breakpoint_address[,breakpoint_address,...]\n");
    printf(" -R (start in RUN mode)\n");
}

struct options *parseopts(int argc, char **argv)
{
    struct options *opts;
    int c;
    char *s;
    int i, cnt;

    opts = xmalloc(sizeof(struct options));

    // default values
    opts->arch = X86;
    opts->mode = MODE_32;
    opts->baseaddress = 0x400000;
    stepmode = STEP;
    opts->os = LINUX;

    while ((c = getopt(argc, argv, "a:m:B:b:O:R?")) != -1) {
        switch(c) {
            case 'a': // process arch
                if (strcmp(optarg, "x86") == 0) {
                    opts->arch = X86;
                } else if (strcmp(optarg, "ARM") == 0) {
                    opts->arch = ARM;
                } else {
                    usage();
                    exit(1);
                }
                break;

            case 'm': // cpu mode
                if (strcmp(optarg, "32") == 0) {
                    opts->mode = MODE_32;
                } else if (strcmp(optarg, "64") == 0) {
                    opts->mode = MODE_64;
                } else {
                    usage();
                    exit(1);
                }
                break;

            case 'B': // baseaddress
                opts->baseaddress = strtoul(optarg, NULL, 0);
                break;

            case 'b': // breakpoints
                cnt = 1;
                for (i = 0; i < strlen(optarg); i++) {
                    if (optarg[i] == ',')
                        cnt++;
                }
                breakpoints = calloc(sizeof(uint64_t), cnt+1);
                s = strtok(optarg, ",");
                breakpoints[0] = strtoul(s, NULL, 0);
                for (i=1; (s = strtok(NULL, ",")) != NULL; i++) {
                    breakpoints[i] = strtoul(s, NULL, 0);
                }
                break;

            case 'R':
                stepmode = RUN;
                break;

            case 'O':
                if (strcmp(optarg, "linux") == 0) {
                    opts->os = LINUX;
                } else {
                    printf("unsupported OS: %s\n", optarg);
                    exit(1);
                }
                break;

            case '?':
                usage();
                exit(1);
                break;

        default:
            usage();
            exit(1);
        }
    }
    opts->scfile = argv[optind];
    if (opts->scfile == NULL) {
        usage();
        exit(1);
    }

    return(opts);
}

int main(int argc, char **argv)
{
    opts = parseopts(argc, argv);

    rf = readfile(opts->scfile);
    ncurses_init();

    baseaddr = opts->baseaddress;
    // hexdump(rf->bytes, rf->len, baseaddr);

    while (true) {
        if (opts->arch == X86 && opts->mode == MODE_32) {
            diss = disass(rf->bytes, rf->len, baseaddr, CS_ARCH_X86, CS_MODE_32);
            unicorn_x86(rf->bytes, rf->len, baseaddr);
        } else if (opts->arch == X86 && opts->mode == MODE_64) {
            diss = disass(rf->bytes, rf->len, baseaddr, CS_ARCH_X86, CS_MODE_64);
            unicorn_x64(rf->bytes, rf->len, baseaddr);
        } else if (opts->arch == ARM && opts->mode == MODE_32) {
            diss = disass(rf->bytes, rf->len, baseaddr, CS_ARCH_ARM, CS_MODE_ARM);
            unicorn_arm(rf->bytes, rf->len, baseaddr);
        } else {
            endwin();
            printf("not supported yet!\n");
            exit(0);
        }
        wclear(consw);
        wrefresh(consw);
    }

    endwin();
    return(0);
}
