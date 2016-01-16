#include "ucui.h"

void sigint(int signal)
{
    endwin();
    /*
    fprintf(stderr, "lines: %d, cols: %d.\n", LINES, COLS);
    fprintf(stderr, "asswl.nlines:   %d\n", asswl.nlines);
    fprintf(stderr, "folwl.nlines:   %d\n", folwl.nlines);
    fprintf(stderr, "conswl.nlines:  %d\n", conswl.nlines);
    fprintf(stderr, "cmdwl.nlines:   %d\n", cmdwl.nlines);
    fprintf(stderr, "sum:            %d\n", asswl.nlines + folwl.nlines + conswl.nlines + cmdwl.nlines);
    */
    exit(0);
}

void ncurses_init(void)
{
    signal(SIGINT, sigint);

    initscr();
    if (LINES < 25 || COLS < 115) {
        endwin();
        fprintf(stderr, "To small window! lines: %d, cols: %d. Need 50/140\n", LINES, COLS);
        exit(1);
    }
    ucui_readline_init();

    start_color();
    cbreak();
    noecho();
    // nonl();
    intrflush(NULL, false);
    // keypad(stdscr, true);
    curs_set(1);

    asswl.nlines = MAX(14, LINES/4);
    asswl.ncols = COLS-65;
    asswl.begin_y = 1;
    asswl.begin_x = 0;

    regswl.nlines = asswl.nlines;
    regswl.ncols = COLS-asswl.ncols-1;
    regswl.begin_y = asswl.begin_y;
    regswl.begin_x = asswl.ncols + asswl.begin_x + 1;

    folwl.nlines = MAX(5, LINES/4);
    folwl.ncols = asswl.ncols;
    folwl.begin_y = asswl.begin_y + asswl.nlines;
    folwl.begin_x = 0;

    // stackwl.nlines = LINES - regswl.nlines - 1;
    stackwl.nlines = folwl.nlines;
    stackwl.ncols = regswl.ncols;
    stackwl.begin_y = asswl.begin_y + asswl.nlines ;
    stackwl.begin_x = regswl.begin_x;

    // conswl.nlines = LINES - asswl.nlines - 3;
    conswl.nlines = (LINES - asswl.nlines - folwl.nlines - 2);
    conswl.ncols = COLS - 2;
    conswl.begin_y = folwl.begin_y + folwl.nlines;
    conswl.begin_x = 1;

    cmdwl.nlines = 1;
    cmdwl.ncols = conswl.ncols - 1;
    cmdwl.begin_y = conswl.begin_y + conswl.nlines;
    cmdwl.begin_x = 0;


    assw = newwin(asswl.nlines, asswl.ncols, asswl.begin_y, asswl.begin_x);
    box(assw, 0, 0);

    regsw = newwin(regswl.nlines, regswl.ncols, regswl.begin_y, regswl.begin_x);
    box(regsw, 0, 0);

    consw = newwin(conswl.nlines, conswl.ncols, conswl.begin_y, conswl.begin_x);
    // box(consw, 0, 0);
    scrollok(consw, true);
    wsetscrreg(consw, 0, conswl.nlines);

    stackw = newwin(stackwl.nlines, stackwl.ncols, stackwl.begin_y, stackwl.begin_x);
    box(stackw, 0, 0);

    folw = newwin(folwl.nlines, folwl.ncols, folwl.begin_y, folwl.begin_x);
    box(folw, 0, 0);

    cmdw = newwin(cmdwl.nlines, cmdwl.ncols, cmdwl.begin_y, cmdwl.begin_x);
    // box(cmdw, 0, 0);

    mvwprintw(assw, 0, 2, " Disassembly ");
    mvwprintw(regsw, 0, 2, " Registers ");
    mvwprintw(stackw, 0, 2, " Stack ");

    refresh();
    wrefresh(assw);
    wrefresh(regsw);
    wrefresh(consw);
    wrefresh(stackw);
    wrefresh(cmdw);
    wrefresh(folw);
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

void redisassemble_code(uc_engine *uc, uint64_t ip, size_t len)
{
    uint8_t *new_code;
    uc_err err;

    new_code = xmalloc(len);
    err = uc_mem_read(uc, ip, new_code, len);
    if (err == UC_ERR_OK) {
        xfree(diss);
        if (opts->arch == X86 && opts->mode == MODE_32) {
            diss = disass(new_code, len, ip, CS_ARCH_X86, CS_MODE_32);
        } else if (opts->arch == X86 && opts->mode == MODE_64) {
            diss = disass(new_code, len, ip, CS_ARCH_X86, CS_MODE_64);
        } else if (opts->arch == ARM && opts->mode == MODE_32) {
            diss = disass(new_code, len, ip, CS_ARCH_ARM, CS_MODE_ARM);
        }
    } else {
        consw_err("uc_mem_read %u bytes @ 0x%08llx. error %u: %s\n", len, ip, err, uc_strerror(err));
    }
    xfree(new_code);
}

void update_follow_window(uc_engine *uc, uint64_t addr)
{
    int lines = folwl.nlines - 2;
    size_t len = lines * 16;
    struct memory_map *m;
    uint8_t *bytes;
    int i, j, curr_line, y, x;
    uc_err err;

    wclear(folw);

    m = mmap_for_address(addr);
    if ( (addr + len) > (m->baseaddr + m->len) ) {
        len = MIN(1024, (m->baseaddr + m->len) - addr);
    }

    bytes = xmalloc(len);
    if ((err = uc_mem_read(uc, addr, bytes, len)) != UC_ERR_OK) {
        mvwprintw(folw, 1, 1, "%s\n", uc_strerror(err));
        goto ret;
    }

    for (i=0, curr_line=1; i<len; i+=16, curr_line++) {
        mvwprintw(folw, curr_line, 2, "%08lx:  ", (i+addr));
        for (j=0; j<16; j++) {
            if ((i+j) >= len) {
                wprintw(folw, "   ");
            } else {
                wprintw(folw, "%02x ", bytes[i+j]);
                if (last_follow_bytes != NULL && last_follow_bytes[i+j] != bytes[i+j]) {
                    getyx(folw, y, x);
                    mvwchgat(folw, y, x-3, 2, A_BOLD, 0, NULL);
                    wmove(folw, y, x);
                }
            }
            if (j == 7)
                wprintw(folw, " ");
        }
        for (j=0; j<16; j++) {
            if (j==0)
                wprintw(folw, " |");
            if (bytes[i+j] >= 33 && bytes[i+j] <= 126) {
                wprintw(folw, "%c", bytes[i+j]);
            } else {
                wprintw(folw, ".");
            }
            if (last_follow_bytes != NULL && last_follow_bytes[i+j] != bytes[i+j]) {
                getyx(folw, y, x);
                mvwchgat(folw, y, x-1, 1, A_BOLD, 0, NULL);
                wmove(folw, y, x);
            }
            if ((i+j) >= len)
                break;
        }
        wprintw(folw, "|\n");
    }
    wprintw(folw, "\n");

ret:
    if (last_follow_bytes != NULL)
        xfree(last_follow_bytes);
    last_follow_bytes = bytes;
    box(folw, 0, 0);
    mvwprintw(folw, 0, 2, " Follow ");
    wrefresh(folw);
}

void handle_keyboard(uc_engine *uc, uint64_t ip)
{
    struct memory_map *m;
    int ch;
    command_state cmd_state;

    verify_visible_ip(ip);
    if (!ip_aligned_to_disassembly(ip) && uc_running) {
        consw_info("IP not aligned to disassembly @ %08x.", ip);
        if ((m = mmap_for_address(ip)) != NULL) {
            consw(" Re-disassembling at this address...\n");
            redisassemble_code(uc, ip, m->rf->len);
            spos = 0;
        } else {
            consw(" Address is out-of-bounds.\n");
            uc_emu_stop(uc);
            return;
        }
    }
    printwass(spos, (asswl.nlines-2), ip);
    if (opts->follow != -1) {
        update_follow_window(uc, opts->follow);
    } else if ((m = mmap_for_address(ip)) != NULL) {
        update_follow_window(uc, m->baseaddr);
    }

    mvwprintw(cmdw, 0, 0, RL_PROMPT, 0); wrefresh(cmdw);

    curs_set(2);
    while(true) {
        ch = getch();
        // mvwprintw(stdscr, 0, 15, "key: 0%o(%d) <%c>  spos: %d, %d diss->count: %d  ", ch, ch, ch, spos, spos+(asswl.nlines-3), diss->count);
        // wrefresh(stdscr);
        switch(ch) {
            case '\f':
                wclear(consw);
                wrefresh(consw);
                break;

            default:
                // consw("-> 0x%x\n", ch);
                forward_to_readline(ch);
                if (*readline_command != 0) {
                    cmd_state = runcmd(uc, ip, readline_command);
                    *readline_command = 0;
                    wmove(cmdw, 0, strlen(RL_PROMPT)); wrefresh(cmdw);
                    switch(cmd_state) {
                        case DONE_PROCESSING:
                            curs_set(0);
                            return;
                        case MORE_COMMANDS:
                            break;
                    }
                }
        }
        wrefresh(cmdw);
    }
}

void usage(void)
{
    printf("%s [OPTION]... [file]\n", BINNAME);
    printf("\n");
    printf("Options:\n");
    printf(" -a ARCH                  CPU Arch. (x86 or ARM. Default: x86)\n");
    printf(" -m MODE                  CPU mode. (32 or 64. Default: 32)\n");
    printf(" -B BASEADDR              Set baseaddress. (Default: 0x400000)\n");
    // printf(" -O OS                    (linux). Default: linux).\n");
    printf(" -r FILE                  Set initial values of registers.\n");
    printf(" -M FILE                  Load a memory map. (-r required).\n");
    printf("                          Overrides file and BASEADDRESS.\n");
    printf(" -f FOLLOWADDR            Set address in follow window. (Default: code)\n");
    printf(" -b bp_addr[,bp_addr,..]  Set breakpoint(s).\n");
    printf(" -R                       Start in RUN(c) mode\n");
    printf("\nExamples:\n");
    printf("  $ %s ./sample_x86.shellcode\n", BINNAME);
    printf("  $ %s -a ARM ./sample_arm.shellcode\n", BINNAME);
    printf("  $ %s -M ./memory_map -r ./registers\n", BINNAME);
}

struct options *parseopts(int argc, char **argv)
{
    int c;
    char *s;
    int i, cnt;
    char *initial_reg_file = NULL;
    char *memory_map_file = NULL;

    opts = xmalloc(sizeof(struct options));

    // default values
    opts->arch = X86;
    opts->mode = MODE_32;
    opts->baseaddress = 0x400000;
    opts->initial_regs = NULL;
    opts->mmap = NULL;
    stepmode = STEP;
    opts->os = LINUX;
    opts->follow = -1;

    // init
    last_follow_bytes = NULL;

    while ((c = getopt(argc, argv, "a:m:B:b:O:r:M:f:R?")) != -1) {
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

            case 'f':   // follow address
                opts->follow = strtoul(optarg, NULL, 0);                
                break;

            case 'r':   // init registers
                initial_reg_file = optarg;
                break;

            case 'M':   // load memory segments
                memory_map_file = optarg;
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
    
    if (initial_reg_file)
        opts->initial_regs = init_registers_from_file(initial_reg_file);

    if (memory_map_file) {
        if (!initial_reg_file) {
            printf("ERROR: need registers file!\n");
            usage();
            exit(1);
        }
        opts->mmap = init_memory_map(memory_map_file);
        opts->scfile = NULL;
    } else if (opts->scfile == NULL) {
        usage();
        exit(1);
    }

    return(opts);
}

int main(int argc, char **argv)
{
    struct memory_map *m = NULL;

    diss = NULL;
    parseopts(argc, argv);

    if (opts->mmap != NULL) {
        m = opts->mmap;
    } else {
        opts->mmap = xmalloc(sizeof(struct memory_map));
        opts->mmap->rf = readfile(opts->scfile);
        opts->mmap->len = MAX(opts->mmap->rf->len, 3 * 1024 * 1024);
        opts->mmap->baseaddr = opts->baseaddress; // TODO remove opts->baseaddress
        opts->mmap->prot = UC_PROT_ALL;
        m = opts->mmap;
    }

    ncurses_init();

    while (true) {
        xfree(diss);
        if (opts->arch == X86 && opts->mode == MODE_32) {
            diss = disass(m->rf->bytes, m->rf->len, m->baseaddr, CS_ARCH_X86, CS_MODE_32);
            unicorn_x86(m->rf->bytes, m->rf->len, m->baseaddr);
        } else if (opts->arch == X86 && opts->mode == MODE_64) {
            diss = disass(m->rf->bytes, m->rf->len, m->baseaddr, CS_ARCH_X86, CS_MODE_64);
            unicorn_x64(m->rf->bytes, m->rf->len, m->baseaddr);
        } else if (opts->arch == ARM && opts->mode == MODE_32) {
            diss = disass(m->rf->bytes, m->rf->len, m->baseaddr, CS_ARCH_ARM, CS_MODE_ARM);
            unicorn_arm(m->rf->bytes, m->rf->len, m->baseaddr);
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
