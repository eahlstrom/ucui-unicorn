#include "ucui.h"

static command_state cmd_step(uc_engine *uc, uint64_t ip, char *args) 
{
    return(DONE_PROCESSING);
}

static command_state cmd_cont(uc_engine *uc, uint64_t ip, char *args) 
{
    stepmode = RUN;
    return(DONE_PROCESSING);
}

static command_state cmd_pmmap(uc_engine *uc, uint64_t ip, char *args) 
{
    print_memory_map(opts->mmap);
    return(MORE_COMMANDS);
}

static command_state cmd_redisass(uc_engine *uc, uint64_t ip, char *args) 
{
    struct memory_map *m;
    consw_info("Re-disassembling code... ");
    if ((m = mmap_for_address(ip)) != NULL) {
        consw("0x%08x -> 0x%08x\n", m->baseaddr, m->baseaddr + m->rf->len);
        redisassemble_code(uc, m->baseaddr, m->rf->len);
        verify_visible_ip(ip);
        printwass(spos, (asswl.nlines-2), ip);
    } else {
        consw("failed to find memory map for ip 0x%08x\n", ip);
    }
 
    return(MORE_COMMANDS);
}

static command_state cmd_list(uc_engine *uc, uint64_t ip, char *args)
{
    int n;
    unsigned int lno;

    n = sscanf(args, "%u", &lno);
    if (n == 1) {
        if (lno >= diss->count)
            lno = diss->count;
        if (lno < 1)
            lno = 1;
    } else {
        consw("usage: list lineno\n");
        goto ret;
    }

    if (((lno-1) + (asswl.nlines-2)) > diss->count) {
        lno = ((diss->count) - (asswl.nlines-2)) + 1;
    }
    printwass(lno-1, (asswl.nlines-2), ip);

ret:
    return(MORE_COMMANDS);
}

static command_state cmd_hx(uc_engine *uc, uint64_t ip, char *args)
{
    int n; 
    uint64_t addr;
    unsigned int len, max_count = 1024, arg_count = 0;
    uint8_t *bytes = NULL;
    char width;
    uint8_t blen;
    uc_err err;

    n = sscanf(args, "%c %llx %u", &width, (long long unsigned int*)&addr, &arg_count);
    if (n <= 0) {
        goto usage;
    } else if (n == 1) {
        addr = ip;
    } else if (n == 3 && arg_count <=max_count) {
        len = arg_count;
    }
    switch(width) {
        case 'b': 
            blen = 1;
            break;
        case 'h': 
            blen = 2;
            break;
        case 'w': 
            blen = 4;
            break;
        case 'g':
            blen = 8;
            break;
        default:
            goto usage;
    }
    if (arg_count == 0)
        arg_count = (64 / blen);

    len = arg_count * blen;
    consw_info("hexdump %u bytes @ 0x%08llx\n", len, addr);
    bytes = xmalloc(len+1);
    memset(bytes, 0, len+1);
    if ((err = uc_mem_read(uc, addr, bytes, len)) != UC_ERR_OK) {
        consw("%s\n", uc_strerror(err)); 
        goto ret;
    }

    switch(width) {
        case 'b':
            hexdump_uint8(bytes, len, addr);
            goto ret;
        case 'h':
            hexdump_uint16(bytes, len, addr);
            goto ret;
        case 'w':
            hexdump_uint32(bytes, len, addr);
            goto ret;
        case 'g':
            hexdump_uint64(bytes, len, addr);
            goto ret;
        default:
            goto usage;
    }

usage:
    consw("usage: hx width [address] [count]\n");
    consw("  width is one of: b(uint8) h(uint16) w(uint32) g(uint64)\n");
    consw("  ex: hx b 0x0040000 128\n");

ret:
    xfree(bytes);
    return(MORE_COMMANDS);
}

Command *init_commands(void)
{
    Command *root;

               root = create_command("s",     &cmd_step,       "step instruction");
    add_command(root, create_command("c",     &cmd_cont,       "continue to next bp or end"));
    add_command(root, create_command("M",     &cmd_pmmap,      "print memory map"));
    add_command(root, create_command("D",     &cmd_redisass,   "re-disassemble code"));
    add_command(root, create_command("list",  &cmd_list,       "change assembly window listing"));
    add_command(root, create_command("hx",    &cmd_hx,         "hexdump address"));

    return(root);
}

