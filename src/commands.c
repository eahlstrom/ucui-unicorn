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

static command_state cmd_asmw(uc_engine *uc, uint64_t ip, char *args)
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
        consw("usage: asmw line\n");
        goto ret;
    }
    printwass(lno-1, (asswl.nlines-2), ip);

ret:
    return(MORE_COMMANDS);
}


Command *init_commands(void)
{
    Command *root;

               root = create_command("s",     &cmd_step,       "step instruction");
    add_command(root, create_command("c",     &cmd_cont,       "continue to next bp or end"));
    add_command(root, create_command("M",     &cmd_pmmap,      "print memory map"));
    add_command(root, create_command("D",     &cmd_redisass,   "re-disassemble code"));
    add_command(root, create_command("asmw",  &cmd_asmw,       "change assembly window"));

    return(root);
}

