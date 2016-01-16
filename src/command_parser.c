#include "ucui.h"

static void chomp_strip(char *str)
{
    int i;
    for (i=strlen(str); i != 0; i--) {
        switch(str[i]) {
            case 0: case '\t': case '\n': case ' ':
                str[i] = 0;
                break;
            default:
                return;
        }
    }
}

static void cmd_usage(void)
{
    Command *c;

    consw("Valid commands: (enter repeat's previous command)\n");
    c = cmds;
    do {
        consw("  %-10s - %s\n", c->name, c->desc);
    } while ((c = c->next) != NULL);
}

Command *last_command(Command *root)
{
    Command *last, *curr = root;
    while(curr != NULL) {
        last = curr;
        curr = curr->next;
    }
    return(last);
}

Command *create_command(char *name, CmdHandler handler, char *desc)
{
    Command *c;
    c = xmalloc(sizeof(Command));
    c->name     = name;
    c->desc     = desc;
    c->handler  = handler;
    return(c);
}

void add_command(Command *root, Command *addcmd)
{
    Command *last = last_command(root);
    last->next = addcmd;
}

Command *find_command(char *cmd)
{
    Command *c;

    c = cmds;
    do {
        if (strncmp(c->name, cmd, MAX_CMD) == 0)
            return(c);
    } while ((c = c->next) != NULL);

    return(NULL);
}

command_state runcmd(uc_engine *uc, uint64_t ip, char *line)
{
    char cmd[MAX_CMD+1], arg[MAX_CMD+1], *s;
    int i;
    Command *c;

    chomp_strip(line);
    strncpy(cmd, line, MAX_CMD);
    s = strpbrk(cmd, " ");
    if (s) {
        *s = 0; // terminate cmd string
        s++;    // advance to space
        // skip strip spaces before arg(s)
        for (i=0; (char)*s == 0x20 && i < MAX_CMD; i++) 
            s++;
        strncpy(arg, s, MAX_CMD);
    } else {
        arg[0] = 0;
    }

    if ((c = find_command(cmd)) == NULL) {
        cmd_usage();
        return(MORE_COMMANDS);
    }

    return(c->handler(uc, ip, arg));
}
