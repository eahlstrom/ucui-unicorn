#include "ucui.h"

static void parse_x86_register(char *line, struct x86_regs *wr)
{
    char *reg, *val;
    int n;

    n = sscanf(line, "%m[^':']:%ms", &reg, &val);
    if (n == 2) {
        errno = 0;
        if (strcmp(reg, "eax") == 0) { wr->eax = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "ebx") == 0) { wr->ebx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "ecx") == 0) { wr->ecx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "edx") == 0) { wr->edx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "esi") == 0) { wr->esi = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "edi") == 0) { wr->edi = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "ebp") == 0) { wr->ebp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "esp") == 0) { wr->esp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "eip") == 0) { wr->eip = strtoul(val, NULL, 0); }
        // cannot modify!? else if (strcmp(reg, "eflags") == 0) { wr->eflags = strtoul(val, NULL, 0); }
        else { 
            printf("invalid register: %s\n", reg);
            exit(1);
        }
         
        if (errno != 0) {
            perror(line);
            exit(1);
        }
        xfree(reg);
        xfree(val);
    } else if (errno != 0) {
        perror("scanf");
        exit(1);
    } else {
        printf("Invalid format of the register file. It need to be like:\n");
        printf(" eax: 0x1234\n ebx: 1234\n");
        exit(1);
    }

}

static void * init_registers_from_file_x86(char *file)
{
    struct readfile *rf;
    char *line;
    struct x86_regs *r;

    r = xmalloc(sizeof(struct x86_regs));
    memset(r, 0, sizeof(struct x86_regs));
    // printf("%s:%d init_registers_from_file(\"%s\")\n\n", __FILE__, __LINE__, file);

    rf = readfile(file);

    line = strtok((char*)rf->bytes, "\n");
    do {
        parse_x86_register(line, r);
    } while((line = strtok(NULL, "\n")) != NULL);

    return(r);
}

void *init_registers_from_file(char *file)
{
    if (opts->arch == X86 && opts->mode == MODE_32) {
        return(init_registers_from_file_x86(file));
    } else if (opts->arch == X86 && opts->mode == MODE_64) {
        printf("no support yet\n");
    } else if (opts->arch == ARM && opts->mode == MODE_32) {
        printf("no support yet\n");
    }
    return NULL;
}

