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

static void parse_x64_register(char *line, struct x64_regs *wr)
{
    char *reg, *val;
    int n;

    n = sscanf(line, "%m[^':']:%ms", &reg, &val);
    if (n == 2) {
        errno = 0;
        if (strcmp(reg, "rax") == 0) { wr->rax = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rbx") == 0) { wr->rbx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rcx") == 0) { wr->rcx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rdx") == 0) { wr->rdx = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rsi") == 0) { wr->rsi = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rdi") == 0) { wr->rdi = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rbp") == 0) { wr->rbp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rsp") == 0) { wr->rsp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "rip") == 0) { wr->rip = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r8") == 0) { wr->r8 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r9") == 0) { wr->r9 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r10") == 0) { wr->r10 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r11") == 0) { wr->r11 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r12") == 0) { wr->r12 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r13") == 0) { wr->r13 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r14") == 0) { wr->r14 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r15") == 0) { wr->r15 = strtoul(val, NULL, 0); }
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
        printf(" rax: 0x1234\n rbx: 1234\n");
        exit(1);
    }
}

static void parse_arm_register(char *line, struct arm_regs *wr)
{
    char *reg, *val;
    int n;

    n = sscanf(line, "%m[^':']:%ms", &reg, &val);
    if (n == 2) {
        errno = 0;
        if (strcmp(reg, "r1") == 0) { wr->r1 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r2") == 0) { wr->r2 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r3") == 0) { wr->r3 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r4") == 0) { wr->r4 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r5") == 0) { wr->r5 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r6") == 0) { wr->r6 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r7") == 0) { wr->r7 = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r9") == 0 || strcmp(reg, "sb") == 0) { wr->sb = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r10") == 0 || strcmp(reg, "sl") == 0) { wr->sl = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r11") == 0 || strcmp(reg, "fp") == 0) { wr->fp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r12") == 0 || strcmp(reg, "ip") == 0) { wr->ip = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r13") == 0 || strcmp(reg, "sp") == 0) { wr->sp = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r14") == 0 || strcmp(reg, "lr") == 0) { wr->lr = strtoul(val, NULL, 0); }
        else if (strcmp(reg, "r15") == 0 || strcmp(reg, "pc") == 0) { wr->pc = strtoul(val, NULL, 0); }
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
        printf(" r1: 0x1234\n r2: 1234\n");
        exit(1);
    }
}


void *init_registers_from_file(char *file)
{
    struct readfile *rf;
    char *line;
    void *r = NULL;

    // printf("%s:%d init_registers_from_file(\"%s\")\n\n", __FILE__, __LINE__, file);

    rf = readfile(file);
    line = strtok((char*)rf->bytes, "\n");
    do {
        if (opts->arch == X86 && opts->mode == MODE_32) {
            if (r == NULL) {
                r = xmalloc(sizeof(struct x86_regs));
                memset(r, 0, sizeof(struct x86_regs));
            }
            parse_x86_register(line, r);
        } else if (opts->arch == X86 && opts->mode == MODE_64) {
            if (r == NULL) {
                r = xmalloc(sizeof(struct x64_regs));
                memset(r, 0, sizeof(struct x64_regs));
            }
            parse_x64_register(line, r);
        } else if (opts->arch == ARM && opts->mode == MODE_32) {
            if (r == NULL) {
                r = xmalloc(sizeof(struct arm_regs));
                memset(r, 0, sizeof(struct arm_regs));
            }
            parse_arm_register(line, r);
        }
    } while((line = strtok(NULL, "\n")) != NULL);

    return r;
}

