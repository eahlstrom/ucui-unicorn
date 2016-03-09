#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>


#define check(B, M) if (!(B)) {M;}
#define MIN(a,b) ({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })

struct map_entry {
    unsigned long start;
    size_t size;
    char desc[256];
    char flgs[4];
};

struct map_entry ** read_maps(char *mapfile)
{
    FILE *f;
    struct map_entry **eset, *e;
    int r;
    char flgs[5], dev[6];
    char *desc, *l;
    char line[256];
    unsigned long start, end, offset, inode;
    size_t max_entries = 100, i;

    f = fopen(mapfile, "r");
    check(f != NULL, err(1, "fopen: %s", mapfile));
    eset = calloc(max_entries, sizeof(struct map_entry*));

    i = 0;
    l = fgets(line, 255, f);
    check(l != NULL, err(1, "fread: %s", mapfile));
    do {
        r = sscanf(line, "%lx-%lx %s %lx %s %lx %ms", &start, &end, flgs, &offset, dev, &inode, &desc);
        if (r >= 6 && i < max_entries) {
            e = malloc(sizeof(struct map_entry));
            e->start = start;
            e->size = end - e->start;
            strncpy(e->flgs, flgs, 3);
            if (r >= 7)
                strncpy(e->desc, desc, 255);
            eset[i] = e;
            i++;
        }
        free(desc);
    } while(fgets(line, 255, f));

    if (i == 0) {
        free(eset);
        eset = NULL;
    }
    
    fclose(f);
    return(eset);
}

void map2ucui_memmap(char *outfile, struct map_entry **eset)
{
    struct map_entry *e;
    FILE *f;

    f = fopen(outfile, "w");
    check(f != NULL, err(1, "fopen: %s", outfile));
    while((e = *eset++)) {
#ifdef __x86_64__
        fprintf(f, "0x%016lx\t%s\tfile_%016lx\t\t# size: %-9ld %s\n", e->start, e->flgs, e->start, (long int) e->size, e->desc);
#elif __i386__
        fprintf(f, "0x%08lx\t%s\tfile_%08lx\t\t# size: %-9ld %s\n", e->start, e->flgs, e->start, (long int) e->size, e->desc);
#endif
    }
    fclose(f);
}

void regs2ucui_regs(char *outfile, pid_t pid, int detach)
{
    struct user_regs_struct regs;
    long ret;
    int w;
    FILE *f;

    f = fopen(outfile, "w");
    check(f != NULL, err(1, "fopen: %s", outfile));

    ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    check(ret != -1, err(1, "PTRACE_ATTACH pid: %d", pid));
    wait(&w);
    if (!WIFSTOPPED(w)) {
        ret = ptrace(PTRACE_DETACH, pid, NULL, w);
        errx(1, "PTRACE: %d got another signal while we where waiting!\n", pid);
    }

    ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    check(ret == 0, err(1, "PTRACE_GETREGS"));
#ifdef __x86_64__
    fprintf(f, "rax: 0x%016llx\t# orig_rax: 0x%016llx\n", regs.rax, regs.orig_rax);
    fprintf(f, "rbx: 0x%016llx\n", regs.rbx);
    fprintf(f, "rcx: 0x%016llx\n", regs.rcx);
    fprintf(f, "rdx: 0x%016llx\n", regs.rdx);
    fprintf(f, "rsi: 0x%016llx\n", regs.rsi);
    fprintf(f, "rdi: 0x%016llx\n", regs.rdi);
    fprintf(f, "rip: 0x%016llx\n", regs.rip);
    fprintf(f, "rbp: 0x%016llx\n", regs.rbp);
    fprintf(f, "rsp: 0x%016llx\n", regs.rsp);
    fprintf(f, "r8:  0x%016llx\n", regs.r8);
    fprintf(f, "r9:  0x%016llx\n", regs.r9);
    fprintf(f, "r10: 0x%016llx\n", regs.r10);
    fprintf(f, "r11: 0x%016llx\n", regs.r11);
    fprintf(f, "r12: 0x%016llx\n", regs.r12);
    fprintf(f, "r13: 0x%016llx\n", regs.r13);
    fprintf(f, "r14: 0x%016llx\n", regs.r14);
    fprintf(f, "r15: 0x%016llx\n", regs.r15);
    fprintf(f, "ss:  0x%04llx\n", regs.ss);
    fprintf(f, "cs:  0x%04llx\n", regs.cs);
    fprintf(f, "ds:  0x%04llx\n", regs.ds);
    fprintf(f, "es:  0x%04llx\n", regs.es);
    fprintf(f, "fs:  0x%04llx\t\t# fs_base: 0x%04llx\n", regs.fs, regs.fs_base);
    fprintf(f, "gs:  0x%04llx\t\t# gs_base: 0x%04llx\n", regs.gs, regs.gs_base);
    fprintf(f, "eflags: 0x%08llx\n", regs.eflags);
#elif __i386__
    fprintf(f, "eax: 0x%08lx\t# orig_eax: 0x%08lx\n", regs.eax, regs.orig_eax);
    fprintf(f, "ebx: 0x%08lx\n", regs.ebx);
    fprintf(f, "ecx: 0x%08lx\n", regs.ecx);
    fprintf(f, "edx: 0x%08lx\n", regs.edx);
    fprintf(f, "esi: 0x%08lx\n", regs.esi);
    fprintf(f, "edi: 0x%08lx\n", regs.edi);
    fprintf(f, "eip: 0x%08lx\n", regs.eip);
    fprintf(f, "ebp: 0x%08lx\n", regs.ebp);
    fprintf(f, "esp: 0x%08lx\n", regs.esp);
    fprintf(f, "ss:  0x%04lx\n", regs.xss);
    fprintf(f, "cs:  0x%04lx\n", regs.xcs);
    fprintf(f, "ds:  0x%04lx\n", regs.xds);
    fprintf(f, "es:  0x%04lx\n", regs.xes);
    fprintf(f, "fs:  0x%04lx\n", regs.xfs);
    fprintf(f, "gs:  0x%04lx\n", regs.xgs);
    fprintf(f, "eflags: 0x%08lx\n", regs.eflags);
#endif

    fclose(f);
    if (detach) {
        ret = ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
        check(ret != -1, err(1, "PTRACE_DETACH"));
    }
}

void dump_procmem(struct map_entry **eset, pid_t pid, char *basedir)
{
    struct map_entry *e;
    char buf[255];
    void *rbuf;
    size_t r;
    off_t readlen, pos;
    int map, outf;

    snprintf(buf, sizeof(buf), "/proc/%d/mem", pid);
    map = open(buf, O_RDONLY);
    check(map != -1, err(1, "open %s", buf));

    rbuf = malloc(4096);
    check(rbuf != 0, err(1, "malloc"));

    while((e = *eset++)) {
        check(lseek(map, e->start, SEEK_SET) != -1, err(1, "dump_procmem seek(0x%lx)", e->start));

#ifdef __x86_64__
        snprintf(buf, sizeof(buf), "%s/file_%016lx", basedir, e->start);
#elif __i386__
        snprintf(buf, sizeof(buf), "%s/file_%08lx", basedir, e->start);
#endif

        printf("creating raw memory file \"%s\"\n", buf);
        outf = open(buf, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
        check(outf != -1, err(1, "open %s", buf));
        
        pos = e->start;
        check(e->size >= 4096, err(1, "to small memory:(0x%lx) %s", (long int) e->size, buf));
        readlen = 4096;
        while((r = read(map, rbuf, readlen)) != -1) {
            if (r == 0) break;
            check(write(outf, rbuf, r) != -1, err(1, "write %s", buf));
            pos += r;
            readlen = MIN(readlen, (e->start + e->size) - pos);
        }
         
        close(outf);
    }
    close(map);
    free(rbuf);
}

int main(int argc, char **argv)
{
    struct map_entry **eset;
    char buf[255], proc_map[20], basedir[10];
    char *ucui_memfile = "memory.map";
    char *ucui_regfile = "registers";
    pid_t pid;
    int ret;
    struct stat st;

    if (argc != 2) {
        printf("Usage: ucui_procdump <pid>\n");
        exit(1);
    }

    pid = (pid_t) strtoul(argv[1], NULL, 10);
    check(pid != 0, errx(1, "invalid pid!"));

    snprintf(proc_map, 20, "/proc/%d/maps", (int)pid);
    ret = stat(proc_map, &st);
    check(ret == 0, err(1, "stat: %s", proc_map));
    snprintf(basedir, 10, "%d", (int)pid);
    ret = mkdir(basedir, S_IRWXU);
    check(ret == 0, err(1, "mkdir %s", basedir));
    
    snprintf(buf, 255, "%s/%s", basedir, ucui_regfile);
    printf("creating ucui registers \"%s\"...\n", buf);
    regs2ucui_regs(buf, pid, 0);

    snprintf(buf, 255, "%s/%s", basedir, ucui_memfile);
    printf("creating ucui memory map \"%s\"...\n", buf);
    eset = read_maps(proc_map);
    map2ucui_memmap(buf, eset);

    dump_procmem(eset, pid, basedir);

    ret = ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
    check(ret != -1, err(1, "PTRACE_DETACH"));
    return(0);
}
