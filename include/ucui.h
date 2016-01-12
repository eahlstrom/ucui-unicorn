#ifndef BINNAME
# define BINNAME "ucui"
#endif

#ifndef _ucui_h
#define _ucui_h
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <ncurses.h>
#include <signal.h>
#include <libgen.h>
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "syscall.h"
#include "init.h"
#include "memory_map.h"
#include "commands.h"

#define MIN(a,b) ({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })
#define MAX(a,b) ({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })
#define CHECK_BIT(var, pos) ((var) & (1<<(pos)))
#define consw(M, ...) wprintw(consw, M, ##__VA_ARGS__); wrefresh(consw)
#define consw_info(M, ...) consw(">> " M, ##__VA_ARGS__)
#define consw_err(M, ...) consw("[ERROR] (%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)
#define xfree(P) free(P); P = NULL


struct readfile {
  char *filename;
  uint8_t *bytes;
  size_t len;
};

struct disassembly {
  size_t count;
  cs_insn *insn;
};

struct win_layout {
  int nlines;
  int ncols;
  int begin_y;
  int begin_x;
};

struct x86_regs {
  uint32_t eax, ebx, ecx, edx, esi;
  uint32_t edi, ebp, esp, eip, eflags;
  uint16_t ss, cs, ds, es, fs, gs;
};

struct x64_regs {
  uint64_t rax, rbx, rcx, rdx, rsi;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rdi, rbp, rsp, rip, eflags;
};

struct arm_regs {
  uint32_t  r0, r1, r2, r3, r4, r5, r6,
            r7, r8,
            sb,   // r9
            sl,   // r10 ??
            fp,   // r11 
            ip,   // r12
            sp,   // r13 SP stack pointer
            lr,   // r14 LR link register
            pc,   // r15 PC program counter
            cpsr; // status register
};

enum cpu_arch {
  ARM = 0,
  X86,
};

enum cpu_mode {
  MODE_32 = 0,
  MODE_64,
};

enum emulate_os {
  LINUX = 0,
  XX,
};

struct options {
  enum cpu_arch arch;
  enum cpu_mode mode;
  uint64_t baseaddress;
  char *scfile;
  enum emulate_os os;
  void * initial_regs;
  struct memory_map *mmap;
};

enum stepmodes {
  STEP,
  RUN,
};

bool uc_running;
struct options *opts;

struct x86_regs *prev_regs_x86;
struct x86_regs * read_x86_registers(uc_engine *uc);
int unicorn_x86(uint8_t *code, unsigned int len, uint64_t baseaddress);

struct x64_regs *prev_regs_x64;
struct x64_regs *read_x64_registers(uc_engine *uc);
int unicorn_x64(uint8_t *code, unsigned int len, uint64_t baseaddress);

struct arm_regs *prev_regs_arm;
int unicorn_arm(uint8_t *code, unsigned int len, uint64_t baseaddress);
struct arm_regs * read_arm_registers(uc_engine *uc);

void printwass(unsigned int startpos, unsigned int endpos, uint64_t pc);
struct disassembly * disass(uint8_t *code, unsigned int len, uint64_t baseaddress, cs_arch arch, cs_mode mode);
struct readfile * readfile(char *filename);
void hexdump(uint8_t *code, unsigned int len, uint64_t baseaddress);
void verify_visible_ip(uint32_t pc);
bool ip_aligned_to_disassembly(uint32_t pc);
bool should_break(uint64_t pc);
void redisassemble_code(uc_engine *uc, uint64_t ip, size_t len);

void *xmalloc(size_t size);
void wpprintw(WINDOW *w, unsigned char *str, uint32_t size);
void handle_keyboard(uc_engine *uc, uint64_t pc);
struct win_layout asswl, regswl, conswl, stackwl, cmdwl;
WINDOW *assw, *regsw, *consw, *stackw, *cmdw;
struct disassembly *diss;
struct readfile *rf;
unsigned int spos;
uint64_t *breakpoints;
enum stepmodes stepmode;

#endif
