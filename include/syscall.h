#ifndef _syscall_h
#define _syscall_h

#include "syscall_linux.h"

// Helpers for printing syscall arguments
uint64_t uc_mem_read_uint64_t(uc_engine *uc, uint64_t uc_addr);
uint32_t uc_mem_read_uint32_t(uc_engine *uc, uint64_t uc_addr);
char * uc_mem_read_string(uc_engine *uc, uint64_t uc_addr, size_t maxlen);
char * const_char_array_string(uc_engine *uc, void *saddr);

#endif
