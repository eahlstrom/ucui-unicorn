#ifndef __memory_map_h
# define __memory_map_h

struct memory_map {
    struct   readfile *rf;
    uint64_t baseaddr;
    size_t   len; // 1MByte seems to be smallest possible value.
    uint8_t  prot;
    struct   memory_map *next;
};

void print_memory_map(struct memory_map *m);
struct memory_map * mmap_for_address(uint64_t address);
void map_and_write_memory(uc_engine *uc, struct memory_map *mmap);

#endif
