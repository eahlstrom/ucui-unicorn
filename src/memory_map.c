#include "ucui.h"

void map_and_write_memory(uc_engine *uc, struct memory_map *mmap)
{
    struct memory_map *p;
    uc_err err;
    p = mmap;

    do {
        // consw("map 0x%08x with len: 0x%x\n", p->baseaddr, p->len);
        if ((err = uc_mem_map(uc, p->baseaddr, p->len, p->prot)) != UC_ERR_OK) {
            consw_err("uc_mem_map() error %u: %s\n", err, uc_strerror(err));
            goto error;
        }

        if (uc_mem_write(uc, p->baseaddr, p->rf->bytes, p->rf->len)) {
            consw_err("uc_mem_write() error %u: %s\n", err, uc_strerror(err));
            goto error;
        }
    } while ((p = p->next) != NULL);

    return;

error:
    getch();
    endwin();
    exit(1);
}

struct memory_map * mmap_for_address(uint64_t address)
{
    struct memory_map *p;
    p = opts->mmap;
    do {
        if (address >= p->baseaddr && address <= (p->baseaddr+p->len)) {
            return(p);
        }
    } while ((p = p->next) != NULL);

    return(NULL);
}

void print_memory_map(struct memory_map *m)
{
    struct memory_map *p;
    p = m;

    consw("--------- [Memory MAP] ---------\n");
    do {
        consw(" 0x%08x - 0x%08x   %c%c%c\n", 
                p->baseaddr, 
                (p->baseaddr + p->len),
                ((p->prot & UC_PROT_READ)   ? 'r':'-'),
                ((p->prot & UC_PROT_WRITE)  ? 'w':'-'),
                ((p->prot & UC_PROT_EXEC)   ? 'x':'-'));
    } while ((p = p->next) != NULL);
    consw("--------------------------------\n");
}

