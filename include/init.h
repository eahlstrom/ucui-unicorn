#ifndef __init_h
# define __init_h

struct memory_map * init_memory_map(char *map_file);
void * init_registers_from_file(char *file);

#endif
