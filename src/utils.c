#include "ucui.h"

void *xmalloc(size_t size)
{
    void *ptr;

    if ((ptr = malloc(size)) == NULL) {
        endwin();
        printf("malloc: %s\n", strerror(errno));
        exit(1);
    }
    memset(ptr, 0, size);

    return(ptr);
}
