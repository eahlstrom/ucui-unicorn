#include "ucui.h"

struct readfile * readfile(char *filename)
{
    int fd;
    struct readfile *rf;
    struct stat sb;
    size_t r, offs;
    
    if ((fd = open(filename, O_RDONLY)) == -1) {
        printf("%s: %s\n", filename, strerror(errno));
        exit(1);
    }

    if (fstat(fd, &sb) == -1) {
        printf("readfile(%s): fstat: %s\n", filename, strerror(errno));
        exit(1);
    }

    rf = xmalloc(sizeof(struct readfile));
    rf->len = sb.st_size;
    rf->filename = xmalloc(strlen(filename)+1);
    strcpy(rf->filename, filename);
    rf->bytes = xmalloc(rf->len);

    memset(rf->bytes, 0, rf->len);
    offs = 0;
    while ((r = read(fd, (rf->bytes)+offs, rf->len)) != 0) {
        offs += r;
    }

    close(fd);
    return(rf);
}
