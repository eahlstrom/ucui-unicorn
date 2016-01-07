#include "ucui.h"

struct readfile * readfile(char *filename)
{
    FILE *f;
    struct readfile *rf;
    struct stat sb;

    rf = xmalloc(sizeof(struct readfile));
    
    if ((f = fopen(filename, "r")) == NULL) {
        printf("%s: %s\n", filename, strerror(errno));
        exit(1);
    }

    if (fstat(fileno(f), &sb) == -1) {
        printf("fstat: %s\n", strerror(errno));
        exit(1);
    }
    rf->len = sb.st_size;

    rf->bytes = xmalloc(rf->len);
    memset(rf->bytes, 0, rf->len);
    if (fread(rf->bytes, rf->len, 1, f) == 0) {
        printf("fread returned 0\n");
        exit(1);
    }

    fclose(f);
    return(rf);
}
