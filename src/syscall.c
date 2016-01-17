#include "ucui.h"

uint64_t uc_mem_read_uint64_t(uc_engine *uc, uint64_t uc_addr)
{
    uint64_t val;
    if (uc_mem_read(uc, uc_addr, &val, sizeof(uint64_t)) != UC_ERR_OK) {
        val = -1;
    }
    return(val);
}

uint32_t uc_mem_read_uint32_t(uc_engine *uc, uint64_t uc_addr)
{
    uint32_t val;
    if (uc_mem_read(uc, uc_addr, &val, sizeof(uint32_t)) != UC_ERR_OK) {
        val = -1;
    }
    return(val);
}

char * uc_mem_read_string(uc_engine *uc, uint64_t uc_addr, size_t maxlen, bool c_string)
{
    char *s = 0;
    char *sp = 0;
    size_t cutoff = 255;
    size_t len = MIN(cutoff, maxlen);
    unsigned char hn, ln;
    int i,j;

    if ((uint32_t)maxlen > cutoff)
        consw("\nWARN: %s:%d uc_mem_read_string(): maxlen(%u) < cutoff(%u). Limiting to %u bytes.\n", __FILE__, __LINE__, maxlen, cutoff, len);

    s = xmalloc(len+1);
    memset(s, 0, len);

    if (uc_mem_read(uc, uc_addr, s, len) != UC_ERR_OK) {
        sprintf(s, "*((char*)0x%lx)", uc_addr);
        return(s);
    }

    sp = xmalloc(len*2);
    memset(sp, 0, len);
    for (i=0, j=0; i < len && j < len; i++, j++) {
        switch(s[i]) {
            default:
                if (s[i] >= 32 && s[i] <= 126) {
                    sp[j] = s[i];
                } else {
                    if (c_string)
                        break;
                    hn = (s[i] & 0xf0) >> 4;
                    hn += (hn > 9) ? 87 : 48;
                    ln = s[i] & 0xf;
                    ln += (ln > 9) ? 87 : 48;
                    sp[j] = '\\';
                    sp[++j] = 'x';
                    sp[++j] = hn;
                    sp[++j] = ln;
                }
                break;
            case '\n':
                sp[j] = '\\';
                sp[++j] = 'n';
                break;
            case '\r':
                sp[j] = '\\';
                sp[++j] = 'r';
                break;
            case '\t':
                sp[j] = '\\';
                sp[++j] = 't';
                break;
        }
    }

    xfree(s);
    return(sp);
}

//
// prints "const char *const array[]" arguments
//
char * const_char_array_string(uc_engine *uc, void *saddr)
{
    uint64_t ptr_addr;
    uint64_t str_addr;
    char *s = 0, *s2 = 0, *ms = 0;
    int i;

    s2 = xmalloc(260);
    ms = xmalloc(260*4);
    memset(ms, 0, (260*4));

    ptr_addr = (opts->mode == MODE_32 ? *((uint32_t*)saddr) : *((uint64_t*)saddr));
    if (ptr_addr != 0) {
        sprintf(ms, "[");
        
        for (i=0; i<4; i++) {
            str_addr = (opts->mode == MODE_32 ? uc_mem_read_uint32_t(uc, ptr_addr) : uc_mem_read_uint64_t(uc, ptr_addr));
            if (str_addr == 0)
                break;
            s = uc_mem_read_string(uc, str_addr, 255, true);
            snprintf(s2, 260, "%s\"%s\"", (i>0 ? ", " : ""), s);
            strncat(ms, s2, 260);
            xfree(s);
            ptr_addr += (opts->mode == MODE_32 ? 4 : 8);
        }
        strcat(ms, "]");
    } else {
        strcpy(ms, "NULL");
    }
    xfree(s2);

    return(ms);
}

