// LSP-14: 偏移+padding溢出 — malloc(28)+memcpy(buf+24,src,20)
// ptmalloc2: request2size(28)=40 (28+8=36, align_up(36,16)=48, usable=48-8=40)
// slack=40-28=12, write_end=24+20=44 > 40 → OVERFLOW
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src) {
    char* buf = malloc(28);
    if (buf) {
        memcpy(buf + 24, src, 20);
        free(buf);
    }
}
