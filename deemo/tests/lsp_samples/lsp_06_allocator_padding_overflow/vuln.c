// LSP-06: 分配器padding溢出 — malloc(17)+memcpy(40)
// ptmalloc2: request2size(17)=24, usable=24, write_end=40 > 24 → OVERFLOW
// BVF: 常量比较 40>17; LSP Layer3: 40>24 → OVERFLOW
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src) {
    char* buf = malloc(17);
    if (buf) {
        memcpy(buf, src, 40);
        free(buf);
    }
}
