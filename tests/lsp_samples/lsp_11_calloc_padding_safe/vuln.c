// LSP-11: calloc对齐安全 — calloc(1, 12)+memcpy(16)
// ptmalloc2: calloc(1,12)→usable=32? no, 12→usable=24(min_chunk=32)
// Actually 12 → chunk=32, usable=24. memcpy(16)<=24 → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src) {
    char* buf = calloc(1, 12);
    if (buf) {
        memcpy(buf, src, 16);
        free(buf);
    }
}
