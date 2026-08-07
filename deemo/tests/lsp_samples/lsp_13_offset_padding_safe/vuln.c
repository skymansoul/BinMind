// LSP-13: 偏移+padding安全 — malloc(28)+memcpy(buf+24,src,4)
// ptmalloc2: malloc(28)→chunk=48→usable=32? no, align(28+16,16)=48→usable=32
// write_end=24+4=28 <= 32 → SAFE (落在padding)
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src) {
    char* buf = malloc(28);
    if (buf) {
        memcpy(buf + 24, src, 4);
        free(buf);
    }
}
