// LSP-05: 分配器padding安全 — malloc(17)+memcpy(20)
// ptmalloc2: request2size(17)=24 (17+8=25, align_up(25,16)=32, usable=32-8=24)
// slack=24-17=7, write_end=20 <= 24 → SAFE
// BVF: 20>17 → INCONCLUSIVE; LSP Layer3: 20<=24 → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src) {
    char* buf = malloc(17);
    if (buf) {
        memcpy(buf, src, 20);
        free(buf);
    }
}
