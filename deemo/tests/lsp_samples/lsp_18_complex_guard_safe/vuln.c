// LSP-18: 复合条件守卫 — if(n>0 && n<64 && m<=64) memcpy(buf+n,m) into malloc(128)
// BVF: alloc=128(const), write=m(var)→INCONCLUSIVE
// LSP: 路径谓词 m<=64, n<64, write_end=m+n<=128 → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n, int m) {
    if (n > 0 && n < 64 && m > 0 && m <= 64) {
        char* buf = malloc(128);
        if (buf) {
            memcpy(buf + n, src, m);
            free(buf);
        }
    }
}
