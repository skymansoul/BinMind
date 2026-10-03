// LSP-02: 路径条件确认溢出 — if(n>=512) memcpy(buf,n) into malloc(256)
// BVF: alloc=256(常量), write=n(变量), 无共享 → INCONCLUSIVE
// LSP: 路径谓词 n>=512 → write_end >= 512 > 256 = alloc → OVERFLOW
#include <stdlib.h>
#include <string.h>

void vuln_func(unsigned char* src, int n) {
    if (n >= 512) {
        char* buf = malloc(256);
        if (buf) {
            memcpy(buf, src, n);
            free(buf);
        }
    }
}
