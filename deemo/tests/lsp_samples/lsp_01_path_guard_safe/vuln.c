// LSP-01: 路径条件守卫安全 — if(n<=256) memcpy(buf,n) into malloc(256)
// 触发LSP Layer2: BVF INCONCLUSIVE (alloc=常量, write=变量无共享)
// LSP: 路径谓词 n<=256 → write_end <= 256 = alloc → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(unsigned char* src, int n) {
    if (n > 0 && n <= 256) {
        char* buf = malloc(256);
        if (buf) {
            memcpy(buf, src, n);
            free(buf);
        }
    }
}
