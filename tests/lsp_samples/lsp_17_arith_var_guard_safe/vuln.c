// LSP-17: 算术变量+守卫 — malloc(n*2)+memcpy(buf,n)+if(n<=256)
// BVF: 共享n, alloc_coef=2 >= write_coef=1 → SAFE (BVF handles)
// LSP作为保险: 路径谓词 n<=256, write_end=n<=256, alloc=n*2>=2*n>=n
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    if (n > 0 && n <= 256) {
        char* buf = malloc(n * 2);
        if (buf) {
            memcpy(buf, src, n);
            free(buf);
        }
    }
}
