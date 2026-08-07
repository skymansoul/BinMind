// LSP-10: 共享变量+路径守卫 — malloc(n)+memcpy(buf,n)+if(n<=512)
// BVF: 共享变量n, alloc_coef=1 >= write_coef=1 → SAFE (BVF handles this)
// 但如果BVF因某种原因INCONCLUSIVE, LSP作为保险
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    if (n <= 512 && n > 0) {
        char* buf = malloc(n);
        if (buf) {
            memcpy(buf, src, n);
            free(buf);
        }
    }
}
