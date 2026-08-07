// LSP-04: min()约束安全 — n = min(user_n, 128) + memcpy(buf,n) into malloc(128)
// LSP: 提取 n<=128, write_end=n<=128=alloc → SAFE
#include <stdlib.h>
#include <string.h>

#define MIN(a,b) ((a)<(b)?(a):(b))

void vuln_func(char* src, int user_n) {
    int n = MIN(user_n, 128);
    char* buf = malloc(128);
    if (buf) {
        memcpy(buf, src, n);
        free(buf);
    }
}
