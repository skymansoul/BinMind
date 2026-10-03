// LSP-15: while循环守卫安全 — while(n < 128) memcpy(buf,n) into malloc(128)
// LSP: 从while提取 n<128, write_end<=128-1=127 <= 128 → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    n = 0;
    char* buf = malloc(128);
    if (buf) {
        while (n < 128) {
            memcpy(buf, src, n);
            n++;
        }
        free(buf);
    }
}
