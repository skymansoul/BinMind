// LSP-07: 三元条件守卫 — sz = (n <= 100) ? n : 100 + memcpy(buf,sz) into malloc(100)
// LSP: 从三元表达式提取 n<=100, write_end=sz<=100=alloc → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    int sz = (n <= 100) ? n : 100;
    char* buf = malloc(100);
    if (buf) {
        memcpy(buf, src, sz);
        free(buf);
    }
}
