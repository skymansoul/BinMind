// LSP-03: assert约束安全 — assert(len<=64) + memcpy(buf,len) into malloc(64)
// LSP: 从assert提取 len<=64, write_end=len<=64=alloc → SAFE
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void vuln_func(char* src, int len) {
    assert(len <= 64);
    char* buf = malloc(64);
    if (buf) {
        memcpy(buf, src, len);
        free(buf);
    }
}
