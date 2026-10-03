// LSP-16: if-else路径确认溢出 — if(n>=1024) memcpy(buf,n) into malloc(512)
// LSP: 路径谓词 n>=1024 → write_end >= 1024 > 512 → OVERFLOW
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    char* buf = malloc(512);
    if (buf) {
        if (n >= 1024) {
            memcpy(buf, src, n);
        }
        free(buf);
    }
}
