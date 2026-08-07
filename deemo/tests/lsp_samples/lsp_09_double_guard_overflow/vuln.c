// LSP-09: 双重路径守卫溢出 — if(n>0) if(n>=300) memcpy(buf,n) into malloc(200)
// LSP: 路径谓词 n>=300 → write_end >= 300 > 200 → OVERFLOW
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    char* buf = malloc(200);
    if (buf && n > 0) {
        if (n >= 300) {
            memcpy(buf, src, n);
        }
        free(buf);
    }
}
