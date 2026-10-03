// LSP-08: 双重路径守卫 — if(n>0) if(n<=200) memcpy(buf,n) into malloc(200)
// LSP: 两个if生成两条谓词 n<=200 → SAFE
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    char* buf = malloc(200);
    if (buf && n > 0) {
        if (n <= 200) {
            memcpy(buf, src, n);
        }
        free(buf);
    }
}
