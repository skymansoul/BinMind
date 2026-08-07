/* CVE-2020-10713 (GRUB2) UAF 复现 — 脚本变量缓冲区释放后仍被
   引用: free(buf) 后 memcpy 读 buf. 简化: free(p) 后 strlen(p). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p;
    p = (char *)malloc(32);
    if (!p) {
        return 1;
    }
    strcpy(p, "var");
    free(p);
    printf("%zu\n", strlen(p));
    return 0;
}
