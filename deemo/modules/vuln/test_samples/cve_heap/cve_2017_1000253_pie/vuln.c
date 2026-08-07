/* CVE-2017-1000253 — PIE 加载器堆溢出 (常量越界模式)。
 * malloc(64) + memcpy(96)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    char src[96];
    memset(src, 'A', sizeof(src));
    memcpy(buf, src, 96);                 /* 越界 32B */
    free(buf);
    return 0;
}
