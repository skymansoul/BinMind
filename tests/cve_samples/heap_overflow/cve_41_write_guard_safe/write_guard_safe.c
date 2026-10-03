#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-41: write_guard安全 — 条件写入有边界保护
 *
 * 模式: malloc(64); if(offset < 56) memcpy(buf+offset, src, 8);
 * usable(64)=72, offset<=55, write_end=55+8=63 <= 72 → SAFE
 */
int main() {
    int offset = 40;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    char src[8] = "AAAAAAA";
    if (offset < 56) {
        memcpy(buf + offset, src, 8);
    }
    free(buf);
    return 0;
}
