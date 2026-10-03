#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-52: 复杂步长溢出 — 循环步长写入超出分配范围
 *
 * 模式: malloc(128); for(i=0; i<4; i++) memcpy(buf+i*64, src, 64);
 * max_write_end = (4-1)*64 + 64 = 256 > usable(128)=136 → OVERFLOW
 */
int main() {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char src[64];
    memset(src, 'A', 64);
    int i;
    for (i = 0; i < 4; i++) {
        memcpy(buf + i * 64, src, 64);
    }
    free(buf);
    return 0;
}
