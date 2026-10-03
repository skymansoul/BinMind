#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-51: 复杂步长安全 — 循环步长写入精确匹配分配大小
 *
 * 模式: malloc(256); for(i=0; i<4; i++) buf[i*64]=0;
 * max_write_end = (4-1)*64 + 1 = 193 <= usable(256)=264 → SAFE
 */
int main() {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    int i;
    for (i = 0; i < 4; i++) {
        buf[i * 64] = 0;
    }
    free(buf);
    return 0;
}
