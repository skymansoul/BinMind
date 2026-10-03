#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-41: switch-case路径安全 — 每个case的写入都在边界内
 *
 * 模式: malloc(128); switch(mode) {
 *   case 0: memcpy(buf, src1, 32); break;
 *   case 1: memcpy(buf, src2, 64); break;
 *   default: memcpy(buf, src3, 96);
 * }
 * usable(128)=136, 最大写入96 <= 136 → SAFE
 */
int main() {
    int mode = 1;
    char *buf = (char *)malloc(128);
    if (!buf) return 1;

    char src1[64], src2[64], src3[128];
    memset(src1, 'A', 64);
    memset(src2, 'B', 64);
    memset(src3, 'C', 96);

    switch (mode) {
        case 0:
            memcpy(buf, src1, 32);
            break;
        case 1:
            memcpy(buf, src2, 64);
            break;
        default:
            memcpy(buf, src3, 96);
            break;
    }

    printf("switch_path_safe: mode=%d\n", mode);
    free(buf);
    return 0;
}
