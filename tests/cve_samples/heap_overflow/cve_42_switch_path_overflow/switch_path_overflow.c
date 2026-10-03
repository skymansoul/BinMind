#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-42: switch-case路径溢出 — case 2写入超出边界
 *
 * 模式: malloc(64); switch(mode) {
 *   case 0: memcpy(buf, src1, 32); break;   // 32 <= usable(64)=72 → SAFE
 *   case 1: memcpy(buf, src2, 64); break;   // 64 <= 72 → SAFE
 *   case 2: memcpy(buf, src3, 128); break;  // 128 > 72 → OVERFLOW
 *   default: memcpy(buf, src4, 48); break;  // 48 <= 72 → SAFE
 * }
 */
int main() {
    int mode = 2;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    char src1[64], src2[64], src3[128], src4[64];
    memset(src1, 'A', 64);
    memset(src2, 'B', 64);
    memset(src3, 'C', 128);
    memset(src4, 'D', 48);

    switch (mode) {
        case 0:
            memcpy(buf, src1, 32);
            break;
        case 1:
            memcpy(buf, src2, 64);
            break;
        case 2:
            memcpy(buf, src3, 128);
            break;
        default:
            memcpy(buf, src4, 48);
            break;
    }

    printf("switch_path_overflow: mode=%d\n", mode);
    free(buf);
    return 0;
}
