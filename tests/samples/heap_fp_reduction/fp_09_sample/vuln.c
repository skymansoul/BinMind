/*
 * FP-09: memcpy 溢出 —— malloc(16) + memcpy 64B
 *
 * 明确的堆溢出: 分配 16B 但 memcpy 64B 数据。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(16);
    if (!buf) return 1;
    // memcpy 64B 到只有 16B 的缓冲区 → 确定溢出
    memcpy(buf,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        64);
    printf("overflow memcpy done\n");
    free(buf);
    return 0;
}
