/*
 * FP-11: 条件约束 + malloc —— 仅一条路径溢出
 *
 * if (cond) size = 16; else size = 256;
 * buf = malloc(size);
 * memcpy(buf, data, 128);
 *
 * 在 cond=true 路径上溢出了 (16<128), 在 cond=false 路径上安全。
 * 路径敏感分析应报告存在溢出路径, 而非一概过滤。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int size;
    if (argc > 1) {
        size = 16;   // 危险路径
    } else {
        size = 256;  // 安全路径
    }
    char *buf = malloc(size);
    if (!buf) return 1;
    // 写入 128B, 在 size=16 时溢出
    memset(buf, 'Z', 128);
    printf("conditional path: size=%d, buf[0]=%c\n", size, buf[0]);
    free(buf);
    return 0;
}
