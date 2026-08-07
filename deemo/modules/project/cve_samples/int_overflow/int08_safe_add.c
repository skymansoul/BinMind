// int08_safe_add: 安全加法 — 有边界检查保护
// 模式: 加法后检查溢出, 提前返回
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int size = 1024;
    if (argc > 1) size = (unsigned int)atoi(argv[1]);

    // 安全: 溢出检查
    if (size > 0xFFFFFFFF - 32) {
        printf("size too large\n");
        return 1;
    }

    unsigned int padded = size + 32;
    char *buf = (char *)malloc(padded);
    if (!buf) return 1;

    memset(buf, 0, size);
    free(buf);
    return 0;
}
