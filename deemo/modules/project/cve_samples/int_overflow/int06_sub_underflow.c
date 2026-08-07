// int06_sub_underflow: 减法下溢 → 无符号回绕
// 模式: umin - val < 0, 回绕至极大值
// 预期检测: Mode 6 (USUB_WRAP) — 减法下溢
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int size = 32;
    if (argc > 1) size = (unsigned int)atoi(argv[1]);

    // 漏洞: 若size < 8, size - 8 回绕至极大值
    // size=0: 0-8=0xFFFFFFF8 → malloc极大值
    unsigned int alloc_size = size - 8; // 减去header

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;

    memcpy(buf, "data", 4);
    printf("size=%u alloc=%u\n", size, alloc_size);
    free(buf);
    return 0;
}
