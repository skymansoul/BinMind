// int03_shl_overflow: 左移溢出 → 分配大小被截断
// 模式: 1 << shift 溢出32位范围
// 预期检测: Mode 3 (USHL_OVF) — 左移溢出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int shift = 28;
    if (argc > 1) shift = (unsigned int)atoi(argv[1]);

    // 漏洞: 1 << 28 = 0x10000000 (OK, < UINT32_MAX)
    //       1 << 31 = 0x80000000 (OK)
    //       但若 shift >= 31 且后续乘以8:
    //       (1 << 31) * 8 = 0 (溢出为0)
    // 简化版: alloc_size = 1 << shift, shift >= 28 时有溢出风险
    // shift=30: 1<<30=0x40000000 (OK)
    // shift=31: 1<<31=0x80000000 (仍OK, 但靠近边界)
    // shift=32: 1<<32=0x100000000 > UINT32_MAX → 截断为0 (在32位模式下)
    unsigned int alloc_size = 1 << shift;
    // 使用无符号32位运算模拟
    if (alloc_size < 16) alloc_size = 16; // 防止分配0

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;

    memset(buf, 'X', alloc_size - 1);
    buf[alloc_size - 1] = '\0';
    printf("alloc=%u shift=%u\n", alloc_size, shift);
    free(buf);
    return 0;
}
