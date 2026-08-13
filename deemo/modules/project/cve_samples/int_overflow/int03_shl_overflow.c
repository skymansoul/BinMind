// int03_shl_overflow: 左移溢出 → 分配大小被截断
// 模式: 1 << shift 溢出32位范围
// 预期检测: Mode 3 (USHL_OVF) — 左移溢出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int v = 0x40000000;
    v <<= 3;
    printf("%u\n", v);
    return 0;
}
