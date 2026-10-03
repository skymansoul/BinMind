// int07_alloc_size_mul: 乘法→malloc 溢出链 (组合漏洞)
// 模式: imul结果直接传给malloc → 分配大小被截断 → 堆溢出
// 预期检测: Mode 2 + Mode 7 (ALLOC_SIZE_MUL) — CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int count = 0x1000000;
    char *p = (char *)malloc(count * 0x100);
    if (!p) return 1;
    memset(p, 'H', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
