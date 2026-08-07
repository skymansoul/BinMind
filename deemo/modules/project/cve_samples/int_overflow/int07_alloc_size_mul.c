// int07_alloc_size_mul: 乘法→malloc 溢出链 (组合漏洞)
// 模式: imul结果直接传给malloc → 分配大小被截断 → 堆溢出
// 预期检测: Mode 2 + Mode 7 (ALLOC_SIZE_MUL) — CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int n = 0x1000000;  // 16M
    unsigned int elem = 256;     // 每个元素256字节
    if (argc > 1) n = (unsigned int)atoi(argv[1]);

    // 漏洞: n * elem = 0x1000000 * 256 = 0x100000000
    //       > UINT32_MAX → 截断为 0
    // malloc(0) 可能返回一个小的有效指针
    size_t alloc = (size_t)(n * elem);
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;

    // 期望分配16M*256=4G, 实际分配可能只有几个字节
    for (unsigned int i = 0; i < n; i++) {
        buf[i * elem] = 'X';  // 堆溢出
    }
    free(buf);
    return 0;
}
