/*
 * sample_06 — 循环中动态索引导致的堆溢出.
 *
 * 漏洞: 循环次数取决于外部输入(此处简化为常量), 但每次迭代
 * 写入偏移超出分配大小.
 *
 * 静态分析难点: 循环展开分析需要推断归纳变量的上界.
 * 此样本测试 SVSA 对 [0, n*M] strided interval 的建模.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_ITEMS 40
#define ITEM_SIZE 8

int main(void) {
    /* 只分配 32 个元素的空间 */
    char *buf = (char *)malloc(32 * ITEM_SIZE);
    if (!buf) return 1;

    /* 但循环写入 40 个元素 → 溢出 8*8=64 字节 */
    for (int i = 0; i < N_ITEMS; i++) {
        memset(buf + i * ITEM_SIZE, (char)i, ITEM_SIZE);
    }

    printf("buf[0] = %d\n", buf[0]);
    free(buf);
    return 0;
}
