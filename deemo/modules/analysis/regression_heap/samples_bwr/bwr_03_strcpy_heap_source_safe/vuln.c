/*
 * BWR-03: strcpy 堆源安全
 *
 * 源为 malloc(32) 的堆缓冲区, 目标 malloc(64).
 * BWR 通过栈槽别名解析到源分配, 恢复上界 32 ≤ 可用区 64 → 安全.
 * 这是"分配=写入"的跨函数变体, 区间分析会因宽化产生误报.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *src = (char *)malloc(32);
    char *dst = (char *)malloc(64);
    if (!src || !dst) return 1;
    memset(src, 'A', 32);
    src[31] = 0;
    strcpy(dst, src);
    printf("%s\n", dst);
    free(src);
    free(dst);
    return 0;
}
