/*
 * FP-08: 真实溢出 —— malloc(32) + store at offset 40
 *
 * 这是真正的堆溢出, 应该被所有检测器检出。
 * 用作对比基线: 确认增强管线不会把真阳性也过滤掉。
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char *buf = malloc(32);
    if (!buf) return 1;
    memset(buf, 'A', 32);
    // 偏移 40 超出 32B 分配, 即使对齐后 (32B) 也超出
    // glibc x86_64 最小 chunk 32B, 但偏移 40 写 4B = 需要 44B
    *(int *)(buf + 40) = 0xdeadbeef;
    printf("overflow write done\n");
    free(buf);
    return 0;
}
