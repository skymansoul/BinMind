/*
 * TN-05: Dynamic Allocation with Loop Bounded by Size (NO OVERFLOW)
 *
 * malloc(sz) → for i < sz → 循环上界 = 分配大小 → 安全
 * 循环计数器不超过分配范围 → 无溢出
 *
 * 正则检测器会误报: 动态大小malloc + 动态偏移 → 默认真阳性
 * LPVRA应判定: SAFE → FILTER (loop bound = alloc_lo)
 */
#include <stdlib.h>

int fill_exact(int sz) {
    char *buf = (char *)malloc(sz);
    if (!buf) return -1;

    /* 循环上界 = sz → 写入 [0, sz-1] 全部在边界内 */
    for (int i = 0; i < sz; i++) {
        buf[i] = 0x48;
    }

    free(buf);
    return 0;
}

int main(void) {
    return fill_exact(256);
}
