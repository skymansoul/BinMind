/*
 * TN-06: Multi-Path Constraint Merging Proves Safety (NO OVERFLOW)
 *
 * malloc(N) 但两条路径约束均保证写入在 [0, N-1] 内
 * Path1: N=128, offset=64 → 安全
 * Path2: N=256, offset=64 → 安全
 * ∀路径安全 → FILTER
 *
 * 正则检测器会误报: 看到动态分配+动态偏移 → 常为溢出
 * LPVRA应判定: SAFE → FILTER (两条路径均可证明安全)
 */
#include <stdlib.h>

int multi_path_safe(int mode) {
    int sz;
    if (mode == 0) {
        sz = 128;
    } else {
        sz = 256;
    }

    char *buf = (char *)malloc(sz);
    if (!buf) return -1;

    /* offset=64 ≤ min(128, 256) → 所有路径安全 */
    buf[64] = 'M';

    free(buf);
    return 0;
}

int main(void) {
    return multi_path_safe(0);
}
