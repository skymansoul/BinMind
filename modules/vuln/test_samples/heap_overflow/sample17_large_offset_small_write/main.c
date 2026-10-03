/* 大偏移小写入 — offset 很大但仍在范围内.
 *
 * malloc(2112) → usable ≥ 2112, offset=2048, size=8 → 2056 ≤ 2112 → safe.
 * 这是 FP 测试: 检测器看到 offset=2048 (很大) 可能误判.
 * Expected: TN (large offset ≤ alloc → safe)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(2112);
    if (!buf) return 1;
    /* 2048+8=2056 ≤ 2112 → safe */
    memset(buf + 2048, 0, 8);
    free(buf);
    return 0;
}
