/* 对齐填充内的写入 — 应该判为 safe (消除 FP).
 *
 * malloc(50) 实际可用 64 字节 (ptmalloc2 对齐到16).
 * offset=56, size=8 → 56+8=64 ≤ usable(50)=64 → 安全.
 * 这是 FP 测试: 检测器若只看请求大小 50(而非 usable 64) 会误报.
 * Expected: TN (allocation-aware → safe)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(50);
    if (!buf) return 1;
    /* usable=64, 56+8=64 → 恰好在边界内 */
    memset(buf + 56, 0, 8);
    free(buf);
    return 0;
}
