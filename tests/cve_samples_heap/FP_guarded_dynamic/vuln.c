/*
 * FP_guarded_dynamic: False Positive — 动态分配, 写入受守卫保护.
 *
 * GAPSBV S2 (GuardAwareWrites) 应识别:
 *   1. malloc(n) — 分配大小动态 (S1 无法静态判断安全)
 *   2. if (idx < n) guard — 索引受 n 约束
 *   3. memcpy(buf+idx, ...) — 写入偏移依赖 idx
 *   → 守卫边界 n 等于分配大小 n, 写入安全.
 *
 * S1 (AllocatorSemantics) 无法处理动态 alloc, 保留候选.
 * S2 检测 if-guard 并硬过滤.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_guarded(int n, int idx, const char *src) {
    if (n <= 0 || idx < 0) return;

    char *buf = (char *)malloc(n);
    if (!buf) return;

    /* S2: idx 受 n 约束 → 写入安全 */
    if (idx < n) {
        memcpy(buf + idx, src, 1);
    }

    free(buf);
}

int main(void) {
    char data = 'X';
    process_guarded(64, 10, &data);
    return 0;
}
