/*
 * FP_safe_bound_guard — 显式边界守卫保护的安全分配
 * 堆溢出检测器的典型误报场景:
 *   - malloc(n) + memcpy(buf, src, n) 看起来可疑
 *   - 但 n 已被 if (n > BUF_SIZE) n = BUF_SIZE 守卫
 *   - 写入大小 ≤ 分配大小, 可证安全
 *
 * GAPSBV Tier 行为:
 *   Tier 0: alloc=n vs write=n, 若 n 未约束则 POSSIBLE
 *   Tier 1: AffineInterval(n) 在 PathCondition{n≤4096} 下, write=n ≤ alloc=n
 *   Tier 2: 符号化 n, 约束下 unsat → SAFE
 *   Tier 3: 检测到 if(n > BUF_SIZE) n = BUF_SIZE 边界守卫 → FILTER
 *
 * 期望: BinMind-enhanced 应 FILTER (FP suppression),
 *       BinMind-baseline 可能报告 (无路径/守卫分析)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUF_SIZE 4096

static int safe_process(const char *src, int user_size) {
    int n = user_size;

    /* 显式边界守卫 — 确保 n 不超过 BUF_SIZE */
    if (n > BUF_SIZE) {
        n = BUF_SIZE;                     /* Tier 3 守卫检测 */
    }

    char *buf = malloc(n);                /* alloc = n (≤ 4096) */
    if (!buf) return -1;

    memcpy(buf, src, n);                  /* write = n = alloc → SAFE */

    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return safe_process(argv[1], strlen(argv[1]));
}
