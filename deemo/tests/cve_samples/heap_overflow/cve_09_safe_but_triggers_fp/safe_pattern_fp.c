/*
 * CVE-09: 安全模式但触发浅层分析的误报
 *
 * 场景: malloc(20) → store at offset 24.
 * 浅层分析: 20 < 24 → 报告溢出.
 * 实际: glibc 对齐后 malloc(20) 的实际 usable 为 32B (min_chunk=32, header=16),
 *       usable = 32-16 = 16... 不对, request2size 后 chunk_size = max(32, align_up(20+16, 16))
 *       = max(32, 32) = 32B chunk, usable = 32 - 16 = 16B.
 *       但考虑 alignment: 20B 请求 + 16B header = 36B, align_up(36, 16) = 48B chunk,
 *       usable = 48 - 16 = 32B. 所以 offset=24 < 32 — 安全!
 *
 * 更精确: glibc request2size(20) = align_up(20+16+8-1, 16) = align_up(35,16) = 48
 *          chunk_size = 48, usable = 48 - 2*8 = 32 (减去 prev_size 和 size 字段)
 *          所以 malloc(20) 实际可用 32B. offset 24 写入 8B (到 32) 刚好在边界内.
 *
 * 预期: 分配器语义过滤 (Phase 0) 应识别为安全, 滤除此误报.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(20);
    if (!buf) return 1;

    // offset 24 < usable 32 → 安全 (但浅层分析会误报)
    *(long *)(buf + 24) = 0x4242424242424242L;

    printf("safe write done (no overflow)\n");
    free(buf);
    return 0;
}
