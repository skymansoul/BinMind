# coding: utf-8
# 创建: 2026-06-01  |  语料数据 C——TN 安全样本
#
"""TN 样本数据 (误报削减目标). 仅数据, 无逻辑."""

SAMPLES_SAFE = [
    {
        "id": "safe_guard_bounded",
        "cve": "None (synthetic)",
        "title": "Guard-bounded write — 有界守卫保护",
        "pattern": "malloc(64); if (len<=64) memcpy(buf, src, len)",
        "trigger": "无 — 写入仅在 len<=64 时执行",
        "why": "守卫窗口证明 write <= 64 <= usable; 旧检测器对变长写入保守保留 → FP",
        "code": r'''/* safe_guard_bounded — 有界守卫保护 (TN, 误报削减目标)。
 * 守卫 len<=64 保证写入不越界。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 32;
    if (argc > 1) len = strlen(argv[1]);
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (len <= 64) {                      /* 有界守卫 */
        memcpy(buf, argv[1], len);
    }
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "safe_alloc_controllable",
        "cve": "None (synthetic)",
        "title": "Shared-source alloc/write — 分配与写入同源",
        "pattern": "malloc(n); memcpy(buf, src, n)",
        "trigger": "无 — 写入量 == 分配量 (同一变量)",
        "why": "alloc/write 同源变量 → 同一定值根/共享来源证明安全; 旧检测器对参数化大小保守保留 → FP",
        "code": r'''/* safe_alloc_controllable — 分配与写入同源 (TN)。
 * memcpy 写入量与 malloc 大小相同变量 n。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void copy_n(size_t n, char *dst, const char *src) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    memcpy(buf, src, n);                  /* 同源 → 安全 */
    free(buf);
    (void)dst;
}

int main(int argc, char **argv) {
    size_t n = 48;
    if (argc > 1) n = strlen(argv[1]);
    copy_n(n, argv[2], argv[3]);
    return 0;
}
''',
    },
    {
        "id": "safe_alignment_padding",
        "cve": "None (synthetic)",
        "title": "Allocator alignment padding write — 对齐 padding 内写入",
        "pattern": "malloc(17) 后 memcpy(20)",
        "trigger": "无 — 20 <= usable(17)=24",
        "why": "glibc 对齐 padding 内写入合法; 旧检测器直接比较 20>17 → FP",
        "code": r'''/* safe_alignment_padding — 对齐 padding 内写入 (TN)。
 * malloc(17) 实际可用 24, 写入 20 合法。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(17);
    if (!buf) return 1;
    char src[24];
    memset(src, 'F', sizeof(src));
    memcpy(buf, src, 20);                 /* padding 区内 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "safe_disjoint_allocs",
        "cve": "None (synthetic)",
        "title": "Disjoint allocations — 多分配点指针各归其主",
        "pattern": "malloc(64)+malloc(32); 各按其分配大小写入",
        "trigger": "无 — 每次写入均不超其目标分配",
        "why": "旧检测器以'最后一次分配'为基准 → buf1 写入 64 与 alloc#2(32) 比较 → FP; GASRI 按 dst 关联正确配对",
        "code": r'''/* safe_disjoint_allocs — 多分配点指针混淆 (TN)。
 * buf1(64) 写 64, buf2(32) 写 32, 均安全。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf1 = (char *)malloc(64);
    char *buf2 = (char *)malloc(32);
    if (!buf1 || !buf2) return 1;
    memset(buf1, 'G', 64);                /* 恰达 buf1 边界 */
    memset(buf2, 'H', 32);                /* 恰达 buf2 边界 */
    free(buf1);
    free(buf2);
    return 0;
}
''',
    },
]
