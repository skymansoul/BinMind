# coding: utf-8
# 创建: 2026-04-15  |  UAF 语料数据 C——TN 安全样本
#
"""UAF TN 样本数据 (误报削减目标). 仅数据, 无逻辑."""

SAMPLES_UAF_SAFE = [
    {
        "id": "uaf_safe_realloc_reuse",
        "cve": "None (synthetic)",
        "title": "Legitimate reuse after free (malloc reuse)",
        "pattern": "free(p); p=malloc(64); use(p)",
        "trigger": "无 — p 已指向新对象",
        "why": "free 与 use 归因到不同对象 (obj#1 vs obj#2) → R2 SAFE; 旧检测器误报 UAF",
        "code": r'''/* uaf_safe_realloc_reuse — free 后 malloc 复用 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);       /* new object, same slot */
    if (!p) return 1;
    int v = p[0];                 /* deref of new object */
    free(p);
    return v;
}
''',
    },
    {
        "id": "uaf_safe_other_object",
        "cve": "None (synthetic)",
        "title": "Use of a different live object after free",
        "pattern": "malloc A, malloc B; free(A); use(B)",
        "trigger": "无 — 解引用对象 B 仍存活",
        "why": "free→objA, use→objB, 身份不同 → R2 SAFE",
        "code": r'''/* uaf_safe_other_object — free A 后使用 B (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    int *a = (int *)malloc(64);
    int *b = (int *)malloc(64);
    if (!a || !b) return 1;
    free(a);
    return b[0];                  /* b still live */
}
''',
    },
    {
        "id": "uaf_safe_use_before_free",
        "cve": "None (synthetic)",
        "title": "Dereference precedes free (no UAF)",
        "pattern": "use(p); free(p)",
        "trigger": "无 — 解引用在 free 之前",
        "why": "配对仅考虑 free 之后解引用; 之前的不成对",
        "code": r'''/* uaf_safe_use_before_free — 先使用后释放 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(64);
    if (!p) return 1;
    int v = p[0];                 /* use before free */
    free(p);
    return v;
}
''',
    },
    {
        "id": "uaf_safe_no_use",
        "cve": "None (synthetic)",
        "title": "Free without any subsequent dereference",
        "pattern": "malloc → free",
        "trigger": "无 — free 后无解引用",
        "why": "无 free→use 对 → 不检出",
        "code": r'''/* uaf_safe_no_use — free 后无使用 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    return 0;
}
''',
    },
]
