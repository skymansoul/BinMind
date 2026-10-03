"""
UAF 扩展样本集 — 40+样本覆盖路径条件/CVE模拟/工程模式.

样本分类:
  CATEGORY_MUTEX (14): 路径条件互斥 → 路径条件对象生命周期 (Path-Conditioned Object Lifecycle)应过滤为SAFE
  CATEGORY_EARLY (8):  free后early-return → use不可达 → SAFE
  CATEGORY_REAL  (12): 真实UAF, 路径条件对象生命周期 (Path-Conditioned Object Lifecycle)应保持CONFIRMED
  CATEGORY_SAFE  (6):  其他安全模式 (nullify/reassign/different-object)

每个样本: (name, pseudocode, expected_verdict, category)
"""
from typing import List, Tuple

from eval.uaf_cve_samples_part2 import MUTEX_SAMPLES, EARLY_SAMPLES

# REAL_UAF — 真实UAF, 路径条件对象生命周期 (Path-Conditioned Object Lifecycle)应保持CONFIRMED

REAL_UAF_SAMPLES: List[Tuple[str, str, str, str]] = [
    ('cve_real_01', """char *p = malloc(64);
if (cond) {
    free(p);
    *p = 1;
}
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_02', """char *p = malloc(64);
if (error) {
    free(p);
}
*p = 1;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_03', """char *p = malloc(64);
free(p);
*p = 1;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_04', """char *p = malloc(64);
if (a) {
    free(p);
}
if (b) {
    *p = 1;
}
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_05', """char *p = malloc(64);
if (error) {
    free(p);
}
if (error) {
    *p = 1;
}
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_06', """char *p = malloc(64);
char *q = p;
free(p);
*q = 42;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_07', """char *p = malloc(64);
if (cond) {
    free(p);
    return;
}
free(p);
*p = 1;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_08', """char *buf = malloc(128);
free(buf);
buf[0] = 'x';
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_09', """char *ptr = malloc(256);
if (cleanup) {
    free(ptr);
}
ptr->field = 0;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_10', """char *obj = malloc(64);
struct wrapper *w = obj;
free(obj);
w->val = 1;
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_11', """char *data = malloc(128);
if (flag) {
    free(data);
}
memcpy(data, src, 64);
""", 'CONFIRMED', 'REAL_UAF'),

    ('cve_real_12', """char *p = malloc(64);
char *q = p;
char *r = q;
free(q);
*r = 1;
""", 'CONFIRMED', 'REAL_UAF'),
]

# SAFE_PATTERN — 其他安全模式

SAFE_PATTERN_SAMPLES: List[Tuple[str, str, str, str]] = [
    ('cve_safe_01', """char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
}
*p = 1;
""", 'SAFE', 'NULLIFY'),

    ('cve_safe_02', """char *p = malloc(64);
if (error) {
    free(p);
}
p = malloc(128);
*p = 1;
""", 'SAFE', 'REASSIGN'),

    ('cve_safe_03', """char *p = malloc(64);
char *q = malloc(64);
free(p);
*q = 1;
""", 'SAFE', 'DIFF_OBJECT'),

    ('cve_safe_04', """char *p = malloc(64);
char *q = realloc(p, 128);
q[0] = 42;
""", 'SAFE', 'SAFE_REALLOC'),

    ('cve_safe_05', """char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
    return;
}
*p = 1;
""", 'SAFE', 'NULLIFY_RET'),

    ('cve_safe_06', """char *p = malloc(64);
free(p);
p = malloc(64);
*p = 1;
""", 'SAFE', 'IMMEDIATE_REASSIGN'),
]

ALL_UAF_CVE_SAMPLES = (MUTEX_SAMPLES + EARLY_SAMPLES
                       + REAL_UAF_SAMPLES + SAFE_PATTERN_SAMPLES)


def get_sample_count() -> int:
    return len(ALL_UAF_CVE_SAMPLES)


def get_category_stats() -> dict:
    cats = {}
    for _, _, _, cat in ALL_UAF_CVE_SAMPLES:
        cats[cat] = cats.get(cat, 0) + 1
    return cats


__all__ = [
    'MUTEX_SAMPLES', 'EARLY_SAMPLES',
    'REAL_UAF_SAMPLES', 'SAFE_PATTERN_SAMPLES',
    'ALL_UAF_CVE_SAMPLES',
    'get_sample_count', 'get_category_stats',
]
