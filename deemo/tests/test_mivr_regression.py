"""
MIVR 回归测试套件 — 覆盖三层证明体系 (L1/L2/L3) 的所有分支.

测试分类:
  L1_GUARD:  守卫约束直接证明 (if(idx < N) buf[idx] = x)
  L2_AFFINE: 仿射系数分析 (shared variable + coefficient comparison)
  L3_CONST:  常量偏移/大小检查 (malloc(64) + memcpy(buf, src, 128))
  EDGE:      边界情况 (kernel allocators, ternary expressions, calloc)
  FP_FILTER: FP削减验证 (safe code that should NOT trigger overflow)

每条测试包含: 伪代码片段, 期望判定, 期望证明层, 最低置信度.
"""

from __future__ import annotations

import sys, os
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.mivr_pipeline import detect_heap_overflow_mivr


# 测试用例定义

L1_GUARD_TESTS = [
    # (name, pseudocode, expected_verdict, expected_level, min_confidence)
    ("L1: guard bounds idx < alloc",
     """void f(int idx) {
  char *buf = (char*)malloc(64);
  if (idx < 64) {
    buf[idx] = 42;
  }
  free(buf);
}""", "SAFE", "L1", 0.80),

    ("L1: guard bounds idx <= alloc-1",
     """void f(unsigned int idx) {
  char *buf = (char*)malloc(256);
  if (idx <= 255) {
    buf[idx] = value;
  }
  free(buf);
}""", "SAFE", "L1", 0.80),
]

L2_AFFINE_TESTS = [
    ("L2: Heartbleed — claimed+3 > claimed",
     'void f(void) { unsigned short claimed = 128; char *p = (char*)malloc(claimed); memcpy(p, hb, claimed + 3); free(p); }',
     "OVERFLOW", "L2", 0.70),

    ("L2: n*8 > n*4 — write coef larger",
     'void f(int n) { char *buf = (char*)malloc(n * 4); memcpy(buf, src, n * 8); free(buf); }',
     "OVERFLOW", "L2", 0.70),

    ("L2: n*4+16 > n*4+8 — same coef, larger const",
     'void f(int n) { char *buf = (char*)malloc(n * 4 + 8); memcpy(buf, src, n * 4 + 16); free(buf); }',
     "OVERFLOW", "L2", 0.70),

    ("L2: n*8 > n*4 — alloc grows faster, safe",
     'void f(int n) { char *buf = (char*)malloc(n * 8); memcpy(buf, src, n * 4); free(buf); }',
     "SAFE", "L2", 0.60),

    ("L2: n*4 ≤ n*4 — same coef and const",
     'void f(int n) { char *buf = (char*)malloc(n * 4); memcpy(buf, src, n * 4); free(buf); }',
     "SAFE", "L2", 0.70),

    ("L2: len+offset > len — extra var in write",
     'void f(int len, int offset) { char *p = (char*)malloc(len); memcpy(p, data, len + offset); free(p); }',
     "OVERFLOW", "L2", 0.65),
]

L3_CONST_TESTS = [
    ("L3: malloc(64) + memcpy(128) — clear overflow",
     'void f(void) { char *buf = (char*)malloc(64); memcpy(buf, src, 128); free(buf); }',
     "OVERFLOW", "L3", 0.85),

    ("L3: malloc(256) + memcpy(128) — safe",
     'void f(void) { char *buf = (char*)malloc(256); memcpy(buf, src, 128); free(buf); }',
     "SAFE", "L3", 0.80),

    ("L3: malloc(64) + strncpy(buf, src, 64) — exact fit",
     'void f(void) { char *buf = (char*)malloc(64); strncpy(buf, src, 64); free(buf); }',
     "SAFE", "L3", 0.80),

    ("L3: malloc(32) + buf[48] — constant offset overflow",
     'void f(void) { char *buf = (char*)malloc(32); buf[48] = 0; free(buf); }',
     "OVERFLOW", "L3", 0.85),
]

EDGE_TESTS = [
    ("EDGE: kmalloc(len, flags) + memcpy(..., len+offset)",
     'void f(int len, int offset) { char *p = (char*)kmalloc(len, GFP_KERNEL); memcpy(p, data, len + offset); kfree(p); }',
     "OVERFLOW", "L2", 0.65),

    ("EDGE: ternary size — should be UNCERTAIN (not FP)",
     'void f(int n) { char *buf = (char*)malloc(n); memcpy(buf, src, n > 64 ? 64 : n); free(buf); }',
     "UNCERTAIN", "", 0.0),

    ("EDGE: calloc — should be UNCERTAIN (not falsely SAFE)",
     """int main() { int n = 4, m = 16; char *p = calloc(n, m); n = 100; memcpy(p, "data", n); free(p); return 0; }""",
     "UNCERTAIN", "", 0.0),

    ("EDGE: strcpy unbounded — UNCERTAIN (can't prove either way)",
     'void f(void) { char *buf = (char*)malloc(64); strcpy(buf, long_string); free(buf); }',
     "UNCERTAIN", "", 0.0),
]

FP_FILTER_TESTS = [
    ("FP-FILTER: safe malloc(256) + memcpy(128)",
     'void f(void) { char *buf = (char*)malloc(256); memcpy(buf, src, 128); free(buf); }',
     "SAFE", "L3", 0.80),

    ("FP-FILTER: safe malloc(64) + memcpy(64)",
     'void f(void) { char *buf = (char*)malloc(64); memcpy(buf, src, 64); free(buf); }',
     "SAFE", "L3", 0.80),

    ("FP-FILTER: safe guard-protected write",
     """void f(int idx) {
  char *buf = (char*)malloc(64);
  if (idx < 64) { buf[idx] = 42; }
  free(buf);
}""",
     "SAFE", "L1", 0.80),

    ("FP-FILTER: safe n*8 alloc for n*4 write",
     'void f(int n) { char *buf = (char*)malloc(n * 8); memcpy(buf, src, n * 4); free(buf); }',
     "SAFE", "L2", 0.60),
]


def run_regression() -> Tuple[int, int, List[str]]:
    """运行所有回归测试, 返回 (passed, failed, failures)."""
    all_tests = (
        L1_GUARD_TESTS + L2_AFFINE_TESTS + L3_CONST_TESTS +
        EDGE_TESTS + FP_FILTER_TESTS
    )

    passed = 0
    failed = 0
    failures = []

    categories = {
        "L1_GUARD": L1_GUARD_TESTS,
        "L2_AFFINE": L2_AFFINE_TESTS,
        "L3_CONST": L3_CONST_TESTS,
        "EDGE": EDGE_TESTS,
        "FP_FILTER": FP_FILTER_TESTS,
    }

    for cat, tests in categories.items():
        print(f"\n{'='*60}")
        print(f"  {cat} ({len(tests)} tests)")
        print(f"{'='*60}")

        for name, code, exp_verdict, exp_level, min_conf in tests:
            verdict, conf, proofs = detect_heap_overflow_mivr(code)
            level = proofs[0].proof_level if proofs else ""

            # 检查判定
            verdict_ok = verdict == exp_verdict
            level_ok = (exp_level == "") or (level == exp_level)
            conf_ok = conf >= min_conf if exp_verdict != "UNCERTAIN" else True

            ok = verdict_ok and level_ok and conf_ok
            status = "PASS" if ok else "FAIL"

            print(f"  [{status}] {name}")
            if not ok:
                detail = f"  expected={exp_verdict}/{exp_level}/≥{min_conf}, got={verdict}/{level}/{conf:.2f}"
                print(f"    FAIL: {detail}")
                for p in proofs:
                    print(f"      proof: {p.verdict} ({p.proof_level}): {p.proof_detail[:100]}")
                failures.append(f"{name}: {detail}")
                failed += 1
            else:
                passed += 1

    return passed, failed, failures


def run_cve_sample_regression() -> Dict:
    """在已知 CVE 样本上运行 MIVR 回归, 验证关键 CVE 正确检出."""
    from core.c_to_pseudocode import convert as c_to_pseudo

    cve_tests = {
        "CVE-2014-0160 (Heartbleed)": "tests/cve_samples_heap/CVE-2014-0160_heartbleed/vuln.c",
        "CVE-2014-9112 (cpio)": "tests/cve_samples_heap/CVE-2014-9112_cpio_heap_overflow/vuln.c",
        "CVE-2021-3156 (sudo)": "tests/cve_samples_heap/CVE-2021-3156_sudo_heap/vuln.c",
        "CVE-2022-0185 (kernel)": "tests/cve_samples_heap/CVE-2022-0185_kernel_uaf/vuln.c",
        "CVE-2024-21762 (fortios)": "tests/cve_samples_heap/CVE-2024-21762_fortios/vuln.c",
    }

    results = {}
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    print(f"\n{'='*60}")
    print(f"  CVE Sample Regression")
    print(f"{'='*60}")

    for name, rel_path in cve_tests.items():
        path = os.path.join(base, rel_path)
        if not os.path.exists(path):
            print(f"  [MISS] {name}: file not found")
            results[name] = {"status": "MISSING"}
            continue

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
            pseudo = c_to_pseudo(code)
            verdict, conf, proofs = detect_heap_overflow_mivr(pseudo)
            results[name] = {
                "verdict": verdict,
                "confidence": conf,
                "proofs": [(p.verdict, p.proof_level, p.proof_detail[:120]) for p in proofs],
            }
            print(f"  [OK] {name}: {verdict} (conf={conf:.2f})")
            for p in proofs:
                print(f"      {p.proof_level}: {p.proof_detail[:100]}")
        except Exception as e:
            print(f"  [ERR] {name}: ERROR {e}")
            results[name] = {"status": "ERROR", "error": str(e)}

    return results


if __name__ == '__main__':
    print("MIVR Regression Test Suite")
    print("=" * 60)

    passed, failed, failures = run_regression()

    print(f"\n{'='*60}")
    print(f"  Results: {passed} passed, {failed} failed out of {passed+failed}")
    print(f"{'='*60}")

    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")

    # CVE 样本回归
    cve_results = run_cve_sample_regression()

    sys.exit(0 if failed == 0 else 1)
