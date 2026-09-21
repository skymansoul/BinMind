#!/usr/bin/env python3
"""路径可行性检查样本数据 — 路径条件感知回归测试用例及检查函数."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.path_constraint_pipeline import fcpv_filter
from core.path_feasibility_pipeline import fcpv_pcfc_filter
from core.path_constraint_constraint_types import SafetyLabel

passed = 0
failed = 0
fp_filtered = 0
tp_preserved = 0


def _check_case(name, source, expected_vuln):
    """运行路径约束收集验证-only和路径约束收集验证+路径可行性检查对比测试."""
    global passed, failed, fp_filtered, tp_preserved

    r_fcpv = fcpv_filter(source)
    r_pcfc = fcpv_pcfc_filter(source)

    fcpv_vuln = r_fcpv["has_vuln"]
    pcfc_vuln = r_pcfc["has_vuln"]

    ok = (pcfc_vuln == expected_vuln)
    if ok:
        passed += 1
        if expected_vuln:
            tp_preserved += 1
        else:
            fp_filtered += 1
        pcfc_label = "VULN" if pcfc_vuln else "SAFE"
        print(f"  [PASS] {name}: {pcfc_label}")
    else:
        failed += 1
        exp = "VULN" if expected_vuln else "SAFE"
        pcfc_label = "VULN" if pcfc_vuln else "SAFE"
        reason = r_pcfc["vuln"][0].reason if r_pcfc["vuln"] else "N/A"
        print(f"  [FAIL] {name}: got {pcfc_label}, expected {exp}")
        print(f"         reason: {reason}")


def run_all():
    global passed, failed, fp_filtered, tp_preserved
    passed = 0
    failed = 0
    fp_filtered = 0
    tp_preserved = 0


    print(f"\n{'='*60}")
    print(f"路径可行性检查回归测试: {passed} passed, {failed} failed, "
          f"{passed+failed} total")
    print(f"FP过滤: {fp_filtered}, TP保留: {tp_preserved}")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
