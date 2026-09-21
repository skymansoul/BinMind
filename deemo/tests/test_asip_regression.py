#!/usr/bin/env python3
"""
ASIP堆溢出检测回归测试 — 验证55个CVE样本的检出与误报过滤.

测试策略:
  源码级逻辑溢出判定: 按逻辑分配大小判定, 不依赖约束求解 solver的物理chunk模型.
  VULN样本: 逻辑write_end > 逻辑alloc_size → 检出
  SAFE样本: 逻辑write_end <= 逻辑alloc_size → 过滤
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from eval.asip_cve_samples import ALL_SAMPLES
from core.asip_source_detector import extract_candidates_v3
from core.asip_source_pipeline import asip_source_enhance

passed = 0
failed = 0


def detect_vuln(source, use_asip=False):
    """源码级逻辑溢出判定: 按逻辑大小判定, 不依赖物理chunk模型."""
    candidates = extract_candidates_v3(source)

    if use_asip:
        candidates, _ = asip_source_enhance(source, candidates)

    return len(candidates) > 0


def test_asip():
    global passed, failed
    passed = 0
    failed = 0

    for name, source, expected in ALL_SAMPLES:
        expected_vuln = (expected == 'VULN')
        detected = detect_vuln(source, use_asip=True)

        ok = (detected == expected_vuln)
        if ok:
            passed += 1
            label = 'VULN' if detected else 'SAFE'
            print(f"  [PASS] {name}: {label}")
        else:
            failed += 1
            exp = 'VULN' if expected_vuln else 'SAFE'
            got = 'VULN' if detected else 'SAFE'
            print(f"  [FAIL] {name}: got {got}, expected {exp}")

    print(f"\n{'='*60}")
    print(f"ASIP回归测试: {passed} passed, {failed} failed, "
          f"{passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = test_asip()
    sys.exit(0 if ok else 1)
