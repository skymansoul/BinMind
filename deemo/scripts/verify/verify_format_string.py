#!/usr/bin/env python3
"""
格式化字符串漏洞自动化验证 - 检测→偏移计算→利用建议 链路测试。

与栈溢出的单函数分析不同，格式化字符串检测需要扫描整个二进制
（漏洞可能出现在任意调用 printf 系列的路径上）。本脚本验证:
  1. 静态模式匹配的召回率（是否找到所有 printf(user_var) 调用）
  2. 偏移计算的精度（与手工 %p 爆破结果比对）
  3. LLM 增强对置信度的影响

用法:
  python scripts/verify/verify_format_string.py <binary_path> [--expected-offset N]
  python scripts/verify/verify_format_string.py samples/teaching/vuln_fmtstr --expected-offset 6

依赖:
  BinMind 已安装，radare2 在 PATH
"""

import argparse
import json
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(
        description="验证格式化字符串检测链路"
    )
    parser.add_argument("binary", help="目标 ELF 二进制路径")
    parser.add_argument(
        "--expected-offset", type=int, default=0,
        help="手工爆破得出的预期偏移（用于精度对比）"
    )
    parser.add_argument(
        "--use-llm", action="store_true",
        help="启用 LLM 增强分析（需要 API key）"
    )
    parser.add_argument(
        "--output-dir", default="./verify_results",
        help="验证结果输出目录"
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        print(f"[FAIL] 二进制文件不存在: {binary_path}", file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    results: dict = {
        "binary": binary_path,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stages": {},
        "overall": "unknown",
    }

# Stage 1: checksec (格式化字符串漏洞在高防护下仍有利用价值)
    t0 = time.time()
    from core.checksec import detect_checksec, checksec_summary
    checksec = detect_checksec(binary_path)
    results["stages"]["checksec"] = {
        "elapsed": round(time.time() - t0, 2),
        "summary": checksec_summary(checksec),
    }
    print(f"  [checksec] {checksec_summary(checksec)}")

# Stage 2: static detection
    t0 = time.time()
    from core.format_string_detector import detect_format_string_vulns
    # 先不用 LLM，获得纯静态基线
    findings_static = detect_format_string_vulns(
        binary_path, use_llm=False,
    )
    results["stages"]["static"] = {
        "elapsed": round(time.time() - t0, 2),
        "findings_count": len(findings_static),
        "findings": [
            {
                "function": f["function"],
                "format_func": f["format_func"],
                "format_arg": f["format_arg"],
                "offset": f["offset"],
                "confidence": f["confidence"],
            }
            for f in findings_static
        ],
    }
    print(f"  [static] {len(findings_static)} potential format string vuln(s)")
    for f in findings_static:
        print(
            f"    {f['function']}: {f['format_func']}({f['format_arg']})"
            f" offset={f['offset']} conf={f['confidence']:.2f}"
        )

# Stage 3: LLM enhancement (optional)
    if args.use_llm and findings_static:
        t0 = time.time()
        findings_llm = detect_format_string_vulns(
            binary_path, use_llm=True,
        )
        results["stages"]["llm_enhanced"] = {
            "elapsed": round(time.time() - t0, 2),
            "findings_count": len(findings_llm),
        }
        # 对比置信度变化
        for i, f_llm in enumerate(findings_llm):
            if i < len(findings_static):
                delta = f_llm["confidence"] - findings_static[i]["confidence"]
                results["stages"]["llm_enhanced"][
                    f"confidence_delta_{f_llm['function']}"
                ] = round(delta, 2)
        print(f"  [llm] {len(findings_llm)} findings after LLM enhancement")

# Stage 4: offset validation
    if args.expected_offset > 0 and findings_static:
        offsets = [f["offset"] for f in findings_static if f["offset"] > 0]
        if offsets:
            closest = min(offsets, key=lambda o: abs(o - args.expected_offset))
            deviation = abs(closest - args.expected_offset)
            offset_ok = deviation <= 2  # x86_64 偏移估算允许 ±2 的误差
            results["stages"]["offset_validation"] = {
                "expected": args.expected_offset,
                "closest_detected": closest,
                "deviation": deviation,
                "ok": offset_ok,
            }
            status = "[OK]" if offset_ok else f"[OFF by {deviation}]"
            print(
                f"  [offset] expected={args.expected_offset}"
                f" detected={closest} {status}"
            )

# Summary
    _print_summary(results, findings_static)
    results_path = os.path.join(args.output_dir, "verify_format_string.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {results_path}")
    return 0 if results["overall"] == "pass" else 1


def _print_summary(results, findings):
    checks = []
    checks.append(("checksec", bool(results["stages"].get("checksec"))))
    checks.append(("static_detection", len(findings) > 0))

    offset_val = results["stages"].get("offset_validation", {})
    if offset_val:
        checks.append(("offset_accuracy", offset_val.get("ok", False)))

    all_ok = all(p for _, p in checks)
    results["overall"] = "pass" if all_ok else "partial"

    print(f"\n  {'='*40}")
    print(f"  验证结果: {'PASS' if all_ok else 'PARTIAL'}")
    for name, passed in checks:
        print(f"    [{'OK' if passed else 'FAIL'}] {name}")
    print(f"  {'='*40}")


if __name__ == "__main__":
    sys.exit(main())
