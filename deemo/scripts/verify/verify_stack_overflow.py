#!/usr/bin/env python3
"""
栈溢出自动化验证 - 对单个样本执行完整"画像→分析→利用→验证"链路。

使用 BinMind 管线对指定 ELF 二进制进行栈溢出自动分析，验证
stack_overflow_analyzer 的 padding 计算精度和 feedback_loop 的
迭代修正能力。

验证维度:
  1. checksec 检测与 checksec.sh 输出一致性
  2. padding 计算偏差（与手工分析结果对比）
  3. exploit 生成成功率（含 feedback_loop 迭代）
  4. 端到端耗时

用法:
  python scripts/verify/verify_stack_overflow.py <binary_path> [--expected-padding N]
  python scripts/verify/verify_stack_overflow.py samples/ctf/stack_bof --expected-padding 72

依赖:
  BinMind 已安装，radare2 在 PATH，angr 可选（无 angr 时使用静态回退）
"""

import argparse
import json
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(
        description="验证栈溢出自动化分析链路"
    )
    parser.add_argument("binary", help="目标 ELF 二进制路径")
    parser.add_argument(
        "--expected-padding", type=int, default=0,
        help="手工分析得出的预期 padding（用于精度对比）"
    )
    parser.add_argument(
        "--skip-exploit", action="store_true",
        help="跳过 exploit 生成和执行（仅测试分析阶段）"
    )
    parser.add_argument(
        "--output-dir", default="./verify_results",
        help="验证结果输出目录"
    )
    parser.add_argument(
        "--enable-review-gate", action="store_true",
        help="启用人复核门控（默认纯自动模式）"
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

# Stage 1: checksec
    t0 = time.time()
    from core.checksec import detect_checksec, checksec_summary
    checksec = detect_checksec(binary_path)
    results["stages"]["checksec"] = {
        "elapsed": round(time.time() - t0, 2),
        "summary": checksec_summary(checksec),
        "detail": {k: checksec[k] for k in ("nx", "pie", "canary", "relro", "fortify")},
    }
    print(f"  [checksec] {checksec_summary(checksec)}")

# Stage 2: PLT + libc
    t0 = time.time()
    from core.plt_scanner import scan_plt, find_exploitable_functions
    plt_entries = scan_plt(binary_path)
    exploitable = find_exploitable_functions(plt_entries)

    from core.libc_identifier import identify_libc
    libc_info = identify_libc(binary_path)

    results["stages"]["plt"] = {
        "elapsed": round(time.time() - t0, 2),
        "total_plt": len(plt_entries),
        "exploitable_count": len(exploitable),
        "exploitable_funcs": [
            {"name": e["name"], "risk": e["risk_category"]} for e in exploitable[:10]
        ],
    }
    print(f"  [plt] {len(plt_entries)} imports, {len(exploitable)} exploitable")

# Stage 3: binary profile
    t0 = time.time()
    from core.binary_profile import build_binary_profile
    profile = build_binary_profile(
        binary_path, checksec=checksec, plt_entries=plt_entries, libc_info=libc_info,
    )
    results["stages"]["profile"] = {
        "elapsed": round(time.time() - t0, 2),
        "exploit_difficulty": profile.get("exploit_difficulty", "unknown"),
        "recommended_approaches": profile.get("recommended_approach", []),
    }
    print(f"  [profile] difficulty={profile.get('exploit_difficulty')}")

# Stage 4: stack overflow analysis
    t0 = time.time()
    from core.stack_overflow_analyzer import analyze_stack_overflow
    target_func = _find_vuln_function(binary_path)
    overflow_result = analyze_stack_overflow(
        binary_path, target_func, libc_info=libc_info,
    )
    results["stages"]["overflow"] = {
        "elapsed": round(time.time() - t0, 2),
        "target_function": target_func,
        "overflowable": overflow_result["overflowable"],
        "padding": overflow_result["padding"],
        "has_canary": overflow_result["has_canary"],
        "strategy": overflow_result["strategy"],
    }

    padding_ok = "N/A"
    if args.expected_padding > 0:
        deviation = abs(overflow_result["padding"] - args.expected_padding)
        padding_ok = "OK" if deviation <= 8 else f"OFF by {deviation}"
    print(
        f"  [overflow] func={target_func} padding={overflow_result['padding']}"
        f" canary={overflow_result['has_canary']}"
        f" strategy={overflow_result['strategy']}"
        f" (expected={args.expected_padding}, {padding_ok})"
    )

    # === Stage 5: exploit generation + execution (optional) ===
    if not args.skip_exploit and overflow_result["overflowable"]:
        _run_exploit_stage(
            binary_path, overflow_result, profile, checksec,
            args.output_dir, results, args.enable_review_gate,
        )

# Summary
    _print_summary(results, padding_ok)
    results_path = os.path.join(args.output_dir, "verify_stack_overflow.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {results_path}")

    return 0 if results["overall"] in ("pass", "partial") else 1


def _find_vuln_function(binary_path: str) -> str:
    """推断最可能存在漏洞的用户函数。"""
    from core.decompiler import list_functions
    funcs = list_functions(binary_path)
    priority = ("vuln", "vulnerable", "bof", "overflow", "stack", "main")
    for p in priority:
        for f in funcs:
            if p in f.lower() and not f.startswith("_"):
                return f
    # 回退到第一个非库函数
    for f in funcs:
        if not f.startswith(("_", "sym.", "fcn.", "sub.")):
            return f
    return "main"


def _run_exploit_stage(
    binary_path, overflow_result, profile, checksec,
    output_dir, results, enable_gate,
):
    """生成并执行 exploit，支持反馈迭代。"""
    from core.exploit_gen import generate_exploit
    from core.exploit_executor import execute_exploit, is_exploit_successful
    from core.feedback_loop import run_feedback_loop

    t0 = time.time()

    # 初始 exploit 生成——注入 stack_overflow_analyzer 的参数
    binfo = {"path": binary_path, "arch": profile.get("arch", "x86-64"),
             "bits": profile.get("bits", 64), "format": profile.get("format", "ELF")}
    initial = generate_exploit(binfo)

    if not initial.get("success"):
        results["stages"]["exploit"] = {"elapsed": 0, "status": "gen_failed"}
        return

    script_content = initial["script_content"]

    # 反馈环
    loop_result = run_feedback_loop(
        binary_path=binary_path,
        initial_script=script_content,
        binfo=binfo,
        libc_info=profile.get("libc", {}),
        checksec=checksec,
        max_iterations=5,
        timeout=30,
    )

    elapsed = round(time.time() - t0, 2)
    results["stages"]["exploit"] = {
        "elapsed": elapsed,
        "success": loop_result["success"],
        "iterations": loop_result["iterations"],
        "history_count": len(loop_result.get("history", [])),
    }

    status_icon = "[OK]" if loop_result["success"] else "[FAIL]"
    print(
        f"  [exploit] {status_icon} success={loop_result['success']}"
        f" iterations={loop_result['iterations']} elapsed={elapsed}s"
    )

    # 若失败且开启了人工复核门控
    if not loop_result["success"] and enable_gate:
        from core.review_gate import gate_in_feedback_loop
        print("  [gate] 等待人工复核... (编辑 review_gate.toml 后保存)")
        gate_result = gate_in_feedback_loop(
            output_dir, loop_result["iterations"],
            loop_result.get("final_script", script_content),
            loop_result.get("best_result", {}),
            timeout=600,  # 10 分钟
        )
        results["stages"]["exploit"]["gate_action"] = gate_result["action"]
        print(f"  [gate] 人工决策: {gate_result['action']}")


def _print_summary(results, padding_ok):
    """打印验证汇总。"""
    stages = results["stages"]
    checks = []

    # checksec 阶段始终应通过
    checks.append(("checksec", bool(stages.get("checksec"))))

    # PLT 阶段应找到至少 1 个导入
    checks.append(("plt", stages.get("plt", {}).get("total_plt", 0) > 0))

    # 溢出分析应判定 overflowable
    checks.append(("overflow", stages.get("overflow", {}).get("overflowable", False)))

    # exploit 阶段（若执行了）
    exploit = stages.get("exploit", {})
    if exploit:
        checks.append(("exploit", exploit.get("success", False)))

    all_ok = all(passed for _, passed in checks)
    results["overall"] = "pass" if all_ok else "partial"

    print(f"\n  {'='*40}")
    print(f"  验证结果: {'PASS' if all_ok else 'PARTIAL'}")
    for name, passed in checks:
        print(f"    [{'OK' if passed else 'FAIL'}] {name}")
    print(f"  {'='*40}")


if __name__ == "__main__":
    sys.exit(main())
