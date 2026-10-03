# 格式化字符串扫描调度模块.
#
# 决策逻辑:
#   对 build/manifest_build.json 中每个编译产物做 objdump 反汇编,
#   定位 printf 族调用点, 分两条线判定:
#     - baseline: 格式串寄存器的最后定义非 lea[rip]/立即数即告警 (旧启发式).
#     - enhanced: FmtArgVerifier 后向定义链三级判定, 仅 CONFIRMED 计入.
#   量化 FAPV 来源验证的误报抑制贡献.
#

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
BUILD_MANIFEST = ROOT / "build" / "manifest_build.json"


def _ensure_paths():
    deemo = ROOT.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent),
              str(ROOT.parent / "regression_fmt")):
        if p not in sys.path:
            sys.path.insert(0, p)


def classify(gt: str, detected: bool) -> str:
    if gt == "vulnerable":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def scan_binary_fmt(binary: str):
    """扫描单个二进制, 返回 (verdicts, baseline_detected, enhanced_detected)."""
    from modules.analysis.static.disasm_util import (
        disassemble_binary, extract_func_name, norm_reg)
    from fmt_env import PRINTF_FAMILY, FMT_ARG_IDX, ARG_REGS_WIN64, ARG_REGS_SYSV
    from fmt_verdict import FmtArgVerifier

    instructions, fmt, _m, ranges = disassemble_binary(binary)
    if not instructions:
        return [], False, False, "disasm failed"
    use_win64 = "pei" in fmt.lower()
    args = ARG_REGS_WIN64 if use_win64 else ARG_REGS_SYSV
    verifier = FmtArgVerifier(instructions, use_win64=use_win64)

    idx_map = {ins.get("address", i): i
               for i, ins in enumerate(instructions)}
    baseline_detected = False
    enhanced_detected = False
    verdicts = []

    for ins in instructions:
        if ins.get("mnemonic", "").lower() != "call":
            continue
        ops = ins.get("operands", [])
        if not ops:
            continue
        func = extract_func_name(ops[0])
        base = func.replace("__mingw_", "")
        if func.startswith("__mingw") and base.startswith("v"):
            base = base[1:]
        if base not in PRINTF_FAMILY and func not in PRINTF_FAMILY:
            continue
        if base not in FMT_ARG_IDX:
            continue
        addr = ins.get("address", 0)
        # 仅用户代码: CRT 内部 fprintf->vfprintf 链会引入参数槽误报.
        if ranges and not any(lo <= addr < hi for lo, hi in ranges):
            continue
        fmt_idx = FMT_ARG_IDX[base]
        fmt_reg = args[fmt_idx] if fmt_idx < len(args) else None
        if fmt_reg is None:
            continue

        if _baseline_literal(instructions, idx_map, addr, fmt_reg):
            base_hit = False
        else:
            base_hit = True
        verdict, reason = verifier.verify(addr, func)
        verdicts.append({"address": addr, "func": func,
                         "verdict": verdict, "reason": reason,
                         "baseline_hit": base_hit})
        baseline_detected = baseline_detected or base_hit
        enhanced_detected = enhanced_detected or \
            (verdict == "confirmed")
    return verdicts, baseline_detected, enhanced_detected, ""


def _baseline_literal(instructions, idx_map, call_addr, fmt_reg) -> bool:
    """旧启发式: fmt 寄存器最后定义若为 lea[rip]/立即数则视为字面量."""
    idx = idx_map.get(call_addr)
    if idx is None:
        return False
    for j in range(idx - 1, max(0, idx - 12) - 1, -1):
        ins = instructions[j]
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if len(ops) < 2:
            continue
        dst = _norm(ops[0])
        if dst != _norm(fmt_reg):
            continue
        src = ops[1].strip()
        if mnem in ("lea",):
            return "rip" in src.lower()
        if mnem in ("mov", "movabs"):
            if src.startswith("0x") or src.isdigit():
                return True
            if "rip" in src.lower():
                return True
            return False
        if mnem == "call":
            return False
    return False


def _norm(op: str) -> str:
    return op.strip().lower().lstrip("%").lstrip("$")


def scan_all() -> list:
    _ensure_paths()
    if not BUILD_MANIFEST.exists():
        print(f"build manifest not found: {BUILD_MANIFEST}. "
              "Run compile_fmt.py first.")
        return []
    manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
    results = []
    for sample in manifest:
        sid = sample["sample_id"]
        gt = sample["ground_truth"]
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            binary = rec.get("binary", "")
            if not rec.get("compiled") or not os.path.exists(binary):
                continue
            t0 = time.perf_counter()
            verdicts, bdet, edet, err = scan_binary_fmt(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            results.append({
                "sample_id": sid, "cve": sample.get("cve", ""),
                "opt": opt, "ground_truth": gt,
                "baseline_detected": bdet, "enhanced_detected": edet,
                "baseline_verdict": classify(gt, bdet),
                "enhanced_verdict": classify(gt, edet),
                "call_count": len(verdicts),
                "elapsed_ms": round(elapsed, 2), "error": err,
            })
            print(f"  {sid} {opt}: base={results[-1]['baseline_verdict']} "
                  f"enh={results[-1]['enhanced_verdict']} "
                  f"calls={len(verdicts)}")
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / "fmt_scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nfmt scan results -> {out} ({len(results)} rows)")
    return results


if __name__ == "__main__":
    scan_all()
