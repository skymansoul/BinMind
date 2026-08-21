# UAF 扫描调度模块.
#
# 决策逻辑:
#   对 build/manifest_build.json 中每个编译产物调用 UAFDetector,
#   按样本 ground truth 判定 TP/FP/FN/TN:
#     - vulnerable 检出 use_after_free -> TP; 未检出 -> FN.
#     - safe 检出 use_after_free → FP; 未检出 → TN.
#   每个产物扫描两遍: use_ulp=True (增强) 与 use_ulp=False (基线),
#   量化 ULPR 的误报抑制贡献. 结果写 results/uaf_scan_results.json.
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
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent)):
        if p not in sys.path:
            sys.path.insert(0, p)


def classify(gt: str, detected: bool) -> str:
    if gt == "vulnerable":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def scan_binary_uaf(binary: str, use_ulp: bool = True):
    """扫描单个 UAF 二进制, 返回 (detector, confirmed_findings)."""
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.import_resolver import resolve_call_targets
    from modules.analysis.static.uaf_detect import UAFDetector

    instructions, fmt, _main, ranges = disassemble_binary(binary)
    if not instructions:
        return None, []
    instructions = resolve_call_targets(binary, instructions, fmt)
    use_win64 = "pei" in fmt.lower()
    det = UAFDetector(use_win64_abi=use_win64)
    det.set_user_func_ranges(ranges)
    det._ulp_enabled = use_ulp
    det.pre_analyze(instructions)
    for ins in instructions:
        det.analyze_instruction(ins)
    return det, det.finalize(instructions)


def scan_all() -> list:
    """扫描全部编译产物, 返回逐样本结果 (增强+基线两行)."""
    _ensure_paths()
    if not BUILD_MANIFEST.exists():
        print(f"build manifest not found: {BUILD_MANIFEST}. "
              "Run compile_uaf.py first.")
        return []

    manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
    results = []

    for sample in manifest:
        sid = sample["sample_id"]
        gt = sample["ground_truth"]
        expected = sample["expected"]
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            binary = rec.get("binary", "")
            if not rec.get("compiled") or not os.path.exists(binary):
                continue
            for use_ulp in (True, False):
                t0 = time.perf_counter()
                det, confirmed = scan_binary_uaf(binary, use_ulp=use_ulp)
                elapsed = (time.perf_counter() - t0) * 1000
                # finalize 现返回 confirmed+suspected (suspected 保留供复核),
                # 度量口径: ULPR 启用时仅 ulp_verdict=confirmed 计入检出.
                detected = any(
                    f.get("type") == "use_after_free" and
                    (not use_ulp or f.get("ulp_verdict") == "confirmed")
                    for f in confirmed)
                verdict = classify(gt, detected)
                results.append({
                    "sample_id": sid,
                    "cve": sample.get("cve", ""),
                    "opt": opt,
                    "ulp_enabled": use_ulp,
                    "ground_truth": gt,
                    "expected": expected,
                    "binary": binary,
                    "detected": detected,
                    "verdict": verdict,
                    "confirmed_count": len(confirmed),
                    "suspected_count": len(det._suspected_findings)
                    if det else 0,
                    "benign_count": len(det._benign_findings) if det else 0,
                    "elapsed_ms": round(elapsed, 2),
                    "error": "",
                })
            print(f"  {sid} {opt}: "
                  f"ulp={results[-2]['verdict']}/{results[-1]['verdict']} "
                  f"confirmed {results[-2]['confirmed_count']}"
                  f"->{results[-1]['confirmed_count']}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / "uaf_scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nuaf scan results -> {out} ({len(results)} rows)")
    return results


if __name__ == "__main__":
    scan_all()
