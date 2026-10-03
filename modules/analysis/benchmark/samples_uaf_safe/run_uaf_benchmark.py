# UAF 检测精度基准 - vuln/safe 独立二进制
#
# 目标: 量化 UAF 检测器 (生命周期追踪 + 指针溯源) 在
# "free 后非缺陷使用" 与 "真实 UAF" 之间的区分能力.
# 每个 pattern 编译 vuln (应检出=TP) 与 safe (检出=FP) 配对.
#
# 输出: 汇总 TP/FP/TN/FN/Recall/Precision/FPR + JSON.

import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[3]  # samples_uaf_safe → benchmark → analysis → modules → deemo
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.uaf_detect import UAFDetector

MANIFEST = SCRIPT_DIR / "manifest.json"
RESULTS_DIR = SCRIPT_DIR.parents[1] / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def run_uaf(binary: str) -> bool:
    ins, fmt, main, ranges = disassemble_binary(binary)
    det = UAFDetector(use_win64_abi="pei" in fmt.lower())
    if ranges:
        det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    findings = det.finalize(ins)
    return len(findings) > 0


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = []
    print("=" * 64)
    print("UAF Precision Benchmark (vuln/safe pairs)")
    print("=" * 64)
    for e in manifest:
        binary = e.get("binary", "")
        if not binary or not Path(binary).exists():
            continue
        expected = e.get("expected", "")
        is_vuln = expected != "UAF"  # 'SAFE'/'TNF' 等 → 非漏洞
        is_vuln = expected.upper() not in ("SAFE", "TNF", "TN")
        # 从 variant 字段判读: vuln/safe
        variant = e.get("variant", "")
        is_vuln = variant == "vuln" or expected.upper() in ("UAF", "TP")
        t0 = time.perf_counter()
        detected = False
        try:
            detected = run_uaf(binary)
        except Exception as ex:
            pass
        rows.append({
            "pattern": e.get("pattern", ""), "variant": variant,
            "opt": e.get("opt", ""), "is_vuln": is_vuln,
            "detected": detected,
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
        })
        verdict = "TP" if (is_vuln and detected) else \
            ("TN" if (not is_vuln and not detected) else
             ("FP!" if not is_vuln else "FN!"))
        print(f"  {e['pattern']:<24} {variant:<5} {e['opt']:<3} "
              f"detected={detected} -> {verdict}")

    tp = sum(1 for r in rows if r["is_vuln"] and r["detected"])
    fn = sum(1 for r in rows if r["is_vuln"] and not r["detected"])
    fp = sum(1 for r in rows if not r["is_vuln"] and r["detected"])
    tn = sum(1 for r in rows if not r["is_vuln"] and not r["detected"])
    recall = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)

    summary = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4), "precision": round(prec, 4),
        "fpr": round(fpr, 4),
    }
    print("=" * 64)
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%} Precision={prec:.1%} FPR={fpr:.1%}")
    print("=" * 64)

    (RESULTS_DIR / "uaf_precision.json").write_text(json.dumps({
        "summary": summary, "rows": rows,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2, ensure_ascii=False))
    print(f"results: {RESULTS_DIR / 'uaf_precision.json'}")


if __name__ == "__main__":
    main()
