# intof 精度基准 - 独立 vuln/safe 二进制误报控制量化
#
# 决策: 量化 IntegerOverflowDetector 在"安全整数运算 + 溢出检查"
# 样本上的误报率. 独立二进制 (vuln 应检出=TP, safe 检出=FP)
# 使检出可精确归因, 弥补 samples_intof 混编无法量化的缺口.
#
# 判定依据: vuln 二进制含溢出→malloc 链; safe 二进制含溢出检查
# (如 sz/sizeof != count 拒绝). 检测器对 safe 样本不应告警.

import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[3]  # samples_intof_safe → benchmark → analysis → modules → deemo
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary, \
    parse_func_ranges, is_crt_func, extract_func_name
from modules.analysis.static.integer_overflow_detect import IntegerOverflowDetector

MANIFEST = SCRIPT_DIR / "intof_manifest.json"
RESULTS_DIR = SCRIPT_DIR.parents[1] / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _user_reachable_ranges(binary: str):
    """构建用户函数范围: main + 样本函数 (v_ 前缀).

    disassemble_binary 的 ranges 含大量 MinGW CRT 内部函数
    (safe_flush/__freedtoa 等), 直接用作 user 范围会把 CRT 的
    add/shl 误判为溢出流向危险函数. 此处仅保留 main 与样本
    漏洞函数 (命名 v_ 前缀), 排除 CRT 与库代码.
    """
    import subprocess
    out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                         capture_output=True, text=True).stdout
    all_ranges, _ = parse_func_ranges(out)
    result = []
    for n, (lo, hi) in all_ranges.items():
        if n == "main" or n.startswith("v_"):
            if lo < hi:
                result.append((lo, hi))
    return result


def scan_intof(binary: str) -> bool:
    ins, fmt, main, ranges = disassemble_binary(binary)
    # 用 main 可达用户范围 (排除 CRT), 回退到 disassemble ranges
    user_ranges = _user_reachable_ranges(binary) or ranges
    det = IntegerOverflowDetector(
        use_win64_abi="pei" in (fmt or "").lower())
    det.set_instructions(ins)
    det.set_user_func_ranges(user_ranges)
    for i in ins:
        det.analyze(i)
    return len(det.findings) > 0


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    compiled = [e for e in manifest if e.get("compiled")]
    rows = []
    print("=" * 64)
    print("Integer Overflow Precision Benchmark (vuln/safe pairs)")
    print("=" * 64)
    for e in compiled:
        binary = e.get("binary", "")
        if not binary or not Path(binary).exists():
            continue
        is_vuln = e.get("is_vuln", False)
        t0 = time.perf_counter()
        detected = False
        try:
            detected = scan_intof(binary)
        except Exception:
            pass
        rows.append({
            "cve": e.get("cve", ""), "pattern": e.get("pattern", ""),
            "variant": e.get("variant", ""), "opt": e.get("opt", ""),
            "is_vuln": is_vuln, "detected": detected,
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
        })
        verdict = "TP" if (is_vuln and detected) else \
            ("TN" if (not is_vuln and not detected) else
             ("FP!" if not is_vuln else "FN!"))
        print(f"  {e['cve']:<28} {e['variant']:<5} {e['opt']:<3} "
              f"detected={detected} -> {verdict}")

    tp = sum(1 for r in rows if r["is_vuln"] and r["detected"])
    fn = sum(1 for r in rows if r["is_vuln"] and not r["detected"])
    fp = sum(1 for r in rows if not r["is_vuln"] and r["detected"])
    tn = sum(1 for r in rows if not r["is_vuln"] and not r["detected"])
    recall = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)
    print("=" * 64)
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%} Precision={prec:.1%} FPR={fpr:.1%}")
    print("=" * 64)
    (RESULTS_DIR / "intof_precision.json").write_text(json.dumps({
        "summary": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                    "recall": round(recall, 4),
                    "precision": round(prec, 4),
                    "fpr": round(fpr, 4)},
        "rows": rows,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2, ensure_ascii=False))
    print(f"results: {RESULTS_DIR / 'intof_precision.json'}")


if __name__ == "__main__":
    main()
