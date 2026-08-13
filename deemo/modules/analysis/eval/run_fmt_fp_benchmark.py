"""fmt 误报基准 — baseline 量化脚本.

对 samples_fmt_fp/ 的 16 个样本 (8 误报诱发 + 8 真实漏洞),
运行三个既有检测器:
  1. BinaryFmtScanner (run_scanner 的 fmt_binary 检测器)
  2. FmtTaintDetect (fmt_taint_detect.py)
  3. FmtBinaryDetect (fmt_binary_detect.py)
输出 TP/FP/FN/TN 与逐样本状态.
"""

import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(BASE)))
sys.path.insert(0, PROJ_ROOT)

from modules.analysis.static.format_string_analysis.binary_fmt_scanner import \
    BinaryFmtScanner  # noqa: E402
from modules.analysis.static.format_string_analysis.fmt_fpmin_scanner import \
    FmtFpminScanner  # noqa: E402

SAMPLES_DIR = os.path.join(os.path.dirname(BASE), "benchmark",
                           "samples_fmt_fp")


def run_binary_fmt(exe: str) -> bool:
    txt = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                         capture_output=True, text=True,
                         errors="ignore", timeout=60).stdout
    findings = BinaryFmtScanner().scan(txt, user_code_only=True,
                                       binary_path=exe)
    return len(findings) > 0


def run_fpmin_fmt(exe: str) -> bool:
    txt = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                         capture_output=True, text=True,
                         errors="ignore", timeout=60).stdout
    r = FmtFpminScanner().scan(txt, user_code_only=True, binary_path=exe)
    return r["n_findings"] > 0


def main():
    samples = []
    for entry in sorted(os.listdir(SAMPLES_DIR)):
        if not (entry.startswith("fp_") or entry.startswith("vuln_")):
            continue
        exe = os.path.join(SAMPLES_DIR, entry, "vuln.exe")
        if not os.path.isfile(exe):
            continue
        samples.append((entry, entry.startswith("vuln_"), exe))

    stats = {"binary_fmt": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
             "fpmin": {"tp": 0, "fp": 0, "fn": 0, "tn": 0}}
    rows = []
    print(f"{'sample':<28}{'期望':<6}{'binary':<8}{'fpmin':<8}"
          f"{'vb':<4}{'vf'}")
    for name, is_vuln, exe in samples:
        b_det = run_binary_fmt(exe)
        m_det = run_fpmin_fmt(exe)
        for key, det in (("binary_fmt", b_det), ("fpmin", m_det)):
            if is_vuln and det:
                stats[key]["tp"] += 1
            elif not is_vuln and det:
                stats[key]["fp"] += 1
            elif is_vuln and not det:
                stats[key]["fn"] += 1
            else:
                stats[key]["tn"] += 1

        def verdict(det):
            if is_vuln and det:
                return "TP"
            if not is_vuln and det:
                return "FP"
            if is_vuln:
                return "FN"
            return "TN"

        rows.append({"sample": name,
                     "expected": "VULN" if is_vuln else "SAFE",
                     "binary_fmt": verdict(b_det),
                     "fpmin": verdict(m_det)})
        print(f"{name:<28}{'VULN' if is_vuln else 'SAFE':<6}"
              f"{str(b_det):<8}{str(m_det):<8}"
              f"{verdict(b_det):<4}{verdict(m_det)}")

    print("\n" + "=" * 50)
    for key, label in (("binary_fmt", "BinaryFmtScanner (baseline)"),
                       ("fpmin", "FmtFpminScanner (溯源+参数验证)")):
        s = stats[key]
        rec = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 0
        prec = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 1
        fpr = s["fp"] / (s["fp"] + s["tn"]) if s["fp"] + s["tn"] else 0
        print(f"  {label}: TP={s['tp']} FP={s['fp']} "
              f"FN={s['fn']} TN={s['tn']} recall={rec:.2f} "
              f"precision={prec:.2f} fpr={fpr:.2f}")

    with open(os.path.join(BASE, "fmt_fp_baseline.json"), "w",
              encoding="utf-8") as f:
        json.dump({"stats": stats, "rows": rows}, f, indent=2,
                  ensure_ascii=False)
    print("[OK] fmt_fp_baseline.json")


if __name__ == "__main__":
    main()
