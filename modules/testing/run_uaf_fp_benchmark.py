"""UAF 误报基准 — baseline vs uaf_fpmin 对比.

对 uaf_samples/ 的 16 个样本 (8 误报诱发 + 8 真实 UAF),
运行三个检测器:
  1. BinaryUafScanner (baseline, run_scanner 的 uaf_binary)
  2. UafFpminScanner (baseline + S1-S7 误报抑制)
  3. UAFDetector v6 (PDL-UAF, 对照)
输出 TP/FP/FN/TN 与逐样本状态.
"""

import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(BASE))   # testing → modules → deemo
sys.path.insert(0, PROJ_ROOT)

from modules.analysis.static.uaf_analysis.binary_uaf_scanner import \
    BinaryUafScanner  # noqa: E402
from modules.analysis.static.uaf_analysis.uaf_fpmin_scanner import \
    UafFpminScanner  # noqa: E402
from modules.analysis.static.uaf_detect import UAFDetector  # noqa: E402
from modules.analysis.static.disasm_util import disassemble_binary  # noqa: E402

SAMPLES_DIR = os.path.join(BASE, "uaf_samples")


def run_binary_scanner(exe: str) -> bool:
    txt = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                         capture_output=True, text=True,
                         errors="ignore", timeout=60).stdout
    findings = BinaryUafScanner().scan(txt, user_code_only=True)
    return len(findings) > 0


def run_fpmin_scanner(exe: str) -> bool:
    txt = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                         capture_output=True, text=True,
                         errors="ignore", timeout=60).stdout
    r = UafFpminScanner(binary_path=exe).scan(txt, user_code_only=True)
    return r["n_findings"] > 0


def run_pdl_uaf(exe: str) -> bool:
    ins, fmt, main, ranges = disassemble_binary(exe)
    det = UAFDetector(use_win64_abi="pei" in fmt.lower())
    if ranges:
        det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    return len(det.finalize(ins)) > 0


def main():
    samples = []
    for entry in sorted(os.listdir(SAMPLES_DIR)):
        if not (entry.startswith("fp_") or entry.startswith("uaf_")):
            continue
        exe = os.path.join(SAMPLES_DIR, entry, "vuln.exe")
        if not os.path.isfile(exe):
            continue
        samples.append((entry, entry.startswith("uaf_"), exe))

    stats = {"binary": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
             "fpmin": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
             "pdl": {"tp": 0, "fp": 0, "fn": 0, "tn": 0}}
    rows = []
    print(f"{'sample':<28}{'期望':<6}{'binary':<8}{'fpmin':<8}"
          f"{'pdl':<6}{'verdict_bin':<12}{'verdict_fpmin':<12}{'verdict_pdl'}")
    for name, is_vuln, exe in samples:
        b_det = run_binary_scanner(exe)
        m_det = run_fpmin_scanner(exe)
        p_det = run_pdl_uaf(exe)
        for key, det in (("binary", b_det), ("fpmin", m_det),
                         ("pdl", p_det)):
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
                     "expected": "UAF" if is_vuln else "SAFE",
                     "binary": verdict(b_det), "fpmin": verdict(m_det),
                     "pdl": verdict(p_det)})
        print(f"{name:<28}{'UAF' if is_vuln else 'SAFE':<6}"
              f"{str(b_det):<8}{str(m_det):<8}{str(p_det):<6}"
              f"{verdict(b_det):<12}{verdict(m_det):<12}{verdict(p_det)}")

    print("\n" + "=" * 60)
    for key, label in (("binary", "BinaryUafScanner (baseline)"),
                       ("fpmin", "UafFpminScanner (S1-S7 抑制)"),
                       ("pdl", "UAFDetector v6 (PDL-UAF)")):
        s = stats[key]
        rec = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 0
        prec = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 1
        fpr = s["fp"] / (s["fp"] + s["tn"]) if s["fp"] + s["tn"] else 0
        print(f"  {label}: TP={s['tp']} FP={s['fp']} FN={s['fn']} "
              f"TN={s['tn']} recall={rec:.2f} precision={prec:.2f} "
              f"fpr={fpr:.2f}")

    with open(os.path.join(BASE, "uaf_fp_baseline.json"), "w",
              encoding="utf-8") as f:
        json.dump({"stats": stats, "rows": rows}, f, indent=2,
                  ensure_ascii=False)
    print("[OK] uaf_fp_baseline.json")


if __name__ == "__main__":
    main()
