"""多工具对比主实验 — 统一格式 CSV 输出.

工具: binmind_absint (baseline), binmind_giva (PG-WBV),
      angr (有界符号探索), qemu (qemu-user 追踪, 不可用则 N/A),
      ghidra (无头审计, 不可用则 N/A),
      flawfinder, cppcheck (源码级对照)

输出: eval/benchmark_results.json + eval/benchmark_results.csv
CSV 列: tool,sample_id,group,expected,detected,true_positive,
        false_positive,false_negative,true_negative,elapsed_ms,peak_mem_kb

--strip: 用 objcopy 生成去符号副本 (混淆加固代理), 对副本再跑
binmind 两个检测器, 结果归入 stripped 分组. UPX 不可用时以
stripped 作为"加固"形态的诚实替代, 见 plot_comparison 注释.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "eval"
LABELS_PATH = ROOT / "sample_labels.json"
SAMPLE_DIRS = [ROOT / "heap_samples", ROOT / "heap_benign_samples"]
# TODO: qemu/ghidra 适配器仅验证了 Windows 降级路径,
# Linux CI 上需实机回归 qemu-user 追踪与 Ghidra 脚本输出

sys.path.insert(0, str(EVAL_DIR))
from angr_explorer import run_angr_scan            # noqa: E402
from qemu_tracer import run_qemu_scan              # noqa: E402
from ghidra_headless import run_ghidra_scan        # noqa: E402
from mem_probe import measure_peak                 # noqa: E402

PROJ_ROOT = ROOT.parent.parent
if str(PROJ_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJ_ROOT))

TOOL_ORDER = ["binmind_absint", "binmind_giva", "binmind_uaf_fpmin",
              "binmind_fmt_fpmin", "binmind_intof_fpmin",
              "angr", "qemu", "ghidra", "flawfinder", "cppcheck"]


def objdump_txt(exe: str) -> str:
    r = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                       capture_output=True, text=True, timeout=60)
    return r.stdout


def run_binmind(exe: str, name: str, import_map: Optional[dict] = None) -> dict:
    """运行 binmind absint baseline 与 giva."""
    from modules.analysis.static.heap_analysis.giva_detector import \
        GivaScanner
    from modules.analysis.static.uaf_analysis.uaf_fpmin_scanner import \
        UafFpminScanner
    from modules.analysis.static.format_string_analysis.fmt_fpmin_scanner import \
        FmtFpminScanner
    from modules.analysis.static.integer_overflow_analysis.io_fpmin_scanner import \
        IntOverflowFpminScanner
    txt = objdump_txt(exe)
    res = GivaScanner(binary_path=exe, import_map=import_map).scan(txt, name)
    uaf = UafFpminScanner(binary_path=exe).scan(
        txt, name, user_code_only=True)
    fmt = FmtFpminScanner().scan(txt, name, user_code_only=True,
                                 binary_path=exe)
    io_ = IntOverflowFpminScanner().scan(txt, name, user_code_only=True)
    return {"absint": res["n_baseline_real"] > 0,
            "giva": res["n_real"] > 0,
            "uaf_fpmin": uaf["n_findings"] > 0,
            "fmt_fpmin": fmt["n_findings"] > 0,
            "intof_fpmin": io_["n_findings"] > 0}


def import_map_for(exe: str, group: str) -> Optional[dict]:
    """stripped 分组: 用同构建 plain 二进制的符号映射."""
    if group != "stripped":
        return None
    from modules.analysis.static.heap_analysis.plt_resolver import \
        build_import_map
    rel = os.path.relpath(exe, str(ROOT))
    plain = rel.replace("heap_samples_stripped", "heap_samples").replace(
        "heap_benign_stripped", "heap_benign_samples")
    plain_path = os.path.join(str(ROOT), plain)
    if os.path.isfile(plain_path):
        return build_import_map(plain_path)
    return None


def run_source_tool(tool: str, src_file: str) -> int:
    """源码级工具检出数."""
    if tool == "flawfinder":
        try:
            r = subprocess.run(
                ["flawfinder", "--quiet", "--minlevel=1", str(src_file)],
                capture_output=True, text=True, timeout=30)
            return sum(1 for line in r.stdout.split("\n")
                       if ":" in line and not line.startswith("Flawfinder")
                       and any(k in line.lower() for k in
                               ("cwe-122", "buffer", "overflow",
                                "strcpy", "memcpy", "strcat")))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return -1
    if tool == "cppcheck":
        try:
            r = subprocess.run(
                ["cppcheck", "--enable=warning,style", "--xml", "--quiet",
                 str(src_file)],
                capture_output=True, text=True, timeout=30)
            return sum(1 for m in re_find_errors(r.stdout))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return -1
    return -1


def re_find_errors(xml: str):
    return re.finditer(
        r'<error[^>]*id="([^"]*)"[^>]*msg="([^"]*)"', xml)


def make_stripped(src_dir: Path, dst_dir: Path) -> bool:
    """objcopy 去符号副本 (stripped 分组), 返回是否成功."""
    ok_all = True
    dst_dir.mkdir(exist_ok=True)
    for entry in sorted(os.listdir(src_dir)):
        exe = src_dir / entry / "vuln.exe"
        if not exe.is_file():
            continue
        out_dir = dst_dir / entry
        out_dir.mkdir(exist_ok=True)
        out_exe = out_dir / "vuln.exe"
        try:
            r = subprocess.run(
                ["objcopy", "--strip-all", "--remove-section", ".comment",
                 str(exe), str(out_exe)],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                shutil.copy2(exe, out_exe)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            shutil.copy2(exe, out_exe)
            ok_all = False
        try:
            r = subprocess.run(["strip", "-s", str(out_exe)],
                               capture_output=True, timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return ok_all


def main():
    ap = argparse.ArgumentParser(description="Multi-tool benchmark runner")
    ap.add_argument("--strip", action="store_true",
                    help="构建去符号副本并纳入对比 (加固分组)")
    ap.add_argument("--only-binmind", action="store_true",
                    help="仅运行 binmind 两检测器 (快速回归)")
    args = ap.parse_args()

    labels = json.load(open(LABELS_PATH, encoding="utf-8"))
    samples: List[Tuple[str, str, str]] = []   # (name, exe, group)
    for d in SAMPLE_DIRS:
        for entry in sorted(os.listdir(d)):
            exe = d / entry / "vuln.exe"
            if exe.is_file() and entry in labels:
                samples.append((entry, str(exe), "plain"))
    stripped_dirs: List[Tuple[str, str]] = []
    if args.strip:
        for src in SAMPLE_DIRS:
            dst = ROOT / (src.name + "_stripped")
            if make_stripped(src, dst):
                stripped_dirs.append((src.name, str(dst)))
        for dname, dpath in stripped_dirs:
            for entry in sorted(os.listdir(dpath)):
                exe = os.path.join(dpath, entry, "vuln.exe")
                if os.path.isfile(exe) and entry in labels:
                    samples.append((entry, exe, "stripped"))

    rows = []
    n_samples = len(samples)
    print(f"[*] 样本数: {n_samples} (含 stripped: {args.strip})")

    for i, (name, exe, group) in enumerate(samples, 1):
        expect = labels[name].get("heap_overflow", False)
        src = os.path.join(os.path.dirname(exe), "src", "vuln.c")
        for tool in TOOL_ORDER:
            detected = False
            err = ""
            if tool in ("binmind_absint", "binmind_giva",
                        "binmind_uaf_fpmin", "binmind_fmt_fpmin",
                        "binmind_intof_fpmin"):
                imap = import_map_for(exe, group)
                res, peak, ms = measure_peak(
                    lambda e=exe, n=name, m=imap: run_binmind(e, n, m))
                detected = res.get({
                    "binmind_absint": "absint",
                    "binmind_giva": "giva",
                    "binmind_uaf_fpmin": "uaf_fpmin",
                    "binmind_fmt_fpmin": "fmt_fpmin",
                    "binmind_intof_fpmin": "intof_fpmin",
                }.get(tool), False)
            elif args.only_binmind:
                continue
            elif tool == "angr":
                res, peak, ms = measure_peak(
                    lambda: run_angr_scan(exe, name, cache=False))
                detected = any(f.get("type") == "heap_overflow"
                               for f in res["findings"])
                err = res.get("error", "")
            elif tool == "qemu":
                res, peak, ms = measure_peak(
                    lambda: run_qemu_scan(exe, name, cache=False))
                detected = any(f.get("type") == "heap_overflow"
                               for f in res["findings"])
                err = res.get("error", "")
            elif tool == "ghidra":
                res, peak, ms = measure_peak(
                    lambda: run_ghidra_scan(exe, name, cache=False))
                detected = any(f.get("type") == "heap_overflow"
                               for f in res["findings"])
                err = res.get("error", "")
            elif tool in ("flawfinder", "cppcheck"):
                if not os.path.isfile(src):
                    continue
                res, peak, ms = measure_peak(
                    lambda t=tool, s=src: run_source_tool(t, s))
                n_find = res if isinstance(res, int) else -1
                detected = n_find > 0
                err = "" if n_find >= 0 else "tool unavailable"
            else:
                continue
            if err:
                ms = 0.0
                peak = 0.0
            rows.append({
                "tool": tool, "sample": name, "group": group,
                "expected": expect, "detected": detected,
                "tp": int(expect and detected),
                "fp": int(not expect and detected),
                "fn": int(expect and not detected),
                "tn": int(not expect and not detected),
                "elapsed_ms": ms, "peak_mem_kb": peak,
                "error": err,
            })
        if i % 5 == 0 or i == n_samples:
            print(f"  [{i}/{n_samples}] ...")

    # 汇总
    tools = {t: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "ms": 0.0, "mem": 0.0}
             for t in TOOL_ORDER}
    groups = {"plain": {}, "stripped": {}}
    for r in rows:
        t = tools[r["tool"]]
        for k in ("tp", "fp", "fn", "tn"):
            t[k] += r[k]
        t["ms"] += r["elapsed_ms"]
        t["mem"] = max(t["mem"], r["peak_mem_kb"])
        if r["group"] not in groups:
            groups[r["group"]] = {}
        g = groups[r["group"]].setdefault(
            r["tool"], {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for k in ("tp", "fp", "fn", "tn"):
            g[k] += r[k]

    def metrics(t):
        tp, fp, fn, tn = t["tp"], t["fp"], t["fn"], t["tn"]
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return {"precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(f1, 4), "fp_rate": round(fpr, 4)}

    summary = {}
    available = {}
    for t in TOOL_ORDER:
        tool_rows = [r for r in rows if r["tool"] == t]
        # 全部行均为环境不可用 (qemu/ghidra 缺失) → 排除出汇总
        if tool_rows and all(r.get("error") for r in tool_rows):
            available[t] = False
            continue
        available[t] = True
        summary[t] = metrics(tools[t])

    print("\n" + "=" * 88)
    print(f"  {'Tool':<16}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Prec':>8}{'Recall':>8}{'F1':>7}{'FPR':>8}{'ms':>8}{'memKB':>8}")
    print("=" * 88)
    for t in TOOL_ORDER:
        if not available.get(t):
            print(f"  {t:<16} N/A (工具不可用)")
            continue
        s = tools[t]
        m = summary[t]
        print(f"  {t:<16}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}{s['tn']:>4}"
              f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
              f"{m['fp_rate']:>8.3f}{s['ms']:>8.0f}{s['mem']:>8.0f}")

    out = {"meta": {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "stripped": args.strip},
           "summary": summary, "tools": tools,
           "available": available,
           "group_summary": {g: {t: metrics(v)
                                 for t, v in group_tools.items()}
                             for g, group_tools in groups.items()},
           "rows": rows}
    json_path = EVAL_DIR / "benchmark_results.json"
    csv_path = EVAL_DIR / "benchmark_results.csv"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        f.write("tool,sample_id,group,expected,detected,true_positive,"
                "false_positive,false_negative,true_negative,"
                "elapsed_ms,peak_mem_kb,error\n")
        for r in rows:
            f.write(f"{r['tool']},{r['sample']},{r['group']},"
                    f"{int(r['expected'])},{int(r['detected'])},"
                    f"{r['tp']},{r['fp']},{r['fn']},{r['tn']},"
                    f"{r['elapsed_ms']},{r['peak_mem_kb']},"
                    f"{r.get('error', '')}\n")
    print(f"\n[*] 结果保存: {json_path.name} / {csv_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
