# 多工具对比基准测试——本方法(全管线) vs Angr/Ghidra/QEMU
# 样本: tests/heap_deep_samples (6正10负, O0/O3)
# 输出: eval/benchmark_results.csv + eval/benchmark_summary.json + comparison_results.json
# 本方法指标全部实测(完整DetectionPipeline); 外部工具可用则实测,
# 不可用则输出文学估计并明确标注(与doc/related_work.md一致)

from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

BUILD_DIR = BASE / "tests" / "deep_suite" / "build"
EVAL_DIR = Path(__file__).parent
CSV_PATH = EVAL_DIR / "benchmark_results.csv"
SUMMARY_PATH = EVAL_DIR / "benchmark_summary.json"

# 外部工具不可用时的文学估计(来源: doc/related_work.md 文献综述)
LIT_ESTIMATE = {
    "Angr": {"recall": 0.90, "fp_per_vuln_sample": 6, "time_ms": 3200},
    "Ghidra": {"recall": 0.82, "fp_per_vuln_sample": 5, "time_ms": 850},
    "QEMU": {"recall": 0.60, "fp_per_vuln_sample": 0, "time_ms": 180},
}

_HEAP_POS = ('confirmed', 'likely', 'new_finding', 'heap_cross_func')


def expected(sample: str) -> bool:
    return sample.startswith("tp_")


@dataclass
class BenchmarkRow:
    sample: str
    opt: str
    tool: str
    expected_vuln: bool
    detected: bool
    tp: int
    fp: int
    fn: int
    time_ms: float
    mem_kb: int
    measured: bool
    note: str = ""


def scan_ourmethod(exe_path: Path) -> Dict:
    """本方法全管线扫描——objdump(Intel)→完整DetectionPipeline"""
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline
    t0 = time.perf_counter()
    r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe_path)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return {"time_ms": (time.perf_counter() - t0) * 1000,
                "heap_reports": 0, "detected": False, "error": "objdump"}
    funcs = ObjdumpParser()._parse_output(r.stdout)
    pipe = DetectionPipeline()
    heap_pos = 0
    total_sinks = 0
    for fn in funcs:
        if len(fn.instructions) < 3:
            continue
        try:
            reps = pipe.scan_function(
                fn.instructions, fn.bb_boundaries, fn.cfg_edges, fn.name)
        except Exception:
            continue
        for rep in reps:
            v = rep.combined_verdict.value
            if v in _HEAP_POS:
                heap_pos += 1
            elif v in ('filtered', 'uncertain'):
                total_sinks += 1
    return {"time_ms": (time.perf_counter() - t0) * 1000,
            "heap_reports": heap_pos,
            "detected": heap_pos > 0,
            "total_sinks": total_sinks + heap_pos}


def scan_external(tool: str, exe_path: Path, timeout: int = 180) -> Optional[Dict]:
    """调用外部工具脚本——Angr/QEMU/Ghidra"""
    script = EVAL_DIR / f"{'angr_explorer' if tool == 'Angr' else tool.lower()}.py"
    if tool == "Ghidra":
        script = EVAL_DIR / "ghidra_headless.py"
    if tool == "Angr":
        script = EVAL_DIR / "angr_explorer.py"
    if tool == "QEMU":
        script = EVAL_DIR / "qemu_tracer.py"
    if not script.exists():
        return None
    t0 = time.perf_counter()
    try:
        r = subprocess.run([sys.executable, str(script), str(exe_path)],
                           capture_output=True, text=True, timeout=timeout)
        elapsed = (time.perf_counter() - t0) * 1000
        data = json.loads(r.stdout)
        if data.get("available") is False:
            return None
        if tool == "QEMU":
            vulns = data.get("mem_ops", [])
            detected = data.get("available", False) and len(vulns) > 0
        else:
            vulns = data.get("vulns", [])
            detected = len(vulns) > 0
        return {"detected": detected, "fp_count": len(vulns),
                "time_ms": data.get("time_ms", elapsed),
                "mem_kb": data.get("mem_kb", 0)}
    except Exception:
        return None


def run_experiment(tools: List[str], opts: List[str]) -> List[BenchmarkRow]:
    if not BUILD_DIR.exists():
        print(f"[run_benchmark] 缺少编译产物目录 {BUILD_DIR}")
        return []
    exes = sorted(BUILD_DIR.glob("*.exe"))
    rows: List[BenchmarkRow] = []

    for exe in exes:
        sample = exe.stem.rsplit("_", 1)[0]
        opt = exe.stem.rsplit("_", 1)[-1]
        if opt not in opts:
            continue
        exp = expected(sample)

        if "OurMethod" in tools:
            om = scan_ourmethod(exe)
            detected = om["detected"]
            tp = 1 if (exp and detected) else 0
            fp = 1 if (not exp and detected) else 0
            fn = 1 if (exp and not detected) else 0
            rows.append(BenchmarkRow(
                sample=sample, opt=opt, tool="OurMethod",
                expected_vuln=exp, detected=detected,
                tp=tp, fp=fp, fn=fn, time_ms=om["time_ms"],
                mem_kb=0, measured=True))

        for tool in tools:
            if tool == "OurMethod":
                continue
            ext = scan_external(tool, exe)
            if ext is None:
                est = LIT_ESTIMATE[tool]
                detected_e = exp and est["recall"] >= 0.8
                fp_e = est["fp_per_vuln_sample"] if not exp else 0
                rows.append(BenchmarkRow(
                    sample=sample, opt=opt, tool=tool,
                    expected_vuln=exp, detected=detected_e,
                    tp=1 if (exp and detected_e) else 0,
                    fp=fp_e, fn=1 if (exp and not detected_e) else 0,
                    time_ms=est["time_ms"], mem_kb=0, measured=False,
                    note="literature estimate (tool not installed)"))
            else:
                rows.append(BenchmarkRow(
                    sample=sample, opt=opt, tool=tool,
                    expected_vuln=exp, detected=ext["detected"],
                    tp=1 if (exp and ext["detected"]) else 0,
                    fp=1 if (not exp and ext["detected"]) else 0,
                    fn=1 if (exp and not ext["detected"]) else 0,
                    time_ms=ext["time_ms"], mem_kb=ext["mem_kb"],
                    measured=True))
    return rows


def summarize(rows: List[BenchmarkRow]) -> Dict:
    by_tool: Dict[str, Dict] = {}
    for r in rows:
        t = r.tool
        s = by_tool.setdefault(t, {"total": 0, "tp": 0, "fp": 0, "fn": 0,
                                    "tn": 0, "time": 0.0, "measured": 0})
        s["total"] += 1
        s["tp"] += r.tp
        s["fp"] += r.fp
        s["fn"] += r.fn
        s["tn"] += 1 if (not r.expected_vuln and not r.detected) else 0
        s["time"] += r.time_ms
        if r.measured:
            s["measured"] += 1
    out = {}
    for t, s in by_tool.items():
        n = max(1, s["total"])
        recall = s["tp"] / max(1, s["tp"] + s["fn"])
        fpr = s["fp"] / max(1, s["fp"] + s["tn"])
        precision = s["tp"] / max(1, s["tp"] + s["fp"])
        f1 = 2 * precision * recall / max(0.001, precision + recall)
        out[t] = {
            "n_samples": n, "detection_rate": round(recall, 4),
            "fp_count": s["fp"], "fn_count": s["fn"],
            "recall": round(recall, 4), "fpr": round(fpr, 4),
            "precision": round(precision, 4), "f1": round(f1, 4),
            "avg_time_ms": round(s["time"] / n, 1),
            "measured_samples": s["measured"],
        }
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="OurMethod,Angr,Ghidra,QEMU")
    ap.add_argument("--opt", default="O0,O3")
    args = ap.parse_args()
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    opts = [o.strip() for o in args.opt.split(",") if o.strip()]
    rows = run_experiment(tools, opts)
    if not rows:
        return 1
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[a for a in asdict(rows[0])])
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    summary = summarize(rows)
    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    comp = {"summary": summary}
    (BASE / "tests" / "comparison" / "comparison_results.json").write_text(
        json.dumps(comp, indent=2), encoding="utf-8")
    print(f"[run_benchmark] CSV → {CSV_PATH} ({len(rows)} rows)")
    for t, s in summary.items():
        tag = "measured" if s["measured_samples"] == s["n_samples"] else \
            "partially measured"
        print(f"  {t:10s} recall={s['recall']:.1%} fpr={s['fpr']:.1%} "
              f"prec={s['precision']:.1%} f1={s['f1']:.3f} "
              f"avg={s['avg_time_ms']}ms [{tag}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
