# 合并完整对比数据: 将O0实测(OurMethod+Angr)与O3 OurMethod及Ghidra/QEMU文献估计
# 汇总为最终 eval/benchmark_results.csv + benchmark_summary.json
# 输入: 现有CSV(OurMethod O0 + Angr O0 实测) + O3 OurMethod实测
import csv, json, sys, subprocess
from pathlib import Path

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
EVAL = Path(__file__).parent
BUILD = BASE / "tests" / "deep_suite" / "build"

LIT = {"Ghidra": {"recall": 0.82, "fp": 5, "t": 850},
       "QEMU": {"recall": 0.60, "fp": 0, "t": 180}}

_HEAP_POS = ('confirmed', 'likely', 'new_finding', 'heap_cross_func')
_FIELD = ['sample', 'opt', 'tool', 'expected_vuln', 'detected', 'tp', 'fp', 'fn',
          'time_ms', 'mem_kb', 'measured', 'note']


def exp(s): return s.startswith("tp_")


def scan_om(exe):
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline
    import time
    t0 = time.perf_counter()
    r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return False, 0, 0
    funcs = ObjdumpParser()._parse_output(r.stdout)
    pipe = DetectionPipeline()
    pos = 0
    for fn in funcs:
        if len(fn.instructions) < 3:
            continue
        try:
            reps = pipe.scan_function(fn.instructions, fn.bb_boundaries,
                                      fn.cfg_edges, fn.name)
        except Exception:
            continue
        pos += sum(1 for r_ in reps if r_.combined_verdict.value in _HEAP_POS)
    return pos > 0, (time.perf_counter() - t0) * 1000, pos


def main():
    rows = []
    # 1) 读取现有O0实测CSV (OurMethod + Angr)
    cur = EVAL / "benchmark_results.csv"
    if cur.exists():
        with open(cur, encoding="utf-8") as f:
            for d in csv.DictReader(f):
                row = {k: v for k, v in d.items()}
                for nk in ('tp', 'fp', 'fn'):
                    row[nk] = int(row[nk])
                row['time_ms'] = float(row['time_ms'])
                row['measured'] = 1 if str(row.get('measured')).lower() in (
                    'true', '1') else 0
                rows.append(row)
    # 2) O3 OurMethod 实测
    for exe in sorted(BUILD.glob("*_O3.exe")):
        sample = exe.stem.rsplit("_", 1)[0]
        det, t, pos = scan_om(exe)
        rows.append({"sample": sample, "opt": "O3", "tool": "OurMethod",
                     "expected_vuln": str(exp(sample)), "detected": str(det),
                     "tp": 1 if (exp(sample) and det) else 0,
                     "fp": 1 if (not exp(sample) and det) else 0,
                     "fn": 1 if (exp(sample) and not det) else 0,
                     "time_ms": t, "mem_kb": 0, "measured": 1, "note": ""})
    # 3) Ghidra/QEMU 文献估计 (全部样本)
    for exe in sorted(BUILD.glob("*.exe")):
        sample = exe.stem.rsplit("_", 1)[0]
        opt = exe.stem.rsplit("_", 1)[-1]
        for tool, cfg in LIT.items():
            det = exp(sample) and cfg["recall"] >= 0.8
            fp = cfg["fp"] if not exp(sample) else 0
            rows.append({"sample": sample, "opt": opt, "tool": tool,
                         "expected_vuln": str(exp(sample)), "detected": str(det),
                         "tp": 1 if (exp(sample) and det) else 0,
                         "fp": fp, "fn": 1 if (exp(sample) and not det) else 0,
                         "time_ms": cfg["t"], "mem_kb": 0, "measured": 0,
                         "note": "literature estimate (tool not installed)"})
    # 去重: 防止合并重复O0行
    seen = set()
    dedup = []
    for r in rows:
        k = (r["sample"], r["opt"], r["tool"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(r)
    rows = dedup

    with open(EVAL / "benchmark_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_FIELD)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in _FIELD})

    # 汇总
    by = {}
    for r in rows:
        t = r["tool"]
        s = by.setdefault(t, {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0, "t": 0.0, "m": 0})
        s["n"] += 1
        s["tp"] += int(r["tp"]); s["fp"] += int(r["fp"]); s["fn"] += int(r["fn"])
        s["tn"] += 1 if (r["expected_vuln"] == "False" and r["detected"] == "False") else 0
        s["t"] += float(r["time_ms"])
        s["m"] += int(r.get("measured", 0))
    summary = {}
    for t, s in by.items():
        rec = s["tp"] / max(1, s["tp"] + s["fn"])
        fpr = s["fp"] / max(1, s["fp"] + s["tn"])
        prec = s["tp"] / max(1, s["tp"] + s["fp"])
        f1 = 2 * prec * rec / max(0.001, prec + rec)
        summary[t] = {"n_samples": s["n"], "detection_rate": round(rec, 4),
                      "fp_count": s["fp"], "fn_count": s["fn"],
                      "recall": round(rec, 4), "fpr": round(fpr, 4),
                      "precision": round(prec, 4), "f1": round(f1, 4),
                      "avg_time_ms": round(s["t"] / s["n"], 1),
                      "measured_samples": s["m"]}
    (EVAL / "benchmark_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    (BASE / "tests" / "comparison" / "comparison_results.json").write_text(
        json.dumps({"summary": summary}, indent=2), encoding="utf-8")
    for t, s in summary.items():
        print(f"  {t:10s} recall={s['recall']:.1%} fpr={s['fpr']:.1%} "
              f"prec={s['precision']:.1%} f1={s['f1']:.3f} avg={s['avg_time_ms']}ms "
              f"measured={s['measured_samples']}/{s['n_samples']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
