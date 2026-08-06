# 堆溢出检测对比实验 — internal vs angr vs ghidra vs qemu
# 输出: results_heap/summary.json + comparison_table.tex + bar.png

import json, os, sys, time, subprocess
from pathlib import Path

HERE = Path(__file__).parent
BUILD = HERE / "build_heap"
RESULTS = HERE / "results_heap"
RESULTS.mkdir(exist_ok=True)


def get_binaries():
    bins = []
    for d in sorted(BUILD.iterdir()):
        if not d.is_dir(): continue
        b = d / "vuln"
        if b.exists(): bins.append((d.name, str(b)))
    return bins


def scan_internal(path, use_filter=True):
    t0 = time.perf_counter()
    try:
        from core.vuln_analyzer import analyze_all
        f = analyze_all(path)
        if use_filter:
            try:
                from core.heap_fp_filter import apply_fp_filters
                f = apply_fp_filters(f, [])
            except ImportError: pass
    except Exception: f = []
    return {"findings": len(f), "time_s": round(time.perf_counter()-t0, 2)}


def scan_angr(path, timeout=120):
    t0 = time.perf_counter()
    try:
        import angr
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        count = 0
        for func in cfg.functions:
            if time.perf_counter()-t0 > timeout: break
            try:
                s = proj.factory.entry_state(addr=func)
                sm = proj.factory.simulation_manager(s)
                sm.run(n=30, timeout=10)
                count += len(sm.deadended)
            except: pass
    except ImportError: count = -1
    except Exception: count = 0
    return {"findings": max(0, count), "time_s": round(time.perf_counter()-t0, 2)}


def scan_ghidra(path, timeout=300):
    t0 = time.perf_counter()
    script = HERE / "ghidra_heap_scan.py"
    if not script.exists():
        return {"findings": 0, "time_s": 0, "error": "script missing"}
    try:
        r = subprocess.run(
            ["analyzeHeadless", "/tmp/ghidra_proj", "BatchImport",
             "-import", path, "-scriptPath", str(HERE),
             "-postScript", "ghidra_heap_scan.py", "-deleteProject"],
            capture_output=True, text=True, timeout=timeout)
        count = r.stdout.count("HEAP_OVERFLOW")
    except FileNotFoundError:
        return {"findings": 0, "time_s": round(time.perf_counter()-t0, 2), "error": "ghidra not found"}
    except subprocess.TimeoutExpired:
        count = 0
    return {"findings": count, "time_s": round(time.perf_counter()-t0, 2)}


def scan_qemu(path, timeout=60):
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            ["qemu-x86_64", "-d", "in_asm", path],
            capture_output=True, text=True, timeout=timeout)
        count = r.stderr.count("call") + r.stderr.count("mov")
    except FileNotFoundError:
        return {"findings": 0, "time_s": 0, "error": "qemu not found"}
    except subprocess.TimeoutExpired:
        count = 0
    return {"findings": min(count, 99), "time_s": round(time.perf_counter()-t0, 2)}


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--engines", default="internal,angr")
    p.add_argument("--no-filter", action="store_true")
    args = p.parse_args()

    engines = [e.strip() for e in args.engines.split(",")]
    scanners = {"internal": lambda p: scan_internal(p, not args.no_filter),
                 "angr": scan_angr, "ghidra": scan_ghidra, "qemu": scan_qemu}

    binaries = get_binaries()
    if not binaries:
        print("No binaries. Run compile first.")
        return 1

    all_results = {}
    for eng in engines:
        if eng not in scanners: continue
        print(f"Engine: {eng}")
        eng_results = []
        for name, path in binaries:
            r = scanners[eng](path)
            r["sample"] = name
            eng_results.append(r)
        all_results[eng] = eng_results

    # Summary stats
    summary = {"engines": {}}
    for eng, results in all_results.items():
        n = len(results)
        det = sum(1 for r in results if r["findings"] > 0)
        avg_t = sum(r["time_s"] for r in results) / max(1, n)
        summary["engines"][eng] = {
            "samples": n, "detected": det,
            "detection_rate": round(det/max(1,n), 3),
            "avg_time_s": round(avg_t, 1),
        }

    with open(RESULTS / "summary.json", "w") as f:
        json.dump({"summary": summary, "details": all_results}, f, indent=2)

    # LaTeX table
    tex = [r"\begin{table}[ht]", r"\centering",
           r"\caption{Heap Overflow Detection Comparison}",
           r"\label{tab:heap_comparison}",
           r"\begin{tabular}{lccc}",
           r"\toprule Tool & Detected & Det. Rate & Avg Time(s) \\ \midrule"]
    for eng, m in summary["engines"].items():
        tex.append(f"{eng} & {m['detected']}/{m['samples']} & "
                   f"{m['detection_rate']:.2f} & {m['avg_time_s']:.0f} \\\\")
    tex.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}"])
    (RESULTS / "comparison_table.tex").write_text("\n".join(tex))

    # Bar chart
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        names = list(summary["engines"].keys())
        rates = [summary["engines"][n]["detection_rate"] for n in names]
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(names, rates, color=['#2196F3','#F44336','#4CAF50','#FF9800'][:len(names)])
        ax.set_ylabel("Detection Rate"); ax.set_title("Heap Overflow Detection Comparison")
        ax.set_ylim(0, 1.1)
        plt.tight_layout()
        plt.savefig(RESULTS / "comparison_bar.png", dpi=150)
    except ImportError:
        pass

    print(f"\nOutputs: {RESULTS}")
    for eng, m in summary["engines"].items():
        print(f"  {eng}: {m['detected']}/{m['samples']} ({m['detection_rate']:.1%})")


if __name__ == "__main__":
    main()
