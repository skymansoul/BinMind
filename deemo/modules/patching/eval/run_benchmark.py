# 多工具对比基准测试主脚本
"""对所有CVE样本运行 BinMind + Angr + QEMU + Ghidra，输出统一CSV。

用法: python eval/run_benchmark.py
输出: eval/benchmark_results.csv + eval/benchmark_summary.json
"""
import os, sys, json, time, csv, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
SAMPLE_ROOT = os.path.join(os.path.dirname(__file__), '..', 'tests', 'cve_samples')
EVAL_DIR = os.path.dirname(os.path.abspath(__file__))

def find_binaries(config="debug"):
    bins = []; target = f"vuln_{config}"
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        p = os.path.join(SAMPLE_ROOT, d, target)
        if os.path.isfile(p):
            bins.append({"name": d, "path": p})
    return bins

def run_binmind(binary):
    t0 = time.time()
    try:
        from patching import AutoPatcher
        r = AutoPatcher(binary["path"]).analyze_and_patch()
        return {"detected": len(r.vulnerabilities) > 0, "vulns": len(r.vulnerabilities),
                "time": round(time.time()-t0,2), "error": None}
    except Exception as e:
        return {"detected": False, "vulns": 0, "time": round(time.time()-t0,2), "error": str(e)[:100]}

def run_external(script, binary, args=None):
    t0 = time.time()
    cmd = [sys.executable, os.path.join(EVAL_DIR, script), binary["path"]]
    if args: cmd.extend(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        data = json.loads(r.stdout) if r.stdout else {}
        data["time_secs"] = round(time.time()-t0, 2)
        return data
    except:
        return {"detected": False, "time_secs": round(time.time()-t0,2), "error": "exec failed"}

# crash inputs for heap overflow samples
CRASH_ARGS = {"heap_overflow": ["512"], "stack_overflow": ["A"*200, "512"]}

def main():
    binaries = find_binaries("debug")
    if not binaries:
        print("No binaries found. Run: cd tests && python compile_samples.py debug")
        return 1
    rows = [["sample","tool","detected","time_secs","vuln_count","error"]]
    summary = {}
    for b in binaries:
        crash_args = []
        for k, v in CRASH_ARGS.items():
            if k in b["name"]: crash_args = v
        for tool_name, runner in [
            ("BinMind", lambda: run_binmind(b)),
            ("Angr", lambda: run_external("angr_explorer.py", b)),
            ("QEMU+Trace", lambda: run_external("qemu_tracer.py", b, crash_args)),
            ("Ghidra", lambda: run_external("ghidra_headless.py", b)),
        ]:
            r = runner()
            rows.append([b["name"], tool_name, str(r.get("detected",False)),
                        str(r.get("time_secs", r.get("time",0))),
                        str(r.get("vulns", r.get("vuln_count", 0))),
                        r.get("error","")[:100]])
            print(f"  [{tool_name:12s}] {b['name']:45s} detected={r.get('detected',False)}")

    csv_path = os.path.join(EVAL_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    print(f"\nCSV saved: {csv_path} ({len(rows)-1} rows)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
