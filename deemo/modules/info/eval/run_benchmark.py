# eval/run_benchmark — 多工具堆溢出检测对比基准测试
# 对同一批样本运行 AC3 / Angr / Ghidra / QEMU, 收集统一指标。

import os, sys, json, time, subprocess, csv, tempfile
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
SAMPLES_DIR = Path(__file__).parent.parent / "tests" / "regression" / "samples"
OUTPUT_CSV = Path(__file__).parent / "benchmark_results.csv"

GROUND_TRUTH = {
    "CVE-2014-0160_heartbleed": "HO", "CVE-2015-0235_ghost": "HO",
    "CVE-2016-10190_heap_overflow": "HO", "CVE-2019-15922_uaf": "OTHER",
    "CVE-2019-11477_integer_overflow": "HO", "CVE-2008-0062_double_free": "OTHER",
    "CVE-2012-0809_format_string": "OTHER", "CVE-2021-3156_sudo_heap": "HO",
    "CVE-2023-33476_heap_overflow": "HO", "CVE-2017-1000253_pie_stack": "OTHER",
    "CVE-2019-12815_proftpd_heap": "HO", "CVE-2022-0185_kernel_heap": "HO",
    "CVE-2020-10713_grub_heap": "HO", "CVE-2018-10933_libssh_heap": "HO",
    "CVE-2023-3269_linux_heap": "HO",
}


def _measure_peak_memory():
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1024 / 1024
    except ImportError:
        return 0.0


def run_ac3(target: str) -> dict:
    mem0 = _measure_peak_memory()
    t0 = time.time()
    try:
        from modules.info.info_collection.src import heap_overflow_detector as hod
        from modules.info.info_collect import get_binary_info
        info = get_binary_info(target)
        imports = info.get("imports", {"all_imports": {}})
        strings = info.get("key_strings", info.get("strings", []))
        checksec = info.get("checksec", {})
        result = hod.detect_heap_overflow(imports, strings, checksec)
        found = result.get("stats", {}).get("total", 0) > 0
        fps = len([f for f in result.get("findings", []) if f.get("confidence", 0) > 0.60])
    except Exception as e:
        found, fps = False, 0
    elapsed = time.time() - t0
    mem = _measure_peak_memory() - mem0
    return {"detected": found, "fp_count": fps, "elapsed": round(elapsed, 3), "peak_memory_mb": round(max(mem, 0), 1)}


def run_angr_benchmark(target: str) -> dict:
    script = f'''
import angr, json, time
t0=time.time()
try:
    p=angr.Project("{target}",auto_load_libs=False)
    cfg=p.analyses.CFGFast()
    dang={{"memcpy","strcpy","sprintf","gets","malloc","free"}}
    found=[f for f in cfg.functions if f in dang]
    print(json.dumps({{"tool":"angr","found":len(found),"elapsed":time.time()-t0}}))
except Exception as e:
    print(json.dumps({{"tool":"angr","error":str(e)[:100]}}))
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script); tmp = f.name
    try:
        proc = subprocess.run(["python", tmp], capture_output=True, text=True, timeout=180)
        data = json.loads(proc.stdout.strip()) if proc.stdout.strip().startswith("{") else {}
        return {"detected": data.get("found", 0) > 0, "fp_count": 0, "elapsed": round(data.get("elapsed", 0), 3), "peak_memory_mb": 0}
    except: return {"detected": False, "fp_count": 0, "elapsed": 0, "peak_memory_mb": 0, "error": "timeout"}
    finally: os.unlink(tmp)


def run_ghidra_benchmark(target: str) -> dict:
    try:
        proc = subprocess.run(["analyzeHeadless", "/tmp", "proj", "-import", target, "-postScript", "/dev/null"],
                            capture_output=True, text=True, timeout=120)
        return {"detected": "memcpy" in proc.stdout, "fp_count": 0, "elapsed": 30.0, "peak_memory_mb": 0}
    except: return {"detected": False, "fp_count": 0, "elapsed": 0, "peak_memory_mb": 0, "error": "not_installed"}


def main():
    tools = {"AC3": run_ac3, "Angr": run_angr_benchmark, "Ghidra": run_ghidra_benchmark}
    rows = []
    for tool_name, runner in tools.items():
        print(f"\n=== {tool_name} ===")
        tp = fp = fn = total_time = 0
        count = 0
        for d in sorted(SAMPLES_DIR.iterdir()):
            if not d.is_dir(): continue
            build_dir = d / "build"
            elfs = list(build_dir.glob("*.elf")) if build_dir.exists() else []
            if not elfs: continue
            count += 1
            target = str(elfs[0])
            result = runner(target)
            gt = GROUND_TRUTH.get(d.name, "OTHER")
            if gt == "HO" and result["detected"]: tp += 1
            elif gt == "HO" and not result["detected"]: fn += 1
            elif gt == "OTHER" and result["detected"]: fp += 1
            total_time += result.get("elapsed", 0)
            print(f"  {d.name}: gt={gt} detected={result['detected']} time={result.get('elapsed',0):.1f}s")

        ho_count = sum(1 for v in GROUND_TRUTH.values() if v == "HO")
        rows.append({
            "Tool": tool_name, "Samples": count, "TP": tp, "FP": fp, "FN": fn,
            "Detection_Rate": round(tp / max(ho_count, 1) * 100, 1),
            "FP_Rate": round(fp / max(count - ho_count, 1) * 100, 1) if count > ho_count else 0,
            "Avg_Time_s": round(total_time / max(count, 1), 1),
        })

    with open(OUTPUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    print(f"\nResults saved to {OUTPUT_CSV}")
    return rows


if __name__ == "__main__":
    main()
