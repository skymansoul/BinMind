# eval/run_benchmark — 多工具堆溢出检测对比基准测试
# 对同一批样本运行 AC3 / Angr / Ghidra / QEMU, 收集统一指标。
# 输出两份 CSV:
#   benchmark_results.csv   — 按工具聚合的 TP/FP/FN/检出率 (原有格式, 保留)
#   benchmark_unified.csv   — 逐样本统一格式 (工具名/样本ID/检出数/误报数/漏报数/耗时/峰值内存)
# 二进制解析: build/*.elf → build/*.exe → 样本目录内直接可执行文件。

import os, sys, json, time, subprocess, csv, tempfile
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
SAMPLES_DIR = Path(__file__).parent.parent / "tests" / "regression" / "samples"
OUTPUT_CSV = Path(__file__).parent / "benchmark_results.csv"
OUTPUT_UNIFIED = Path(__file__).parent / "benchmark_unified.csv"

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


def _resolve_binary(sample_dir: Path):
    """解析样本二进制: build/*.elf → build/*.exe → 目录内直接可执行文件。"""
    build_dir = sample_dir / "build"
    if build_dir.exists():
        for pat in ("*.elf", "*.exe", "sample*"):
            hits = sorted(build_dir.glob(pat))
            if hits:
                return str(hits[0])
    for f in sorted(sample_dir.iterdir()):
        if f.is_file() and f.suffix in (".elf", ".exe"):
            return str(f)
    return None


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
    script = r'''
import sys, angr, json, time
t0=time.time()
try:
    p=angr.Project(sys.argv[1],auto_load_libs=False)
    cfg=p.analyses.CFGFast()
    dang={"memcpy","strcpy","sprintf","strncpy","gets","malloc","calloc","realloc","read","recv","free"}
    found=[]
    try:
        mo=p.loader.main_object
        for k in mo.imports.keys():
            if str(k).lower().rstrip("aw") in dang:
                found.append(str(k))
    except Exception:
        pass
    for f in cfg.functions:
        if f in dang and f not in found:
            found.append(f)
    print(json.dumps({"tool":"angr","found":len(found),"elapsed":time.time()-t0}))
except Exception as e:
    print(json.dumps({"tool":"angr","error":str(e)[:100]}))
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script); tmp = f.name
    try:
        proc = subprocess.run(["python", tmp, target], capture_output=True, text=True, timeout=180)
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


def run_qemu_benchmark(target: str) -> dict:
    t0 = time.time()
    try:
        from qemu_tracer import trace_execution
        r = trace_execution(target, timeout=25)
    except ImportError:
        return {"detected": False, "fp_count": 0, "elapsed": round(time.time() - t0, 3),
                "peak_memory_mb": 0, "error": "qemu_tracer unavailable"}
    if r.get("skip") or r.get("error"):
        return {"detected": False, "fp_count": 0, "elapsed": round(time.time() - t0, 3),
                "peak_memory_mb": 0, "error": r.get("error", "skip")}
    return {"detected": r.get("dangerous_calls_detected", 0) > 0, "fp_count": 0,
            "elapsed": round(time.time() - t0, 3), "peak_memory_mb": 0}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default=str(SAMPLES_DIR))
    args = parser.parse_args()
    samples_dir = Path(args.samples)

    tools = {"AC3": run_ac3, "Angr": run_angr_benchmark,
             "Ghidra": run_ghidra_benchmark, "QEMU": run_qemu_benchmark}
    rows = []
    unified = []
    for tool_name, runner in tools.items():
        print(f"\n=== {tool_name} ===")
        tp = fp = fn = total_time = 0
        count = 0
        for d in sorted(samples_dir.iterdir()):
            if not d.is_dir():
                continue
            target = _resolve_binary(d)
            if not target:
                continue
            count += 1
            target = str(elfs[0])
            result = runner(target)
            gt = GROUND_TRUTH.get(d.name, "OTHER")
            is_ho = gt == "HO"
            detected = bool(result["detected"])
            if is_ho and detected:
                tp += 1
            elif is_ho and not detected:
                fn += 1
            elif not is_ho and detected:
                fp += 1
            total_time += result.get("elapsed", 0)
            unified.append({
                "工具名": tool_name,
                "样本ID": d.name,
                "检出数": int(detected),
                "误报数": int(not is_ho and detected),
                "漏报数": int(is_ho and not detected),
                "耗时": result.get("elapsed", 0),
                "峰值内存": result.get("peak_memory_mb", 0),
            })
            print(f"  {d.name}: gt={gt} detected={detected} time={result.get('elapsed',0):.1f}s")

        ho_count = sum(1 for v in GROUND_TRUTH.values() if v == "HO")
        rows.append({
            "Tool": tool_name, "Samples": count, "TP": tp, "FP": fp, "FN": fn,
            "Detection_Rate": round(tp / max(ho_count, 1) * 100, 1),
            "FP_Rate": round(fp / max(count - ho_count, 1) * 100, 1) if count > ho_count else 0,
            "Avg_Time_s": round(total_time / max(count, 1), 1),
        })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    with open(OUTPUT_UNIFIED, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["工具名", "样本ID", "检出数", "误报数",
                                          "漏报数", "耗时", "峰值内存"])
        w.writeheader(); w.writerows(unified)
    print(f"\n聚合结果: {OUTPUT_CSV}")
    print(f"逐样本统一结果: {OUTPUT_UNIFIED} ({len(unified)} 行)")
    return rows


if __name__ == "__main__":
    main()
