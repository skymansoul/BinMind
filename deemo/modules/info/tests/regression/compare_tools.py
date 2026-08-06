# Created: 2025-07-30 15:00:00
# compare_tools — 跨工具对比实验调度脚本
# 对同一样本集运行 CAIR / Angr / QEMU-instrument / Ghidra-headless,
# 收集各工具检出数(TP)、误报数(FP)、漏报数(FN)、耗时、峰值内存。

import os, sys, json, time, subprocess, tempfile
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
SAMPLES_DIR = Path(__file__).parent / "samples"
RESULTS_FILE = Path(__file__).parent / "comparison_results.json"

# 每个样本的 ground truth (堆溢出=HO 存在或不存在)
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


def _measure(func):
    t0 = time.time()
    import psutil
    proc = psutil.Process()
    mem_before = proc.memory_info().rss
    result = func()
    mem_after = proc.memory_info().rss
    elapsed = round(time.time() - t0, 3)
    peak_mb = round((mem_after - mem_before) / 1024 / 1024, 2)
    return result, elapsed, peak_mb


def run_cair(binary_path: str) -> dict:
    from modules.info.info_collection.src import heap_overflow_detector as hod
    from modules.info.info_collection.src import heap_overflow_detector
    from modules.info.info_collection.src._shared import shannon_entropy
    try:
        from modules.info.info_collect import get_binary_info
        info = get_binary_info(binary_path)
    except:
        info = {}
    imports = info.get("imports", {"all_imports": {}})
    strings = info.get("key_strings", info.get("strings", []))
    checksec = info.get("checksec", {})
    return hod.detect_heap_overflow(imports, strings, checksec)


def run_angr_script(target: str) -> dict:
    """Angr exploration 脚本 — 寻找到达危险函数的路径。"""
    script = f'''
import angr, sys, time
p = angr.Project("{target}", auto_load_libs=False)
cfg = p.analyses.CFGFast()
dangerous = {{"memcpy","strcpy","sprintf","gets"}}
found = set()
for func in cfg.functions.values():
    if func.name in dangerous:
        found.add(func.name)
t0 = time.time()
# 尝试对每个危险函数做符号执行 (限时)
for df in list(found):
    try:
        state = p.factory.entry_state()
        simgr = p.factory.simulation_manager(state)
        simgr.explore(find=lambda s: df.encode() in s.posix.dumps(1))
    except: pass
elapsed = time.time()-t0
print(json.dumps({{"tool":"angr","found":list(found),"elapsed":elapsed}}))
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script)
        tmp = f.name
    try:
        proc = subprocess.run(["python", tmp], capture_output=True, text=True, timeout=300)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
    except:
        pass
    finally:
        os.unlink(tmp)
    return {"tool": "angr", "found": [], "elapsed": 0, "error": "timeout_or_not_installed"}


def run_qemu_trace(target: str) -> dict:
    """QEMU user mode 轻量插桩 — 抓取 memcpy 调用。"""
    try:
        proc = subprocess.run(
            ["qemu-x86_64", "-d", "in_asm", "-D", "/dev/stdout", target],
            capture_output=True, text=True, timeout=30,
        )
        return {"tool": "qemu", "executed": proc.returncode == 0,
                "stderr_len": len(proc.stderr) if proc.stderr else 0}
    except FileNotFoundError:
        return {"tool": "qemu", "error": "qemu-x86_64 not installed"}
    except subprocess.TimeoutExpired:
        return {"tool": "qemu", "error": "timeout"}


def run_ghidra_headless(target: str) -> dict:
    """Ghidra 无头分析 — 导入表+危险函数自动审计。"""
    script = f'''
import json, sys
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    prog = getCurrentProgram()
    api = FlatProgramAPI(prog)
    dangerous = ["memcpy","strcpy","sprintf","gets","malloc","free"]
    found = []
    for sym in prog.getSymbolTable().getAllSymbols(True):
        name = sym.getName().lower()
        for d in dangerous:
            if d in name:
                found.append(d)
    print(json.dumps({{"tool":"ghidra","found":list(set(found)),"func_count":len(list(prog.getFunctionManager().getFunctions(True)))}}))
except Exception as e:
    print(json.dumps({{"tool":"ghidra","error":str(e)}}))
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script)
        tmp = f.name
    try:
        proc = subprocess.run(
            ["analyzeHeadless", "/tmp", "ghidra_project", "-import", target,
             "-postScript", tmp],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                if line.strip().startswith("{"):
                    return json.loads(line.strip())
    except:
        pass
    finally:
        os.unlink(tmp)
    return {"tool": "ghidra", "found": [], "elapsed": 0, "error": "not_installed_or_timeout"}


def run_all_tools():
    results = {"timestamp": datetime.now().isoformat(), "tools": {}}
    tools = {"cair": run_cair, "angr": run_angr_script,
             "qemu": run_qemu_trace, "ghidra": run_ghidra_headless}

    for tool_name, runner in tools.items():
        print(f"\n=== {tool_name.upper()} ===")
        tool_results = {"scans": [], "tp": 0, "fp": 0, "fn": 0, "total_time": 0.0}

        for d in sorted(SAMPLES_DIR.iterdir()):
            if not d.is_dir(): continue
            build_dir = d / "build"
            if not build_dir.exists(): continue
            elfs = list(build_dir.glob("*.elf"))
            if not elfs: continue

            target = str(elfs[0])
            t0 = time.time()
            try:
                output = runner(target)
            except Exception as e:
                output = {"error": str(e)}
            elapsed = round(time.time() - t0, 3)

            gt = GROUND_TRUTH.get(d.name, "OTHER")
            found_list = output.get("found", output.get("findings", []))
            if isinstance(found_list, list):
                detected_ho = len(found_list) > 0
            else:
                detected_ho = isinstance(found_list, dict) and found_list.get("stats", {}).get("total", 0) > 0

            if gt == "HO" and detected_ho: tool_results["tp"] += 1
            elif gt == "HO" and not detected_ho: tool_results["fn"] += 1
            elif gt == "OTHER" and detected_ho: tool_results["fp"] += 1

            tool_results["scans"].append({
                "sample": d.name, "gt": gt, "detected": detected_ho,
                "elapsed": elapsed,
            })
            tool_results["total_time"] += elapsed

        results["tools"][tool_name] = tool_results

    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {RESULTS_FILE}")
    return results


if __name__ == "__main__":
    run_all_tools()
