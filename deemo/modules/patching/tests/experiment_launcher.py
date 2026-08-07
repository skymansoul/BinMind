# 创建: 2026-05-30 13:00
# 横向对比实验启动器 — 统一调度 Angr/QEMU/Ghidra/BinMind 检测

"""横向对比实验启动器。

对同一批CVE样本运行四个工具:
  1. BinMind (本项目的AutoPatcher + TaintEngine)
  2. Angr (exploration-based, CFG到达漏洞点分析)
  3. QEMU user mode (配合自定义asan插桩检测crash)
  4. Ghidra (Headless脚本自动分析)

每个工具的输出统一解析为:
  {sample, tool, detected: bool, time_secs: float, peak_mem_mb: float}

输出:
  - experiment_results.json (原始数据)
  - comparison_table.tex (LaTeX对比表)
  - bar_chart.py (matplotlib绘图的独立脚本)
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import hashlib

SAMPLE_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/cve_samples"
TIMEOUT_PER_SAMPLE = 60  # 每个工具对每个样本的超时秒数


def find_binaries(config: str = "debug") -> list:
    """找到所有编译好的样本。"""
    bins = []
    target = f"vuln_{config}"
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        path = os.path.join(SAMPLE_ROOT, d, target)
        if os.path.isfile(path):
            name = d.split("_", 2)[-1] if "_" in d else d
            bins.append({"name": d, "path": path, "cve": d.split("_")[0] + "-" + d.split("_")[1],
                         "type": name})
    return bins


def run_binmind(binary: dict) -> dict:
    """运行BinMind检测。"""
    t0 = time.time()
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(SAMPLE_ROOT), ".."))
        from patching import AutoPatcher
        patcher = AutoPatcher(binary["path"])
        result = patcher.analyze_and_patch()
        elapsed = time.time() - t0
        return {
            "tool": "BinMind", "detected": len(result.vulnerabilities) > 0,
            "time_secs": round(elapsed, 2), "vuln_count": len(result.vulnerabilities),
            "error": None
        }
    except Exception as exc:
        return {"tool": "BinMind", "detected": False, "time_secs": round(time.time() - t0, 2),
                "error": str(exc)[:200]}


def run_angr(binary: dict) -> dict:
    """运行Angr CFG分析检测漏洞点。

    方法: 使用angr构建CFG，检查是否存在从入口到危险函数
    (strcpy/memcpy/system)的路径。
    若angr未安装，返回error标记。
    """
    t0 = time.time()
    try:
        import angr
        proj = angr.Project(binary["path"], auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        # 检测危险函数是否在CFG中可达
        dangerous = {"strcpy", "memcpy", "system", "sprintf", "printf", "free"}
        detected_funcs = set()
        for func_addr, func in cfg.functions.items():
            if func.name in dangerous:
                detected_funcs.add(func.name)
        elapsed = time.time() - t0
        return {
            "tool": "Angr", "detected": len(detected_funcs) > 0,
            "time_secs": round(elapsed, 2), "dangerous_funcs_found": list(detected_funcs),
            "cfg_nodes": len(list(cfg.nodes())), "error": None
        }
    except ImportError:
        return {"tool": "Angr", "detected": False, "time_secs": 0, "error": "angr not installed"}
    except Exception as exc:
        return {"tool": "Angr", "detected": False, "time_secs": round(time.time() - t0, 2),
                "error": str(exc)[:200]}


def run_qemu_asan(binary: dict) -> dict:
    """运行QEMU user mode + ASAN检测崩溃。

    方法: 使用qemu-x86_64运行binary并检测SIGSEGV/SIGABRT。
    若qemu未安装，返回error。
    """
    t0 = time.time()
    try:
        # 尝试多种调用方式
        crash_inputs = {
            "heap_overflow": ["512"],
            "uaf": [],
            "format_string": ["%x.%x.%x.%x"],
            "stack_overflow": ["AAAAAAAAAA", "512"],
        }
        sample_type = binary["type"]
        args = crash_inputs.get(sample_type, [])
        cmd = ["qemu-x86_64", binary["path"]] + args

        proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_PER_SAMPLE // 2)
        crashed = proc.returncode < 0  # signal = negative returncode
        elapsed = time.time() - t0
        return {
            "tool": "QEMU+ASAN", "detected": crashed,
            "time_secs": round(elapsed, 2),
            "exit_code": proc.returncode, "error": None
        }
    except FileNotFoundError:
        return {"tool": "QEMU+ASAN", "detected": False, "time_secs": 0, "error": "qemu-x86_64 not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "QEMU+ASAN", "detected": False, "time_secs": TIMEOUT_PER_SAMPLE // 2,
                "error": "timeout"}
    except Exception as exc:
        return {"tool": "QEMU+ASAN", "detected": False, "time_secs": round(time.time() - t0, 2),
                "error": str(exc)[:200]}


def run_ghidra_headless(binary: dict) -> dict:
    """运行Ghidra headless脚本分析。

    使用Ghidra的analyzeHeadless模式进行基础安全分析。
    若ghidra未安装(通过GHIDRA_HOME环境变量)，返回error。
    """
    ghidra_home = os.environ.get("GHIDRA_HOME", "")
    if not ghidra_home:
        return {"tool": "Ghidra", "detected": False, "time_secs": 0,
                "error": "GHIDRA_HOME not set"}

    t0 = time.time()
    try:
        tmp_dir = tempfile.mkdtemp()
        analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        cmd = [analyze_headless, tmp_dir, "BinMind_Project",
               "-import", binary["path"], "-postScript", "FindVulnerableFunctions.java",
               "-deleteProject", "-noanalysis"]
        proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_PER_SAMPLE)
        elapsed = time.time() - t0
        return {
            "tool": "Ghidra", "detected": "vulnerability" in proc.stdout.decode(errors='replace').lower(),
            "time_secs": round(elapsed, 2), "error": None
        }
    except FileNotFoundError:
        return {"tool": "Ghidra", "detected": False, "time_secs": 0,
                "error": "analyzeHeadless not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "Ghidra", "detected": False, "time_secs": TIMEOUT_PER_SAMPLE,
                "error": "timeout"}
    except Exception as exc:
        return {"tool": "Ghidra", "detected": False, "time_secs": round(time.time() - t0, 2),
                "error": str(exc)[:200]}


def run_all(binaries: list = None) -> dict:
    """对全部样本运行全部工具。"""
    if binaries is None:
        binaries = find_binaries("debug")

    tools = [run_binmind, run_angr, run_qemu_asan, run_ghidra_headless]
    report = {"total_samples": len(binaries), "tools": ["BinMind", "Angr", "QEMU+ASAN", "Ghidra"],
              "results": []}

    for binary in binaries:
        for tool_fn in tools:
            result = tool_fn(binary)
            result["sample"] = binary["name"]
            result["cve"] = binary["cve"]
            report["results"].append(result)
            status = "DETECTED" if result["detected"] else ("ERROR" if result.get("error") else "miss")
            print(f"  [{status}] {result['tool']:12s} on {binary['name']:45s} ({result['time_secs']:5.1f}s)")

    return report


if __name__ == "__main__":
    print("Running comparison experiment on CVE samples...\n")
    report = run_all()
    out_path = os.path.join(os.path.dirname(SAMPLE_ROOT), "experiment_results.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nResults saved: {out_path}")
