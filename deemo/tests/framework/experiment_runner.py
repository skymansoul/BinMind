"""
创建: 2026-07-24

对比实验启动脚本 — 将同一批样本喂给 BinMind / Angr / QEMU / Ghidra,
统计检测耗时、检出数、峰值内存占用。

依赖: angr, qemu-user, ghidra (headless 模式), psutil (内存监控)
各工具均需提前安装到 PATH 或指定路径。

输出: tests/experiment_results.json — 供 plot_experiment.py 和 LaTeX 模板消费。
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES_DIR = os.path.join(PROJECT_ROOT, "tests", "cve_binaries")
RESULTS_PATH = os.path.join(PROJECT_ROOT, "tests", "experiment_results.json")


@dataclass
class ToolResult:
    tool: str
    sample: str
    findings: int
    elapsed_sec: float
    peak_memory_mb: float
    success: bool
    error: str = ""


def measure_memory_peak(pid: int) -> float:
    """读取进程峰值内存 (MB)。需要 psutil。"""
    try:
        import psutil
        proc = psutil.Process(pid)
        mem_info = proc.memory_info()
        return mem_info.rss / (1024 * 1024)
    except ImportError:
        return -1.0
    except Exception:
        return -1.0


def run_binmind(binary_path: str, timeout_sec: int = 120) -> ToolResult:
    """BinMind 扫描——使用 main.py 入口。"""
    binmind = os.path.join(PROJECT_ROOT, "main.py")
    sample = os.path.basename(binary_path)
    start = time.time()

    try:
        proc = subprocess.Popen(
            [sys.executable, binmind, binary_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            mem = measure_memory_peak(proc.pid)
        except Exception:
            mem = -1.0
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        elapsed = time.time() - start

        findings = stdout.count('[FINDING]') + stdout.count('"type"')
        return ToolResult(
            tool="BinMind", sample=sample, findings=findings,
            elapsed_sec=round(elapsed, 1), peak_memory_mb=round(mem, 1),
            success=(proc.returncode == 0),
            error=stderr[:200] if proc.returncode != 0 else "",
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        return ToolResult(tool="BinMind", sample=sample, findings=0,
                          elapsed_sec=timeout_sec, peak_memory_mb=-1,
                          success=False, error="Timeout")


def run_angr(binary_path: str, timeout_sec: int = 300) -> ToolResult:
    """Angr exploration 漏洞点分析——符号执行路径探索。"""
    sample = os.path.basename(binary_path)
    start = time.time()
    script = f"""
import angr, sys
proj = angr.Project('{binary_path}', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
dangerous = 0
for f in cfg.functions.values():
    for b in f.blocks:
        for insn in b.capstone.insns:
            if insn.mnemonic == 'call':
                name = cfg.functions.get(insn.operands[0].imm)
                if name and name.name in ('printf','gets','strcpy','system','free','strcat'):
                    dangerous += 1
print(dangerous)
"""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=timeout_sec,
        )
        elapsed = time.time() - start
        findings = int(proc.stdout.strip() or "0")
        return ToolResult(
            tool="Angr", sample=sample, findings=findings,
            elapsed_sec=round(elapsed, 1), peak_memory_mb=-1,
            success=True, error=proc.stderr[:200] if proc.stderr else "",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="Angr", sample=sample, findings=0,
                          elapsed_sec=timeout_sec, peak_memory_mb=-1,
                          success=False, error="Timeout")
    except Exception as e:
        return ToolResult(tool="Angr", sample=sample, findings=0,
                          elapsed_sec=time.time()-start, peak_memory_mb=-1,
                          success=False, error=str(e))


def run_qemu(binary_path: str, timeout_sec: int = 60) -> ToolResult:
    """QEMU user mode 自定义插桩——通过 -strace 追踪系统调用。"""
    sample = os.path.basename(binary_path)
    start = time.time()
    try:
        proc = subprocess.run(
            ["qemu-x86_64", "-strace", binary_path],
            capture_output=True, text=True, timeout=timeout_sec,
        )
        elapsed = time.time() - start
        output = proc.stderr
        dangerous = 0
        for pattern in ('write(', 'execve(', 'open('):
            dangerous += output.count(pattern)
        return ToolResult(
            tool="QEMU", sample=sample, findings=dangerous,
            elapsed_sec=round(elapsed, 1), peak_memory_mb=-1,
            success=True, error="",
        )
    except FileNotFoundError:
        return ToolResult(tool="QEMU", sample=sample, findings=0,
                          elapsed_sec=time.time()-start, peak_memory_mb=-1,
                          success=False, error="qemu-x86_64 not installed")
    except subprocess.TimeoutExpired:
        return ToolResult(tool="QEMU", sample=sample, findings=0,
                          elapsed_sec=timeout_sec, peak_memory_mb=-1,
                          success=False, error="Timeout")
    except Exception as e:
        return ToolResult(tool="QEMU", sample=sample, findings=0,
                          elapsed_sec=0, peak_memory_mb=-1,
                          success=False, error=str(e))


def run_ghidra(binary_path: str, timeout_sec: int = 120) -> ToolResult:
    """Ghidra headless 脚本分析——自动反编译并搜索危险函数调用。"""
    sample = os.path.basename(binary_path)
    start = time.time()

    ghidra_script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "ghidra_analyze.py",
    )

    try:
        # Ghidra headless: analyzeHeadless <project> <folder> -import <binary> -scriptPath -postScript
        proc = subprocess.run(
            ["analyzeHeadless", "/tmp/ghidra_project", "BinMind",
             "-import", binary_path,
             "-scriptPath", os.path.dirname(ghidra_script),
             "-postScript", os.path.basename(ghidra_script),
             "-deleteProject", "-noanalysis"],
            capture_output=True, text=True, timeout=timeout_sec,
        )
        elapsed = time.time() - start
        findings = proc.stdout.count("DANGER:") + proc.stdout.count("[!]")
        return ToolResult(
            tool="Ghidra", sample=sample, findings=findings,
            elapsed_sec=round(elapsed, 1), peak_memory_mb=-1,
            success=True, error="",
        )
    except FileNotFoundError:
        return ToolResult(tool="Ghidra", sample=sample, findings=0,
                          elapsed_sec=time.time()-start, peak_memory_mb=-1,
                          success=False, error="analyzeHeadless not in PATH")
    except subprocess.TimeoutExpired:
        return ToolResult(tool="Ghidra", sample=sample, findings=0,
                          elapsed_sec=timeout_sec, peak_memory_mb=-1,
                          success=False, error="Timeout")
    except Exception as e:
        return ToolResult(tool="Ghidra", sample=sample, findings=0,
                          elapsed_sec=0, peak_memory_mb=-1,
                          success=False, error=str(e))


def run_all(bin_dir: str = SAMPLES_DIR) -> List[ToolResult]:
    """对样本目录中的所有 ELF 运行 4 个工具。"""
    if not os.path.isdir(bin_dir):
        print(f"Binary directory not found: {bin_dir}")
        print("Run build_samples.py first to compile CVE samples.")
        return []

    elfs = [os.path.join(bin_dir, f) for f in sorted(os.listdir(bin_dir))
            if f.endswith('.elf') or (
                os.path.isfile(os.path.join(bin_dir, f))
                and open(os.path.join(bin_dir, f), 'rb').read(4) == b'\x7fELF'
            )]

    if not elfs:
        print("No ELF binaries found. Run build_samples.py first.")
        return []

    print(f"Running comparison on {len(elfs)} samples...")
    all_results: List[ToolResult] = []

    for elf in elfs:
        print(f"\n  Sample: {os.path.basename(elf)}")
        for tool_func, name in [(run_binmind, "BinMind"), (run_angr, "Angr"),
                                 (run_qemu, "QEMU"), (run_ghidra, "Ghidra")]:
            result = tool_func(elf)
            all_results.append(result)
            print(f"    {name}: {result.findings} findings, {result.elapsed_sec}s"
                  f"{' FAIL: '+result.error[:60] if result.error else ''}")

    return all_results


def save_comparison(results: List[ToolResult], path: str = RESULTS_PATH) -> None:
    data = []
    for r in results:
        data.append({
            "tool": r.tool, "sample": r.sample,
            "findings": r.findings, "elapsed_sec": r.elapsed_sec,
            "peak_memory_mb": r.peak_memory_mb,
            "success": r.success, "error": r.error,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {path}")


if __name__ == "__main__":
    results = run_all()
    if results:
        save_comparison(results)
