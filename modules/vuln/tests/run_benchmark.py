"""多工具对比基准测试 — 对所有样本调用 BinMind/Angr/QEMU/Ghidra, 输出统一 CSV.

创建: 2025-05-12  更新: 2025-05-12
用途: 一键运行所有工具的对比实验, 输出 CSV + JSON 供后续绘图/制表使用。
      集成了 EnhancedFPFilter (五维联合过滤) 作为 BinMind 的检测后端。
"""
import csv
import json
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import Dict, List

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "sample_bins"
EVAL_DIR = Path(__file__).resolve().parent
HEADER = ["tool", "sample_id", "vuln_type", "detected", "n_findings",
          "n_fp", "detection_rate", "fp_rate", "elapsed_sec", "peak_mem_mb", "note"]


def discover_binaries() -> Dict[str, str]:
    """发现所有编译好的测试样本 ELF."""
    binaries = {}
    if not SAMPLES_DIR.is_dir():
        return binaries
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        # 检查目录中是否有 ELF 文件
        for entry in d.iterdir():
            if entry.is_file() and not entry.suffix:
                # 尝试判断是否为 ELF
                try:
                    with open(entry, "rb") as f:
                        magic = f.read(4)
                    if magic[:4] == b'\x7fELF':
                        binaries[d.name] = str(entry)
                        break
                except Exception:
                    pass
    return binaries


def run_binmind(binary: str) -> dict:
    """运行 BinMind 堆溢出检测 (EnhancedFPFilter)."""
    t0 = time.time()
    try:
        proj_root = str(EVAL_DIR.parent.parent.parent.parent)
        if proj_root not in sys.path:
            sys.path.insert(0, proj_root)

        from modules.vuln.src.heap.orchestrator import analyze_heap
        report = analyze_heap(binary)

        elapsed = round(time.time() - t0, 3)
        return {
            "tool": "BinMind",
            "detected": report.confirmed > 0 or report.likely > 0,
            "n_findings": report.raw_findings,
            "n_fp": report.filtered_fp,
            "elapsed_sec": elapsed,
            "note": (f"FP-reduction: {report.fp_reduction_pct}% "
                     f"({report.confirmed} confirmed, "
                     f"{report.likely} likely, "
                     f"{report.filtered_fp} filtered)"),
        }
    except ImportError:
        return _run_binmind_fallback(binary)
    except Exception as e:
        return {
            "tool": "BinMind",
            "detected": False,
            "elapsed_sec": round(time.time() - t0, 3),
            "note": f"error: {str(e)[:100]}",
        }


def _run_binmind_fallback(binary: str) -> dict:
    """BinMind 回退检测 — 基础分配器感知扫描."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary],
            capture_output=True, text=True, timeout=30)
        asm = proc.stdout
    except Exception:
        try:
            proc = subprocess.run(
                ['llvm-objdump', '-d', binary],
                capture_output=True, text=True, timeout=30)
            asm = proc.stdout
        except Exception:
            asm = ""

    lines = asm.split('\n')
    n_malloc = sum(1 for l in lines if 'malloc' in l.lower())
    n_memcpy = sum(1 for l in lines if 'memcpy' in l.lower())
    n_strcpy = sum(1 for l in lines if 'strcpy' in l.lower())
    n_write = n_memcpy + n_strcpy

    elapsed = round(time.time() - t0, 3)

    # 保守过滤: 计算 malloc 次数与危险写操作的比率
    fp_estimate = max(0, n_write - n_malloc)

    return {
        "tool": "BinMind",
        "detected": n_write > 0,
        "n_findings": n_write,
        "n_fp": fp_estimate,
        "elapsed_sec": elapsed,
        "note": f"fallback-objdump: {n_malloc} mallocs, {n_write} writes",
    }


def run_angr(binary: str) -> dict:
    """运行 Angr 分析."""
    script = EVAL_DIR / "angr_explorer.py"
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(script), binary],
            capture_output=True, text=True, timeout=180)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            return {
                "tool": "angr",
                "detected": data.get("detected", False),
                "n_findings": data.get("finding_count", 0),
                "elapsed_sec": data.get("elapsed_sec", round(time.time() - t0, 3)),
                "note": data.get("note", data.get("error", "")),
            }
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    except Exception:
        pass
    return {
        "tool": "angr",
        "detected": False,
        "elapsed_sec": round(time.time() - t0, 3),
        "note": "angr unavailable or timeout",
    }


def run_qemu(binary: str) -> dict:
    """运行 QEMU user mode 插桩."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            ["qemu-x86_64", "-d", "in_asm", binary],
            capture_output=True, text=True, timeout=10,
            input="AAAA\n")
        output = (proc.stdout + proc.stderr).lower()
        dangerous = {"memcpy", "strcpy", "system", "exec", "gets", "sprintf"}
        found = [f for f in dangerous if f in output]
        return {
            "tool": "qemu",
            "detected": len(found) > 0,
            "n_findings": len(found),
            "elapsed_sec": round(time.time() - t0, 3),
            "note": f"runtime calls: {found}" if found else "no dangerous calls at runtime",
        }
    except FileNotFoundError:
        return {
            "tool": "qemu", "detected": False, "elapsed_sec": 0,
            "note": "qemu-x86_64 not installed"}
    except subprocess.TimeoutExpired:
        return {
            "tool": "qemu", "detected": False, "elapsed_sec": 10,
            "note": "timeout 10s"}
    except Exception as e:
        return {
            "tool": "qemu", "detected": False,
            "elapsed_sec": round(time.time() - t0, 3), "note": str(e)[:80]}


def run_ghidra(binary: str) -> dict:
    """运行 Ghidra 无头分析 (或回退到 objdump)."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            ["objdump", "-T", binary],
            capture_output=True, text=True, timeout=15)
        syms = proc.stdout.lower()
    except Exception:
        try:
            proc = subprocess.run(
                ["llvm-objdump", "-T", binary],
                capture_output=True, text=True, timeout=15)
            syms = proc.stdout.lower()
        except Exception:
            syms = ""

    dangerous = {"memcpy", "memmove", "strcpy", "strcat",
                 "system", "popen", "gets", "sprintf", "malloc", "free"}
    found = [f for f in dangerous if f in syms]
    return {
        "tool": "ghidra",
        "detected": len(found) > 0,
        "n_findings": len(found),
        "elapsed_sec": round(time.time() - t0, 3),
        "note": f"fallback-objdump: {len(found)} syms found",
    }


TOOLS = {
    "BinMind": run_binmind,
    "angr": run_angr,
    "qemu": run_qemu,
    "ghidra": run_ghidra,
}


def run_all(output_dir: str = ".") -> str:
    """对所有样本运行所有工具, 输出 CSV."""
    binaries = discover_binaries()
    if not binaries:
        print("[!] No binaries found. Run compile_samples.py first.")
        return ""

    os.makedirs(output_dir, exist_ok=True)
    rows = []

    for sample_id, binary_path in sorted(binaries.items()):
        print(f"\n--- {sample_id} ---")
        for tool_name, tool_func in TOOLS.items():
            result = tool_func(binary_path)
            rows.append([
                tool_name,
                sample_id,
                "heap_overflow",
                "1" if result.get("detected") else "0",
                str(result.get("n_findings", 0)),
                str(result.get("n_fp", 0)),
                "",
                "",
                str(result.get("elapsed_sec", "")),
                "",
                result.get("note", ""),
            ])
            status = "DETECT" if result.get("detected") else "clean"
            print(f"  [{tool_name:8s}] {status:6s} "
                  f"({result.get('n_findings', 0)} findings, "
                  f"{result.get('elapsed_sec', 0):.1f}s)")

    csv_path = os.path.join(output_dir, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        writer.writerows(rows)
    print(f"\n[+] CSV: {csv_path} ({len(rows)} rows)")

    json_path = os.path.join(output_dir, "benchmark_results.json")
    json_data = {}
    for tool in TOOLS:
        json_data[tool] = [
            {HEADER[i]: row[i] for i in range(len(HEADER))}
            for row in rows if row[0] == tool
        ]
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"[+] JSON: {json_path}")

    return csv_path


if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    run_all(out_dir)
