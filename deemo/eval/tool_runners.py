"""
外部工具运行器 — 独立于 benchmark 框架的工具调用封装。

每个函数返回统一格式的 dict:
  {tool, sample, duration_s, success, error, ...tool-specific fields}
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any, Dict, List


TIMEOUT_PER_SAMPLE = 120


def run_binmind(binary_path: str, sample_id: str) -> dict:
    """运行 BinMind 堆溢出扫描。"""
    t0 = time.perf_counter()
    try:
        cmd = [sys.executable, "-c", f"""
import sys; sys.path.insert(0, '.')
from core.heap_overflow_verifier import HeapOverflowVerifier
from modules.info.analysis.taint_propagation_source_level import detect_heap_overflow
import subprocess, json

code = subprocess.run(['objdump', '-d', '{binary_path}'],
    capture_output=True, text=True, timeout=15).stdout or ""
findings_raw = detect_heap_overflow(code)
verifier = HeapOverflowVerifier()
confirmed, filtered = verifier.verify_findings(findings_raw)
print(json.dumps({{"confirmed": len(confirmed),
    "filtered": len(filtered), "total": len(findings_raw)}}))
"""]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=os.path.dirname(os.path.dirname(__file__)))
        dt = round(time.perf_counter() - t0, 3)
        import json
        try:
            lines = r.stdout.strip().split('\n')
            data = json.loads(lines[-1] if lines else '{}')
        except Exception:
            data = {}

        return {
            "tool": "BinMind", "sample": sample_id,
            "findings_total": data.get("total", 0),
            "findings_confirmed": data.get("confirmed", 0),
            "findings_filtered": data.get("filtered", 0),
            "duration_s": dt, "success": True, "error": "",
        }
    except Exception as e:
        return {
            "tool": "BinMind", "sample": sample_id,
            "findings_total": 0, "findings_confirmed": 0,
            "findings_filtered": 0,
            "duration_s": round(time.perf_counter() - t0, 3),
            "success": False, "error": str(e)[:200],
        }


def run_angr_analysis(binary_path: str, sample_id: str) -> dict:
    """Angr: CFG + 危险函数调用计数。"""
    t0 = time.perf_counter()
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False)

        danger = {'malloc', 'calloc', 'realloc', 'memcpy', 'strcpy',
                  'strncpy', 'strcat', 'free', 'gets', 'sprintf',
                  'snprintf', 'printf', 'scanf'}
        call_count = 0
        found = set()
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        try:
                            target = cfg.functions.get(insn.operands[0].imm)
                            if target and target.name in danger:
                                call_count += 1
                                found.add(target.name)
                        except Exception:
                            pass

        dt = round(time.perf_counter() - t0, 3)
        return {
            "tool": "Angr", "sample": sample_id,
            "functions_total": len(cfg.functions),
            "dangerous_calls": call_count,
            "functions_found": list(found),
            "duration_s": dt, "success": True, "error": "",
        }
    except ImportError:
        return {"tool": "Angr", "sample": sample_id, "duration_s": 0,
                "success": False, "error": "angr not installed"}
    except Exception as e:
        return {"tool": "Angr", "sample": sample_id,
                "duration_s": round(time.perf_counter() - t0, 3),
                "success": False, "error": str(e)[:200]}


def run_qemu_trace(binary_path: str, sample_id: str) -> dict:
    """QEMU user-mode: 指令执行计数。"""
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            ["qemu-x86_64", "-d", "in_asm", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        dt = round(time.perf_counter() - t0, 3)
        insn_lines = r.stdout.count('\n') if r.stdout else 0
        return {
            "tool": "QEMU-user", "sample": sample_id,
            "instructions_executed": insn_lines,
            "duration_s": dt, "success": True, "error": "",
        }
    except FileNotFoundError:
        return {"tool": "QEMU-user", "sample": sample_id, "duration_s": 0,
                "success": False, "error": "qemu-x86_64 not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "QEMU-user", "sample": sample_id,
                "instructions_executed": 0,
                "duration_s": TIMEOUT_PER_SAMPLE,
                "success": False, "error": "timeout"}
    except Exception as e:
        return {"tool": "QEMU-user", "sample": sample_id,
                "duration_s": round(time.perf_counter() - t0, 3),
                "success": False, "error": str(e)[:200]}


def run_ghidra_analysis(binary_path: str, sample_id: str) -> dict:
    """Ghidra headless: 委托给 analyzeHeadless。"""
    t0 = time.perf_counter()
    ghidra_home = os.environ.get("GHIDRA_HOME", "")
    if not ghidra_home:
        return {"tool": "Ghidra", "sample": sample_id, "duration_s": 0,
                "success": False, "error": "GHIDRA_HOME not set"}

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        r = subprocess.run(
            [analyze_headless, "/tmp/ghidra_bench_proj", sample_id,
             "-import", binary_path, "-scriptPath", script_dir,
             "-postScript", "ghidra_heap_scan.py", "-noanalysis"],
            capture_output=True, text=True, timeout=60,
        )
        dt = round(time.perf_counter() - t0, 3)
        return {
            "tool": "Ghidra", "sample": sample_id,
            "duration_s": dt, "success": True, "error": "",
            "stdout_tail": r.stdout[-200:] if r.stdout else "",
        }
    except Exception as e:
        return {"tool": "Ghidra", "sample": sample_id,
                "duration_s": round(time.perf_counter() - t0, 3),
                "success": False, "error": str(e)[:200]}


TOOL_RUNNERS = {
    "binmind": run_binmind,
    "angr": run_angr_analysis,
    "qemu": run_qemu_trace,
    "ghidra": run_ghidra_analysis,
}
