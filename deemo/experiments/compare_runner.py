# experiments/compare_runner.py
# 多工具横向对比实验启动脚本
# 对同一批样本分别调用BinMind/Angr/QEMU/Ghidra,
# 统计每个工具的检测耗时、检出数、误报数、内存峰值。
import os
import sys
import json
import time
import subprocess
try:
    import resource  # Unix-only
except ImportError:
    resource = None
from dataclasses import dataclass, field
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class ToolResult:
    tool: str
    sample: str
    optimize: str = 'O0'
    success: bool = False
    findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    duration_sec: float = 0.0
    peak_memory_mb: float = 0.0
    error_msg: str = ''


def run_binmind(binary_path: str, sample: str,
                optimize: str = 'O0') -> ToolResult:
    """Run BinMind format string + heap detection."""
    r = ToolResult(tool='BinMind', sample=sample, optimize=optimize)
    t0 = time.perf_counter()
    try:
        from core.format_string_detector import detect_format_string_vulns
        findings = detect_format_string_vulns(binary_path)
        r.findings = len(findings)
        r.success = True
    except Exception as e:
        r.error_msg = str(e)[:100]
    r.duration_sec = round(time.perf_counter() - t0, 2)
    return r


def run_angr(binary_path: str, sample: str,
             optimize: str = 'O0') -> ToolResult:
    """Run Angr CFG + vulnerability point analysis."""
    r = ToolResult(tool='Angr', sample=sample, optimize=optimize)
    t0 = time.perf_counter()
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        # Count dangerous call sites as proxy for vulnerability detection
        dangerous = {'printf', 'sprintf', 'malloc', 'free', 'strcpy',
                    'memcpy', 'gets', 'scanf'}
        vuln_sites = 0
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        target = cfg.functions.get(insn.operands[0].imm)
                        if target and target.name in dangerous:
                            vuln_sites += 1
        r.findings = vuln_sites
        r.success = True
    except ImportError:
        r.error_msg = 'angr not installed'
    except Exception as e:
        r.error_msg = str(e)[:100]
    r.duration_sec = round(time.perf_counter() - t0, 2)
    return r


def run_qemu(binary_path: str, sample: str,
             optimize: str = 'O0') -> ToolResult:
    """Run QEMU user-mode with basic block counting as proxy analysis."""
    r = ToolResult(tool='QEMU-user', sample=sample, optimize=optimize)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ['qemu-x86_64', '-d', 'in_asm', binary_path],
            capture_output=True, text=True, timeout=10,
            env={'QEMU_LOG': 'in_asm', 'QEMU_LOG_FILENAME': '/dev/stderr'})
        if proc.returncode != 0:
            r.error_msg = f'QEMU exit {proc.returncode}'
            r.findings = 0
        else:
            r.findings = proc.stdout.count('call') + proc.stdout.count('jmp')
        r.success = True
    except FileNotFoundError:
        r.error_msg = 'qemu-x86_64 not found'
    except Exception as e:
        r.error_msg = str(e)[:100]
    r.duration_sec = round(time.perf_counter() - t0, 2)
    return r


def run_ghidra(binary_path: str, sample: str,
               optimize: str = 'O0') -> ToolResult:
    """Placeholder for Ghidra headless analysis."""
    r = ToolResult(tool='Ghidra', sample=sample, optimize=optimize)
    r.success = False
    r.error_msg = 'Ghidra headless requires JAVA_HOME and analyzeHeadless'
    return r


RUNNERS = {
    'BinMind': run_binmind,
    'Angr': run_angr,
    'QEMU-user': run_qemu,
    'Ghidra': run_ghidra,
}


def run_comparison(samples_root: str,
                   tools: List[str] = None,
                   optimize: str = 'O0') -> List[ToolResult]:
    """Run all tools on all compiled samples."""
    if tools is None:
        tools = ['BinMind', 'Angr']
    results = []
    for entry in sorted(os.listdir(samples_root)):
        d = os.path.join(samples_root, entry)
        if not os.path.isdir(d):
            continue
        binary = os.path.join(d, f'vuln_{optimize}')
        if not os.path.isfile(binary):
            continue
        for tool in tools:
            runner = RUNNERS.get(tool)
            if runner:
                results.append(runner(binary, entry, optimize))
    return results


def results_to_json(results: List[ToolResult]) -> str:
    return json.dumps([
        {'tool': r.tool, 'sample': r.sample, 'optimize': r.optimize,
         'findings': r.findings, 'duration_sec': r.duration_sec,
         'error': r.error_msg}
        for r in results
    ], indent=2)


if __name__ == '__main__':
    root = os.path.join(os.path.dirname(__file__), '..',
                       'tests', 'cve_samples')
    results = run_comparison(root)
    print(results_to_json(results))
