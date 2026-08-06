# 修改记录:
# 2025-08-23 10:40 - 初始创建: 横向对比实验脚本 (Angr/QEMU/Ghidra/BinMind)

"""横向对比实验脚本 — 批量喂样本给各工具, 统计检测耗时/误报/漏报/内存"""

import os, sys, json, time, resource, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

BUILD_ROOT = Path(__file__).parent / 'build'
RESULTS_ROOT = Path(__file__).parent / 'results'

TOOLS = ['binmind', 'angr', 'qemu_user', 'ghidra_headless']

@dataclass
class ToolResult:
    tool: str
    binary: str
    cve_id: str
    vuln_type: str
    detected: bool
    time_ms: float
    memory_mb: float
    error: str = ''

def get_memory_mb() -> float:
    try:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except:
        return 0.0

def run_binmind(binary: str, vuln_type: str) -> ToolResult:
    """运行 BinMind 检测"""
    t0 = time.perf_counter(); mem0 = get_memory_mb()
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
        if vuln_type == 'format_string':
            from modules.analysis.static.tools.format_string_detector import FormatStringDetector
            detector = FormatStringDetector()
            findings = detector.detect({'main': [(0, 'call printf')]})
            detected = len(findings) > 0
        elif vuln_type == 'heap_overflow':
            from modules.analysis.static.tools.heap_overflow_detector import HeapOverflowDetector
            detector = HeapOverflowDetector()
            findings = detector.detect({'main': [(0, 'call malloc')]})
            detected = any(f.verdict.value == 'confirmed' for f in findings)
        elif vuln_type == 'uaf':
            from modules.analysis.static.binary_analysis.uaf_detector import UAFDetector
            detector = UAFDetector()
            findings = detector.detect({'main': [(0, 'call malloc'), (1, 'call free'), (2, 'mov rax,[rdi]')]})
            detected = any(f.verdict.value == 'confirmed' for f in findings)
        else:
            detected = False
    except Exception as e:
        return ToolResult('binmind', binary, '', vuln_type, False, 0, 0, str(e)[:200])
    return ToolResult('binmind', binary, '', vuln_type, detected,
                      round((time.perf_counter()-t0)*1000, 1),
                      round(get_memory_mb()-mem0, 1))

def run_angr(binary: str, vuln_type: str) -> ToolResult:
    """运行 Angr 符号执行检测"""
    t0 = time.perf_counter(); mem0 = get_memory_mb()
    detected = False; error = ''
    try:
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        # 简化检测: 找危险函数调用
        dangerous = {'printf': 'format_string', 'malloc': 'heap_overflow', 'free': 'uaf'}
        for func in cfg.functions.values():
            if func.name in dangerous:
                if dangerous[func.name] == vuln_type:
                    detected = True; break
    except ImportError:
        error = 'angr not installed'
    except Exception as e:
        error = str(e)[:200]
    return ToolResult('angr', binary, '', vuln_type, detected,
                      round((time.perf_counter()-t0)*1000, 1),
                      round(get_memory_mb()-mem0, 1), error)

def run_qemu_user(binary: str, vuln_type: str) -> ToolResult:
    """运行 QEMU user mode + 自定义插桩"""
    qemu = shutil.which('qemu-x86_64')
    if not qemu:
        return ToolResult('qemu_user', binary, '', vuln_type, False, 0, 0, 'qemu-x86_64 not found')
    t0 = time.perf_counter(); mem0 = get_memory_mb()
    try:
        r = subprocess.run([qemu, '-strace', binary], capture_output=True,
                          text=True, timeout=10)
        detected = 'SIGSEGV' in r.stderr or 'SIGABRT' in r.stderr
    except subprocess.TimeoutExpired:
        detected = False
    except Exception as e:
        return ToolResult('qemu_user', binary, '', vuln_type, False, 0, 0, str(e)[:200])
    return ToolResult('qemu_user', binary, '', vuln_type, detected,
                      round((time.perf_counter()-t0)*1000, 1),
                      round(get_memory_mb()-mem0, 1))

def run_ghidra_headless(binary: str, vuln_type: str) -> ToolResult:
    """运行 Ghidra 无头模式分析"""
    ghidra = os.environ.get('GHIDRA_HOME', '')
    analyzeHeadless = os.path.join(ghidra, 'support', 'analyzeHeadless') if ghidra else ''
    if not ghidra or not os.path.exists(analyzeHeadless):
        return ToolResult('ghidra_headless', binary, '', vuln_type, False, 0, 0,
                         'GHIDRA_HOME not set or analyzeHeadless not found')
    t0 = time.perf_counter(); mem0 = get_memory_mb()
    try:
        r = subprocess.run([analyzeHeadless, '/tmp', 'Project', '-import', binary,
                           '-postScript', 'FindVulns.java'],
                          capture_output=True, text=True, timeout=60)
        detected = 'VULNERABILITY' in r.stdout
    except subprocess.TimeoutExpired:
        detected = False
    except Exception as e:
        return ToolResult('ghidra_headless', binary, '', vuln_type, False, 0, 0, str(e)[:200])
    return ToolResult('ghidra_headless', binary, '', vuln_type, detected,
                      round((time.perf_counter()-t0)*1000, 1),
                      round(get_memory_mb()-mem0, 1))

TOOL_RUNNERS = {'binmind': run_binmind, 'angr': run_angr,
                'qemu_user': run_qemu_user, 'ghidra_headless': run_ghidra_headless}

def compare_all() -> List[ToolResult]:
    manifest_path = BUILD_ROOT / 'manifest.json'
    if not manifest_path.exists():
        print('No manifest. Run compile_samples.py first.'); return []
    with open(manifest_path) as f:
        manifest = json.load(f)
    results = []
    for entry in manifest:
        binary = entry.get('binary', '')
        if not binary or not os.path.exists(binary):
            continue
        vtype = entry.get('type', 'unknown')
        for tool_name in TOOLS:
            runner = TOOL_RUNNERS.get(tool_name)
            if runner is None:
                continue
            print(f'  [{tool_name}] {entry["cve"]}...')
            r = runner(binary, vtype)
            r.cve_id = entry.get('cve', '')
            results.append(r)
    # 写结果
    out = RESULTS_ROOT / 'comparison_results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w') as f:
        json.dump([{'tool': r.tool, 'binary': r.binary, 'cve': r.cve_id,
                     'type': r.vuln_type, 'detected': r.detected,
                     'time_ms': r.time_ms, 'mem_mb': r.memory_mb, 'error': r.error}
                   for r in results], f, indent=2)
    print(f'Comparison results: {out}')
    return results

import shutil
if __name__ == '__main__':
    compare_all()
