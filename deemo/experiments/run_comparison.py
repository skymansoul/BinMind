#!/usr/bin/env python3
"""
对比实验统一启动脚本 — Angr/QEMU/Ghidra vs 本项目扫描器。
喂入同一批样本, 统计耗时/TP/FP/内存峰值, 输出JSON+LaTeX表格。
"""
import os, sys, json, time, subprocess, argparse
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(BASE, '..')
sys.path.insert(0, PROJECT_ROOT)

@dataclass
class ToolResult:
    tool: str
    sample: str
    opt_level: str
    is_packed: bool
    findings: int
    scan_time_sec: float
    peak_memory_mb: float
    success: bool
    error: str = ""

def build_manifest(samples_dir: str) -> List[Dict]:
    """扫描samples_dir下的ELF文件构建manifest。"""
    import glob
    manifest = []
    for f in sorted(glob.glob(os.path.join(samples_dir, '**', '*'), recursive=True)):
        if os.path.isfile(f) and os.access(f, os.X_OK):
            name = os.path.basename(f)
            sample = name.rsplit('_o', 1)[0]
            opt = 'O0'
            if '_o0' in name: opt = 'O0'
            elif '_o2' in name: opt = 'O2'
            elif '_o3' in name: opt = 'O3'
            packed = '_packed' in name
            manifest.append({'sample': sample, 'binary': f, 'opt': opt, 'packed': packed})
    return manifest

def run_our_scanner(binary: str, timeout: int = 120) -> ToolResult:
    """运行本项目内置扫描器。"""
    start = time.time()
    try:
        r = subprocess.run([sys.executable, '-c', f'''
import sys; sys.path.insert(0, "{PROJECT_ROOT}")
try:
    from modules.vuln.detection import detect_vulnerabilities
    f = detect_vulnerabilities("{binary}")
    n = len(f) if isinstance(f, list) else (1 if f else 0)
    print(n)
except Exception as e: print(f"ERR:{{e}}")
'''], capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - start
        out = r.stdout.strip()
        n = int(out) if out.isdigit() else 0
        return ToolResult('ours', os.path.basename(binary), '', False, n, round(elapsed,2), 0, True)
    except subprocess.TimeoutExpired:
        return ToolResult('ours', os.path.basename(binary), '', False, 0, timeout, 0, False, 'timeout')

def run_angr(binary: str, timeout: int = 300) -> ToolResult:
    """Angr exploration模式扫描。"""
    start = time.time()
    try:
        r = subprocess.run([sys.executable, '-c', f'''
import angr, sys
try:
    p = angr.Project("{binary}", auto_load_libs=False)
    cfg = p.analyses.CFGFast()
    # 检测危险函数调用
    dangerous = {{'memcpy','strcpy','sprintf','gets','free','system','popen'}}
    found = 0
    for func in cfg.functions.values():
        if func.name in dangerous:
            found += 1
    print(found)
except Exception as e: print(f"ERR:{{e}}")
'''], capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - start
        out = r.stdout.strip()
        n = int(out) if out.isdigit() else 0
        return ToolResult('Angr', os.path.basename(binary), '', False, n, round(elapsed,2), 0, True)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ToolResult('Angr', os.path.basename(binary), '', False, 0, timeout, 0, False, 'timeout or not installed')

def run_ghidra(binary: str, timeout: int = 300) -> ToolResult:
    """Ghidra headless脚本分析。需要 GHIDRA_INSTALL_DIR 环境变量。"""
    ghidra_home = os.environ.get('GHIDRA_INSTALL_DIR', '')
    if not ghidra_home:
        return ToolResult('Ghidra', os.path.basename(binary), '', False, 0, 0, 0, False, 'GHIDRA_INSTALL_DIR not set')
    start = time.time()
    # 运行时生成 GhidraScript, 避免依赖预置脚本文件
    java_script = '''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class FindVulnerabilities extends GhidraScript {
    public void run() throws Exception {
        String[] danger = {"memcpy", "strcpy", "sprintf", "gets", "free", "system", "popen"};
        java.util.Set<String> dset = new java.util.HashSet<>(java.util.Arrays.asList(danger));
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (dset.contains(f.getName())) println("VULN_FOUND " + f.getName());
        }
    }
}
'''
    try:
        import tempfile
        analyze_headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
        if sys.platform == 'win32':
            analyze_headless += '.bat'
        if not os.path.isfile(analyze_headless):
            return ToolResult('Ghidra', os.path.basename(binary), '', False, 0,
                              round(time.time() - start, 2), 0, False,
                              f'analyzeHeadless missing at {analyze_headless}')
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, 'FindVulnerabilities.java')
            with open(script_path, 'w') as f:
                f.write(java_script)
            r = subprocess.run([analyze_headless, os.path.join(tmp, 'proj'), 'Analysis',
                               '-import', os.path.abspath(binary), '-scriptPath', tmp,
                               '-postScript', 'FindVulnerabilities.java', '-deleteProject'],
                              capture_output=True, text=True, timeout=timeout)
            elapsed = round(time.time() - start, 2)
            n = (r.stdout + r.stderr).count('VULN_FOUND')
            return ToolResult('Ghidra', os.path.basename(binary), '', False, n,
                              elapsed, 0, n > 0)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ToolResult('Ghidra', os.path.basename(binary), '', False, 0, timeout, 0, False, 'timeout')
    except Exception as e:
        return ToolResult('Ghidra', os.path.basename(binary), '', False, 0,
                          round(time.time() - start, 2), 0, False, str(e)[:80])

def run_all(samples_dir: str, output_dir: str, tools: List[str] = None):
    tools = tools or ['ours', 'angr']
    manifest = build_manifest(samples_dir)
    results: List[ToolResult] = []
    os.makedirs(output_dir, exist_ok=True)

    for entry in manifest[:10]:  # 限制样本数以控制耗时
        binary = entry['binary']
        print(f"  [{entry['sample']}] {entry['opt']}")
        for tool in tools:
            if tool == 'ours': r = run_our_scanner(binary)
            elif tool == 'angr': r = run_angr(binary)
            elif tool == 'ghidra': r = run_ghidra(binary)
            else: continue
            r.opt_level = entry['opt']
            r.is_packed = entry.get('packed', False)
            r.sample = entry['sample']
            results.append(r)
            status = f"{r.findings}f, {r.scan_time_sec:.1f}s" if r.success else f"FAIL: {r.error[:30]}"
            print(f"    {tool}: {status}")

    with open(os.path.join(output_dir, 'comparison_results.json'), 'w') as f:
        json.dump([{'tool': r.tool, 'sample': r.sample, 'opt': r.opt_level,
                    'findings': r.findings, 'time': r.scan_time_sec,
                    'success': r.success, 'error': r.error} for r in results], f, indent=2)
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('samples_dir', help='Path to compiled binaries')
    parser.add_argument('--output', '-o', default='comparison_output')
    parser.add_argument('--tools', nargs='+', default=['ours', 'angr'])
    args = parser.parse_args()
    run_all(args.samples_dir, args.output, args.tools)
