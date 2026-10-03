# coding: utf-8
"""对比实验——BinMind vs Angr vs Ghidra vs QEMU, 统计检出率/误报率/耗时"""
import os, sys, json, time, subprocess
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ToolResult:
    tool: str; sample: str; detected: bool; elapsed_sec: float; error: str = ""

def run_binmind(binary):
    t0 = time.time()
    try:
        out = subprocess.run(['objdump','-d','-M','intel',binary], capture_output=True, text=True, timeout=15)
        insns = [l.strip() for l in out.stdout.split('\n') if l.strip() and ':' in l[:20]]
        from modules.vuln.detection.ho_fp_filter import HoFpFilter
        s = HoFpFilter().filter(insns, os.path.basename(binary))
        return ToolResult('BinMind', os.path.basename(binary), s.confirmed>0, time.time()-t0)
    except Exception as e:
        return ToolResult('BinMind', os.path.basename(binary), False, time.time()-t0, str(e)[:60])

def run_angr(binary):
    t0 = time.time()
    try:
        import angr; proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        found = any(f.name in {'memcpy','strcpy','sprintf','system','malloc','free'} for f in cfg.functions.values())
        return ToolResult('Angr', os.path.basename(binary), found, time.time()-t0)
    except ImportError:
        return ToolResult('Angr', os.path.basename(binary), False, time.time()-t0, 'angr not installed')
    except Exception as e:
        return ToolResult('Angr', os.path.basename(binary), False, time.time()-t0, str(e)[:60])

def run_ghidra(binary):
    t0 = time.time()
    ghidra = os.environ.get('GHIDRA_HOME','')
    if not ghidra:
        return ToolResult('Ghidra', os.path.basename(binary), False, time.time()-t0, 'GHIDRA_HOME not set')
    try:
        subprocess.run([os.path.join(ghidra,'support','analyzeHeadless'), '/tmp/ghidra_proj','Test','-import',binary,'-postScript','FindVulnerableFunctions.java'], capture_output=True, timeout=60)
        return ToolResult('Ghidra', os.path.basename(binary), True, time.time()-t0)
    except Exception as e:
        return ToolResult('Ghidra', os.path.basename(binary), False, time.time()-t0, str(e)[:60])

def run_qemu(binary):
    t0 = time.time()
    try:
        p = subprocess.run(['qemu-x86_64','-strace',binary], capture_output=True, text=True, timeout=5)
        return ToolResult('QEMU', os.path.basename(binary), p.returncode!=0, time.time()-t0)
    except FileNotFoundError:
        return ToolResult('QEMU', os.path.basename(binary), False, time.time()-t0, 'qemu-user not installed')
    except subprocess.TimeoutExpired:
        return ToolResult('QEMU', os.path.basename(binary), True, time.time()-t0, 'timeout (possible crash)')

def run_all(build_dir):
    tools = [('BinMind',run_binmind),('Angr',run_angr),('Ghidra',run_ghidra),('QEMU',run_qemu)]
    all_results = {}
    for name, runner in tools:
        print(f'\n--- {name} ---')
        results = []
        for f in sorted(os.listdir(build_dir)):
            p = os.path.join(build_dir, f)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                r = runner(p); results.append(r)
                status = 'FOUND' if r.detected else 'MISS'
                print(f'  [{f}] {status} ({r.elapsed_sec:.1f}s)' + (f' ERR:{r.error}' if r.error else ''))
        all_results[name] = results
    return all_results

if __name__ == '__main__':
    build = sys.argv[1] if len(sys.argv)>1 else '../build_heap'
    results = run_all(build)
    with open('comparison_results.json','w') as f:
        json.dump({t:[{'sample':r.sample,'detected':r.detected,'sec':r.elapsed_sec,'error':r.error} for r in rs] for t,rs in results.items()}, f, indent=2)
    print('\nSaved comparison_results.json')
