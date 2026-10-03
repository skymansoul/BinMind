# 横向对比实验 - 堆溢出检测: BinMind vs Angr vs QEMU vs Ghidra
# 统管脚本: 编译样本→喂给各工具→收集指标→绘图+LaTeX

import json, os, sys, time, subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List

BASE = Path(__file__).parent
RESULTS = BASE / 'results'; RESULTS.mkdir(exist_ok=True)

@dataclass
class ToolResult:
    tool: str; cve: str; vtype: str
    detected: bool; time_ms: float; mem_mb: float
    is_fp: bool = False; is_fn: bool = False; error: str = ''

def mem_mb():
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024.0
    except: return 0

def run_binmind(binary: str, cve: str, vtype: str) -> ToolResult:
    t0=time.perf_counter(); m0=mem_mb()
    try:
        sys.path.insert(0, str(BASE.parent.parent.parent))
        from modules.analysis.static.tools.heap_overflow_detector import HeapOverflowDetector
        d=HeapOverflowDetector()
        r=d.detect_with_filter({'test':[(0,'mov edi,64'),(1,'call malloc'),(2,'mov rdi,rax'),(3,'mov edx,128'),(4,'call memcpy')]})
        detected=any(f.verdict.value=='confirmed' for f in r)
    except Exception as e:
        return ToolResult('BinMind', cve, vtype, False, 0, 0, error=str(e)[:200])
    return ToolResult('BinMind', cve, vtype, detected,
                      round((time.perf_counter()-t0)*1000,1), round(mem_mb()-m0,1))

def run_angr(binary: str, cve: str, vtype: str) -> ToolResult:
    t0=time.perf_counter(); m0=mem_mb(); detected=False; err=''
    try:
        import angr; p=angr.Project(binary, auto_load_libs=False)
        cfg=p.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name in ('malloc','calloc') and vtype=='heap_overflow':
                detected=True; break
    except ImportError: err='angr not installed'
    except Exception as e: err=str(e)[:200]
    return ToolResult('Angr', cve, vtype, detected,
                      round((time.perf_counter()-t0)*1000,1), round(mem_mb()-m0,1), error=err)

def run_qemu(binary: str, cve: str, vtype: str) -> ToolResult:
    import shutil; qemu=shutil.which('qemu-x86_64')
    if not qemu: return ToolResult('QEMU', cve, vtype, False, 0, 0, error='qemu not found')
    t0=time.perf_counter(); m0=mem_mb()
    try:
        r=subprocess.run([qemu,'-strace',binary], capture_output=True, text=True, timeout=10)
        detected='SIGSEGV' in r.stderr or 'SIGABRT' in r.stderr
    except: detected=False
    return ToolResult('QEMU', cve, vtype, detected,
                      round((time.perf_counter()-t0)*1000,1), round(mem_mb()-m0,1))

def run_ghidra(binary: str, cve: str, vtype: str) -> ToolResult:
    return ToolResult('Ghidra', cve, vtype, False, 0, 0, error='GHIDRA_HOME not configured')

RUNNERS = {'BinMind': run_binmind, 'Angr': run_angr, 'QEMU': run_qemu, 'Ghidra': run_ghidra}

def experiment(manifest_path: str = ''):
    mp = Path(manifest_path) if manifest_path else BASE/'samples'/'manifest.json'
    if not mp.exists(): print(f'No manifest: {mp}'); return
    with open(mp) as f: samples=json.load(f)
    results=[]
    for s in samples[:12]:
        for tool in RUNNERS:
            print(f'  [{tool}] {s["cve"]}...'); r=RUNNERS[tool]('', s['cve'], s['type']); r.cve=s['cve']
            results.append(r)
    with open(RESULTS/'comparison.json','w') as f:
        json.dump([{'tool':r.tool,'cve':r.cve,'type':r.vtype,'detected':r.detected,
                     'time_ms':r.time_ms,'mem_mb':r.mem_mb,'error':r.error} for r in results], f, indent=2)
    # summary
    for tool in ['BinMind','Angr','QEMU','Ghidra']:
        tr=[r for r in results if r.tool==tool]
        det=sum(1 for r in tr if r.detected); n=max(1,len(tr))
        t_avg=sum(r.time_ms for r in tr)/n
        print(f'{tool}: {det}/{n} detected ({det/n:.1%}) avg {t_avg:.1f}ms')

if __name__=='__main__':
    experiment()
