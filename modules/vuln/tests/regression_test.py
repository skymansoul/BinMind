# coding: utf-8
import os, sys, json, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class TestResult:
    cve_id: str; detected: bool; elapsed_ms: float; error: str = ""

def compile_all(samples_dir, build_dir):
    os.makedirs(build_dir, exist_ok=True)
    results = []
    for entry in sorted(os.listdir(samples_dir)):
        d = os.path.join(samples_dir, entry)
        if not os.path.isdir(d): continue
        src = os.path.join(d, 'vuln.c')
        out = os.path.join(build_dir, entry)
        if os.path.exists(src):
            r = subprocess.run(['gcc','-g','-O0','-o',out,src,'-fno-stack-protector','-no-pie'], capture_output=True, text=True, timeout=30)
            results.append((entry, r.returncode==0, out if r.returncode==0 else r.stderr[:80]))
    return results

def scan_all(build_dir):
    results = []
    from modules.vuln.detection.ho_fp_filter import HoFpFilter
    from modules.vuln.detection.heap_disjoint import HeapDisjointAnalyzer
    for fname in sorted(os.listdir(build_dir)):
        path = os.path.join(build_dir, fname)
        if not os.path.isfile(path): continue
        t0 = time.time()
        try:
            out = subprocess.run(['objdump','-d','-M','intel',path], capture_output=True, text=True, timeout=15)
            insns = [l.strip() for l in out.stdout.split('\n') if l.strip() and ':' in l[:20]]
            stats = HoFpFilter().filter(insns, fname)
            dr = HeapDisjointAnalyzer().analyze(insns, fname)
            results.append(TestResult(cve_id=fname, detected=stats.confirmed>0, elapsed_ms=round((time.time()-t0)*1000,1)))
        except Exception as e:
            results.append(TestResult(cve_id=fname, detected=False, error=str(e)[:60]))
    return results

if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(__file__))
    samples = os.path.join(base, 'cve_samples_heap')
    build = os.path.join(base, 'build_heap')
    print('Compiling...')
    compiled = compile_all(samples, build)
    ok = sum(1 for _,s,_ in compiled if s)
    print(f'Compiled: {ok}/{len(compiled)}')
    print('Scanning...')
    results = scan_all(build)
    detected = sum(1 for r in results if r.detected)
    print(f'Detected: {detected}/{len(results)}')
    for r in results:
        print(f'  [{r.cve_id}] {"FOUND" if r.detected else "MISS"} ({r.elapsed_ms:.0f}ms)' + (f' ERR:{r.error}' if r.error else ''))
    with open(os.path.join(build,'regression_report.json'),'w') as f:
        json.dump([{'cve':r.cve_id,'detected':r.detected,'ms':r.elapsed_ms,'error':r.error} for r in results], f, indent=2)
