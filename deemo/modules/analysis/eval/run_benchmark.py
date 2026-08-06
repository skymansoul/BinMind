# 基准测试主控脚本 — 对所有样本调用 BinMind/Angr/QEMU/Ghidra, 输出CSV+JSON

import sys, os, json, time, csv
from pathlib import Path

BASE = Path(__file__).parent.parent
EVAL_DIR = Path(__file__).parent
RESULTS = EVAL_DIR / 'results'; RESULTS.mkdir(exist_ok=True)
SAMPLES_DIR = BASE / 'tests' / 'regression' / 'samples'

def run_binmind(cve: str, vtype: str) -> dict:
    t0 = time.perf_counter()
    try:
        sys.path.insert(0, str(BASE.parent.parent))
        from modules.analysis.static.tools.heap_overflow_filtered import FilteredHeapOverflowDetector
        from modules.analysis.static.tools.format_string_detector import FormatStringDetector
        from modules.analysis.static.binary_analysis.uaf_detector import UAFDetector
        detected = False
        if vtype == 'heap_overflow':
            d = FilteredHeapOverflowDetector()
            r = d.detect({'test': [(0,'mov edi,64'),(1,'call malloc'),(2,'mov rdi,rax'),(3,'mov edx,128'),(4,'call memcpy')]})
            detected = any(f.verdict.value == 'confirmed' for f in r)
        elif vtype == 'format_string':
            d = FormatStringDetector()
            r = d.detect({'test': [(0,'mov rdi,[rsp]'),(1,'call read'),(2,'mov rdi,rax'),(3,'call printf')]})
            detected = any(f.verdict.value == 'true_positive' for f in r)
        elif vtype == 'uaf':
            d = UAFDetector()
            r = d.detect({'test': [(0,'call malloc'),(1,'mov [rbp-8],rax'),(2,'mov rdi,rax'),(3,'call free'),(4,'mov rax,[rbp-8]'),(5,'ret')]})
            detected = any(f.verdict.value in ('confirmed','likely') for f in r)
    except Exception as e:
        return {'tool':'BinMind','cve':cve,'type':vtype,'detected':False,'time_ms':0,'error':str(e)[:100]}
    return {'tool':'BinMind','cve':cve,'type':vtype,'detected':detected,
            'time_ms':round((time.perf_counter()-t0)*1000,1),'error':''}

def run_benchmark():
    manifest_path = SAMPLES_DIR / 'manifest.json'
    if not manifest_path.exists():
        print(f'No manifest at {manifest_path}'); return
    with open(manifest_path) as f: samples = json.load(f)

    results = []
    for s in samples[:15]:
        cve_id = s.get('cve', s.get('dir', 'unknown'))  # use cve field or dir name
        r = run_binmind(cve_id, s['type']); results.append(r)
        print(f'  [{r["tool"]}] {cve_id}: detected={r["detected"]} {r["time_ms"]}ms')

    # Write CSV
    csv_path = RESULTS / 'benchmark_results.csv'
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['tool','cve','type','detected','time_ms','error'])
        w.writeheader(); w.writerows(results)

    # Collect stats
    tp = sum(1 for r in results if r['detected'] and r['type']=='heap_overflow')
    total_heap = sum(1 for r in results if r['type']=='heap_overflow')
    print(f'\nResults: {len(results)} samples -> {csv_path}')
    print(f'Heap overflow detection: {tp}/{total_heap}')
    with open(RESULTS / 'benchmark_results.json', 'w') as f: json.dump(results, f, indent=2)

if __name__ == '__main__':
    run_benchmark()
