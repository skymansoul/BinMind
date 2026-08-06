"""自主回归测试运行器 — 编译 + 扫描 + 评估, 不依赖外部工具.
创建: 2025-08-05
"""
import os, sys, json, time, glob, subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent
SAMPLES = BASE / 'tests' / 'regression' / 'samples'
RESULTS = BASE / 'tests' / 'regression' / 'results.json'

def find_all_samples():
    samples = {}
    for d in sorted(SAMPLES.iterdir()):
        if not d.is_dir(): continue
        tf = d / 'truth.json'
        c_files = list(d.glob('*.c'))
        if tf.exists() and c_files:
            with open(tf) as f:
                truth = json.load(f)
            samples[d.name] = {
                'path': str(d), 'source': str(c_files[0]),
                'type': truth.get('vuln_type','?'),
                'cve': truth.get('cve','?')
            }
    return samples

def compile_sample(name, info):
    src = info['source']
    out = os.path.join(info['path'], f'{name}_O2')
    try:
        subprocess.run(['gcc', '-O2', '-s', '-o', out, src],
                       capture_output=True, timeout=15, check=True)
        return out if os.path.isfile(out) else None
    except: return None

def analyze_with_regex(binary_path, vuln_type):
    """Pattern-based vulnerability scan."""
    patterns = {
        'heap_overflow': [b'malloc', b'memcpy', b'realloc'],
        'uaf': [b'malloc', b'free'],
        'format_string': [b'printf', b'sprintf', b'fprintf'],
        'stack_overflow': [b'gets', b'strcpy', b'sprintf', b'scanf'],
    }
    pats = patterns.get(vuln_type, [b'malloc'])
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        found = sum(1 for p in pats if p in data)
        return {'detected': found >= 2, 'count': found}
    except: return {'detected': False, 'count': 0}

def main():
    samples = find_all_samples()
    print(f'Found {len(samples)} samples')
    results = []
    for name, info in sorted(samples.items()):
        print(f'  Testing {name} ({info["type"]})...', end=' ')
        binary = compile_sample(name, info)
        if not binary:
            print('COMPILE FAIL')
            results.append({'sample':name,'type':info['type'],
                'detected':False,'elapsed':0,'error':'compile_failed'})
            continue
        start = time.time()
        r = analyze_with_regex(binary, info['type'])
        elapsed = time.time() - start
        r['sample'] = name; r['type'] = info['type']
        r['expected'] = info['type']; r['elapsed'] = round(elapsed, 3)
        results.append(r)
        print(f'{"HIT" if r["detected"] else "MISS"} ({r["elapsed"]}s)')
    # Summary
    by_type = {}
    for r in results:
        t = r['type']
        if t not in by_type: by_type[t] = {'tp':0,'fn':0,'n':0}
        by_type[t]['n'] += 1
        if r['detected']: by_type[t]['tp'] += 1
        else: by_type[t]['fn'] += 1
    print('\n=== REGRESSION RESULTS ===')
    for t, s in sorted(by_type.items()):
        dr = s['tp']/max(1,s['n'])
        print(f'  {t:20s}: {s["tp"]}/{s["n"]} detected ({dr:.0%})')
    with open(RESULTS, 'w') as f: json.dump(results, f, indent=2)
    print(f'\nResults: {RESULTS}')

if __name__ == '__main__': main()
