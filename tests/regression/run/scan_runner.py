"""
端到端回归测试 -- 直接import检测模块, 遍历CVE样本, 输出Markdown表格。
"""
import json, os, sys, time, argparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, ROOT)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')


def load_ground_truth():
    gt = {}
    for root, dirs, files in os.walk(SAMPLES_DIR):
        if 'truth.json' in files:
            with open(os.path.join(root, 'truth.json')) as f:
                gt[os.path.basename(root)] = json.load(f)
    return gt


def find_binaries():
    binaries = {}
    for root, dirs, files in os.walk(SAMPLES_DIR):
        for f in files:
            if f.endswith(('.c','.md','.json','.sh','.py','.txt','.h','Makefile')):
                continue
            path = os.path.join(root, f)
            if os.access(path, os.X_OK) or (os.path.isfile(path) and os.path.getsize(path) > 64):
                name = os.path.basename(root)
                if name not in binaries:
                    binaries[name] = path
    return binaries


def _list_funcs(binary_path):
    try:
        import subprocess
        from config import R2_PATH
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false', '-c', 'afl', binary_path],
            capture_output=True, text=True, timeout=15)
        funcs = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                name = parts[-1]
                if not name.startswith(('_','sym.','fcn.','sub.','loc.')):
                    if not any(name.startswith(p) for p in
                               ('__libc','__cxa','register','deregister')):
                        funcs.append(name)
        return funcs
    except Exception:
        return []


def run_detection(binary_path, scan_type):
    start = time.time()
    findings = []
    error = None
    try:
        if scan_type == 'stack_overflow':
            from core.stack_overflow_analyzer import analyze_stack_overflow
            for fn in _list_funcs(binary_path)[:3]:
                r = analyze_stack_overflow(binary_path, fn)
                if r.get('overflowable'):
                    findings.append({'function':fn,'type':'stack_overflow',
                        'confidence':0.80,'detail':r.get('insights',[])})
        elif scan_type == 'format_string':
            from core.format_string_detector import detect_format_string_vulns
            findings = detect_format_string_vulns(binary_path, use_llm=False)
        elif scan_type == 'heap':
            from core.heap_uaf_detector import analyze_heap_vulnerabilities
            for fn in _list_funcs(binary_path)[:3]:
                findings.extend(analyze_heap_vulnerabilities(binary_path, fn))
    except ImportError as e:
        error = f'ImportError:{e}'
    except Exception as e:
        error = f'{type(e).__name__}:{str(e)[:100]}'
    return {'findings':findings,'elapsed':time.time()-start,'error':error}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--type',default='all')
    args = parser.parse_args()

    ground_truth = load_ground_truth()
    binaries = find_binaries()
    if not binaries:
        print("No binaries found. Compile samples first.")
        return 1

    scan_types = (['stack_overflow','format_string','heap']
                  if args.type=='all' else [args.type])
    results = []
    for name, path in sorted(binaries.items()):
        gt = ground_truth.get(name,{})
        exp_type = gt.get('vuln_type', gt.get('type','unknown'))
        for st in scan_types:
            r = run_detection(path, st)
            r['sample']=name; r['scan_type']=st
            r['expected']=exp_type
            r['detected']=len(r['findings'])>0
            r['count']=len(r['findings'])
            results.append(r)

    by_type = {}
    for r in results:
        t = r['scan_type']
        if t not in by_type:
            by_type[t] = {'tp':0,'fp':0,'fn':0,'n':0,'elapsed':[]}
        s=by_type[t]; s['n']+=1; s['elapsed'].append(r['elapsed'])
        if r['detected'] and r['expected']==t: s['tp']+=1
        elif r['detected'] and r['expected']!=t: s['fp']+=1
        elif not r['detected'] and r['expected']==t: s['fn']+=1

    lines=['# Regression Results','',
        '| Scan Type | TP | FP | FN | Precision | Recall | F1 | Avg Time |',
        '|-----------|---|----|----|-----------|--------|----|----------|']
    for t,s in sorted(by_type.items()):
        p=s['tp']/max(s['tp']+s['fp'],1); r=s['tp']/max(s['tp']+s['fn'],1)
        f1=2*p*r/max(p+r,0.001); at=sum(s['elapsed'])/max(len(s['elapsed']),1)
        lines.append(f'| {t:15s} | {s["tp"]:2d} | {s["fp"]:2d} | {s["fn"]:2d} '
                     f'| {p:.2f} | {r:.2f} | {f1:.2f} | {at:.1f}s |')

    out='\n'.join(lines); print(out)
    os.makedirs(RESULTS_DIR,exist_ok=True)
    out_path = os.path.join(RESULTS_DIR,'regression_report.md')
    with open(out_path,'w') as f: f.write(out)
    print(f'\nSaved: {out_path}')
    return 0

if __name__=='__main__':
    sys.exit(main())
