# 回归测试: 编译 + 检测 + CSV 汇总
import os, sys, subprocess, json, time, csv, argparse
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, 'cve_samples')
DEEMO = os.path.join(BASE, '..', 'deemo')
sys.path.insert(0, DEEMO)

TYPE_MAP = {
    'heap_overflow': ('core.heap_overflow_pipeline', 'detect_heap_overflows_full'),
    'uaf': ('core.uaf_use_site_detector', 'detect_use_after_free'),
    'double_free': ('core.double_free_detector', 'detect_double_free'),
    'format_string': ('core.format_string_detector', 'detect_format_string_vulns'),
    'stack_overflow': ('core.stack_overflow_analyzer', 'analyze_stack_overflow'),
    'integer_overflow': ('core.integer_overflow_detector', 'IntegerOverflowDetector'),
}

def compile_all():
    ok = fail = 0
    for d in sorted(os.listdir(SAMPLES)):
        dp = os.path.join(SAMPLES, d)
        if not os.path.isdir(dp): continue
        src = os.path.join(dp, 'vuln.c')
        out = os.path.join(dp, 'vuln')
        out_exe = out + '.exe'  # Windows gcc appends .exe
        if not os.path.isfile(src): continue
        r = subprocess.run(['gcc', src, '-o', out, '-w'], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            ok += 1
            # On Windows, gcc produces .exe regardless of -o name
            if os.path.isfile(out_exe) and not os.path.isfile(out):
                os.rename(out_exe, out) if not os.path.isfile(out) else None
        else: print('  COMPILE FAIL: ' + d); fail += 1
    return ok, fail

def run_detector(vuln_type, binary_path):
    import importlib
    mod_name, fn_name = TYPE_MAP[vuln_type]
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, fn_name)
    t0 = time.time()
    try:
        if vuln_type == 'integer_overflow':
            detector = fn()
            src = binary_path.replace('.exe','').replace('vuln','vuln.c')
            with open(src, encoding='utf-8', errors='replace') as f:
                result = detector.detect(f.read())
        elif vuln_type == 'stack_overflow':
            result = fn(binary_path, 'main')
        elif vuln_type == 'format_string':
            result = fn(binary_path)
        else:
            result = fn([])
        elapsed = (time.time() - t0) * 1000
        count = len(result) if isinstance(result, (list, tuple)) else (1 if result else 0)
        return {'count': count, 'elapsed_ms': round(elapsed, 2), 'success': True}
    except Exception as e:
        return {'count': 0, 'elapsed_ms': 0, 'success': False, 'error': str(e)[:80]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--type', default='all')
    a = p.parse_args()

    print('Phase 1: Compile')
    ok, fail = compile_all()
    print('  %d OK, %d FAIL' % (ok, fail))

    vuln_types = list(TYPE_MAP.keys()) if a.type == 'all' else [a.type]
    rows = []
    for vt in vuln_types:
        print('Phase 2: ' + vt)
        matching = [d for d in os.listdir(SAMPLES) if d.startswith(vt) and os.path.isdir(os.path.join(SAMPLES, d))]
        for d in sorted(matching):
            binary = os.path.join(SAMPLES, d, 'vuln')
            if not os.path.isfile(binary):
                binary_exe = binary + '.exe'
                if os.path.isfile(binary_exe): binary = binary_exe
                else: continue
            r = run_detector(vt, binary)
            r['sample'] = d; r['type'] = vt
            rows.append(r)
            s = ('count=' + str(r['count'])) if r['success'] else ('ERR=' + str(r.get('error','?')))
            print('  %s: %s (%.1fms)' % (d, s, r['elapsed_ms']))

    out = os.path.join(BASE, 'regression_results.csv')
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sample','type','count','elapsed_ms','success','error'])
        w.writeheader(); w.writerows(rows)
    print('\nResults: ' + out + ' (%d rows)' % len(rows))

if __name__ == '__main__':
    main()
