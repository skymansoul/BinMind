"""调用BinMind扫描器 + 源码级深度分析器批量检测。"""
import json, os, subprocess, sys, time
SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_samples")
BIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_binaries")
MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")

results = []
# Path A: 源码级深度分析 (UAF/IntOvf/Heap via value_range + interval + alias)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.uaf_analyzer import comprehensive_uaf_check
    from core.int_overflow_analyzer import IntOverflowAnalyzer
    from core.value_range import analyze_heap_bounds
    ana = IntOverflowAnalyzer()
    for d in sorted(os.listdir(SRC_DIR)):
        vc = os.path.join(SRC_DIR, d, 'vuln.c')
        if not os.path.isfile(vc): continue
        with open(vc, encoding='utf-8', errors='replace') as f: code = f.read()
        f = {'uaf': len(comprehensive_uaf_check(code, d)),
             'int_overflow': len([r for r in ana.analyze(code) if r.used_in_alloc and r.can_overflow]),
             'heap_bounds': len(analyze_heap_bounds(code, d))}
        f['total'] = sum(f.values())
        results.append({'sample': d, 'source_scan': f, 'method': 'source-level'})
except ImportError:
    pass

# Path B: 二进制扫描 (main.py)
if os.path.isdir(BIN_DIR):
    # 样本目录含预编译 PE 固件（.exe）与本地编译产物（.elf）
    for f in sorted(os.listdir(BIN_DIR)):
        if not (f.endswith('.elf') or f.endswith('.exe')): continue
        fp = os.path.join(BIN_DIR, f)
        t0 = time.time()
        try:
            p = subprocess.run([sys.executable, MAIN, fp], capture_output=True, text=True, timeout=120)
            findings = p.stdout.count('[FINDING]') + p.stdout.count('severity')
            results.append({'sample': f, 'binary_findings': findings, 'elapsed': round(time.time()-t0, 1),
                            'ok': p.returncode == 0, 'method': 'binary-main'})
        except Exception as e:
            results.append({'sample': f, 'binary_findings': 0, 'elapsed': 0, 'ok': False, 'error': str(e)[:80]})

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results.json")
with open(out_path, "w") as f: json.dump(results, f, indent=2)
total_src = sum(1 for r in results if r.get('method') == 'source-level')
total_bin = sum(1 for r in results if r.get('method') == 'binary-main')
total_findings = sum(r.get('source_scan', {}).get('total', 0) for r in results)
print(f'Saved: {out_path} ({total_src} source + {total_bin} binary scans, {total_findings} source findings)')
