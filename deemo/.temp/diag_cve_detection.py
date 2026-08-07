"""诊断CVE样本检测能力 — 验证源码级扫描器对16个CVE样本的检测结果。"""
import os, sys, time, json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.pipeline_scanner import scan_binary

CVE_ROOT = os.path.join(BASE, 'samples', 'cve_heap_overflow')

results = []
for d in sorted(os.listdir(CVE_ROOT)):
    dp = os.path.join(CVE_ROOT, d)
    if not os.path.isdir(dp):
        continue
    c_files = [f for f in os.listdir(dp) if f.endswith('.c')]
    if not c_files:
        continue
    src_path = os.path.join(dp, c_files[0])
    binary_path = os.path.join(dp, d.replace('cve_', '') + '.exe')
    # 某些样本已编译
    if not os.path.isfile(binary_path):
        # 尝试其他命名
        exes = [f for f in os.listdir(dp) if f.endswith('.exe')]
        binary_path = os.path.join(dp, exes[0]) if exes else src_path

    with open(src_path, encoding='utf-8', errors='replace') as f:
        source = f.read()

    t0 = time.time()
    r = scan_binary(binary_path if os.path.isfile(binary_path) else '', src_path)
    dt = (time.time() - t0) * 1000

    detected = r.get('detected', False)
    overflow = r.get('src_overflow', 0)
    uncertain = r.get('src_uncertain', 0)
    safe = r.get('src_safe', 0)
    guard_f = r.get('guard_filtered', 0)
    total = r.get('source_scan_count', 0)

    status = 'DETECT' if detected else 'MISS'
    print(f'[{status:6s}] {d:<45s} scan={total} ovf={overflow} unc={uncertain} safe={safe} gflt={guard_f} {dt:.0f}ms')
    if r.get('error'):
        print(f'         ERROR: {r["error"][:120]}')

    results.append({
        'sample': d,
        'detected': detected,
        'overflow': overflow,
        'uncertain': uncertain,
        'safe': safe,
        'guard_filtered': guard_f,
        'source_scan_count': total,
        'duration_ms': dt,
        'error': r.get('error', ''),
    })

tp = sum(1 for r in results if r['detected'])
fn = len(results) - tp
print(f'\n=== 源码级扫描器结果 ===')
print(f'总样本: {len(results)}')
print(f'检出(TP): {tp}')
print(f'漏报(FN): {fn}')
print(f'Recall: {tp/max(len(results),1):.1%}')
