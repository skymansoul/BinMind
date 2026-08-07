"""FCPV 快速测试脚本 — 验证15个格式串样本."""
import sys, os, re
sys.path.insert(0, '.')

from core.fcpv_pipeline import fcpv_filter

samples_dir = 'samples/format_string'
results = []

for d in sorted(os.listdir(samples_dir)):
    p = os.path.join(samples_dir, d, 'vuln.c')
    if not os.path.isfile(p):
        continue
    src = open(p, encoding='utf-8', errors='replace').read()
    
    # 从注释提取期望结果
    comment = src.split('*/')[0] if '*/' in src else src[:500]
    expected_vuln = bool(re.search(r'VULN|CONFIRMED|期望.*漏洞', comment, re.IGNORECASE))
    # 更精确: 有 [VULN] 标记 = 漏洞; [SAFE] = 安全
    if re.search(r'\[VULN\]', src):
        expected_vuln = True
    elif re.search(r'\[SAFE\]', src):
        expected_vuln = False
    
    r = fcpv_filter(src)
    detected = r['has_vuln']
    
    if detected and expected_vuln:
        verdict = 'TP'
    elif detected and not expected_vuln:
        verdict = 'FP'
    elif not detected and expected_vuln:
        verdict = 'FN'
    else:
        verdict = 'TN'
    
    results.append((d, verdict))
    nv = len(r['vuln'])
    ns = len(r['safe'])
    nu = len(r['uncertain'])
    print(f'{d}: {verdict} (vuln={nv}, safe={ns}, unc={nu})')
    for v in r['vuln']:
        print(f'  VULN: {v.sink.sink_func}({v.sink.fmt_arg}) L{v.sink.line} conf={v.confidence:.2f}')
        print(f'    reason: {v.reason[:100]}')
    for u in r['uncertain']:
        print(f'  UNC: {u.sink.sink_func}({u.sink.fmt_arg}) L{u.sink.line} conf={u.confidence:.2f}')
        print(f'    reason: {u.reason[:100]}')

# 汇总
tp = sum(1 for _, v in results if v == 'TP')
fp = sum(1 for _, v in results if v == 'FP')
tn = sum(1 for _, v in results if v == 'TN')
fn = sum(1 for _, v in results if v == 'FN')
p = tp / (tp + fp) if (tp + fp) > 0 else 0
r_ = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * p * r_ / (p + r_) if (p + r_) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
print(f'\n=== FCPV Results ===')
print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
print(f'P={p:.4f} R={r_:.4f} F1={f1:.4f} FPR={fpr:.4f}')
