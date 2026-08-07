"""Shim 运行时 sweep — 验证全部 CVE 样本的运行时溢出行为."""
import glob
import json
import os
import sys

sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\fp_cve_experiment')
from qemu_tracer import asan_ground_truth

CORPUS = r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\fp_cve_experiment\corpus'

out = []
for d in sorted(glob.glob(os.path.join(CORPUS, 'cve_*'))):
    if not os.path.isdir(d):
        continue
    truth = json.load(open(os.path.join(d, 'truth.json'), encoding='utf-8'))
    exe = os.path.join(d, 'vuln.exe')
    r = asan_ground_truth(exe, d)
    ok = r['detected'] == truth['expected_vuln']
    out.append({'id': truth['id'], 'detected': r['detected'],
                'findings': r['findings'], 'error': r['error']})
    print('%-32s detected=%s findings=%d %s' % (
        truth['id'], r['detected'], r['findings'],
        'OK' if ok else 'MISS'))

json.dump(out, open(os.path.join(CORPUS, 'runtime_ground_truth.json'), 'w'),
          indent=2)
