import sys, os
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from tests.cve_samples.heap_overflow.compile_all import find_samples, compile_sample
from pathlib import Path

SAMPLE_DIR = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow')
samples = find_samples(SAMPLE_DIR)
print(f'Found {len(samples)} samples')
ok = 0
fail = 0
for s in samples:
    r = compile_sample(s)
    if r['success']:
        ok += 1
        print(f'  [OK]   {s.name}')
    else:
        fail += 1
        err = r.get('error', '')[:80]
        print(f'  [FAIL] {s.name}: {err}')
print(f'\nCompiled: {ok} OK, {fail} FAIL, {ok+fail} total')
