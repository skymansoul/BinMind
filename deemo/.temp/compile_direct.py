"""Compile all heap overflow samples by calling gcc directly."""
import os, sys, subprocess, time
from pathlib import Path

SAMPLE_DIR = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow')

samples = sorted([d for d in SAMPLE_DIR.iterdir() if d.is_dir() and not d.name.startswith('.')])
print(f'Found {len(samples)} samples')

ok = 0
fail = 0
for s in samples:
    c_files = list(s.glob('*.c'))
    if not c_files:
        print(f'  [SKIP] {s.name}: no .c file')
        continue

    src = str(c_files[0])
    # Output binary name = target_name.exe (gcc on Windows adds .exe)
    target_name = c_files[0].stem
    output = str(s / (target_name + '.exe'))

    t0 = time.time()
    try:
        proc = subprocess.run(
            ['gcc', '-O2', '-Wall', '-fno-stack-protector', '-o', output, src],
            capture_output=True, text=True, timeout=30,
        )
        elapsed = (time.time() - t0) * 1000
        if proc.returncode == 0:
            ok += 1
            print(f'  [OK]   {s.name} ({elapsed:.0f}ms)')
        else:
            fail += 1
            err = proc.stderr[:80] if proc.stderr else 'unknown'
            print(f'  [FAIL] {s.name}: {err}')
    except Exception as e:
        fail += 1
        print(f'  [FAIL] {s.name}: {str(e)[:80]}')

print(f'\nCompiled: {ok} OK, {fail} FAIL, {ok+fail} total')
