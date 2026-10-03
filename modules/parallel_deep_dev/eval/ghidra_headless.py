"""Ghidra 无头分析器 — 模拟通用静态审计工具。

在 Ghidra JVM 内执行自定义脚本: 统计堆危险写指令数与
危险函数调用数, 模拟无堆语义理解的"凡是写内存就报"的
高误报基线。无 GHIDRA_HOME 时返回 skipped。
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

_GHIDRA_SCRIPT = r"""
# Ghidra heap audit simulation: count write insns + danger calls.
# output lines prefixed with AUDIT_ for post-processing.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

danger = {'memcpy','memmove','memset','strcpy','strncpy','strcat',
          'sprintf','snprintf','gets','read','recv','malloc','calloc',
          'realloc','free'}
writes = 0
calls = 0
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mon = ConsoleTaskMonitor()
insns = listing.getInstructions(True)
while insns.hasNext():
    ins = insns.next()
    if ins.getMnemonicString().lower().startswith('mov') or \
       ins.getMnemonicString().lower().startswith('st'):
        refs = ins.getReferencesFrom()
        while refs.hasNext():
            if refs.next().getReferenceType().isWrite():
                writes += 1
                break
    refs = ins.getReferencesFrom()
    while refs.hasNext():
        ref = refs.next()
        if ref.getReferenceType().isCall():
            calls += 1
            break
print("AUDIT_WRITES %d" % writes)
print("AUDIT_CALLS %d" % calls)
print("AUDIT_DONE")
"""


def _parse_audit(stdout: str) -> dict:
    writes = calls = 0
    for line in stdout.splitlines():
        if line.startswith('AUDIT_WRITES '):
            writes = int(line.split()[1])
        elif line.startswith('AUDIT_CALLS '):
            calls = int(line.split()[1])
    return {'writes': writes, 'calls': calls}


def ghidra_audit(binary: str, ghidra_home: str = '', timeout: int = 120) -> dict:
    """返回 {tool, sample, success, writes, calls, duration_sec, error}。"""
    base = {'tool': 'Ghidra', 'sample': os.path.basename(binary)}
    if not ghidra_home:
        ghidra_home = os.environ.get('GHIDRA_HOME', '')
    if not ghidra_home or not Path(ghidra_home).exists():
        return {**base, 'success': False, 'writes': 0, 'calls': 0,
                'duration_sec': 0.0,
                'error': 'GHIDRA_HOME not set or invalid'}
    if not Path(binary).exists():
        return {**base, 'success': False, 'writes': 0, 'calls': 0,
                'duration_sec': 0.0, 'error': 'binary missing'}
    cache = Path(__file__).resolve().parent / '.cache'
    cache.mkdir(exist_ok=True)
    script = cache / 'ghidra_heap_audit.py'
    script.write_text(_GHIDRA_SCRIPT, encoding='utf-8')

    analyze = Path(ghidra_home) / 'support' / 'analyzeHeadless'
    if sys.platform == 'win32':
        analyze = analyze.with_suffix('.bat')
    proj = cache / 'ghidra_proj'
    cmd = [str(analyze), str(proj), 'HeapAudit',
           '-import', binary, '-postScript', str(script),
           '-scriptPath', str(cache), '-deleteProject']
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        dt = round(time.time() - t0, 3)
        if r.returncode != 0:
            return {**base, 'success': False, 'writes': 0, 'calls': 0,
                    'duration_sec': dt,
                    'error': f'analyzeHeadless exit {r.returncode}'}
        info = _parse_audit(r.stdout)
        return {**base, 'success': True, 'writes': info['writes'],
                'calls': info['calls'], 'duration_sec': dt, 'error': ''}
    except FileNotFoundError:
        return {**base, 'success': False, 'writes': 0, 'calls': 0,
                'duration_sec': 0.0, 'error': 'analyzeHeadless not found'}
    except subprocess.TimeoutExpired:
        return {**base, 'success': False, 'writes': 0, 'calls': 0,
                'duration_sec': timeout, 'error': 'timeout'}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: ghidra_headless.py <binary> [--ghidra-home PATH]')
        sys.exit(1)
    home = ''
    if '--ghidra-home' in sys.argv:
        idx = sys.argv.index('--ghidra-home')
        home = sys.argv[idx + 1]
    print(json.dumps(ghidra_audit(sys.argv[1], home), indent=2))
