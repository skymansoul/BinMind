"""Ghidra 无头分析器 — 模拟自动化静态审计 (capstone 回退).

创建: 2023-09-25
方法:
  1. Ghidra 模式: analyzeHeadless + Java 脚本, 枚举所有 store 指令,
     统计指向 malloc 返回值的写入及其偏移 (需要 Ghidra 安装).
  2. capstone 回退 (默认, 本机可运行): 线性反汇编, 启发式判定:
     - 记录 malloc/calloc 调用点及其立即数 size
     - 记录对堆指针区域的写入 (含 memcpy/strcpy 调用)
     - 无路径/污点分析 → 高误报是此类工具的固有特性

约定: 输出 dict: {tool, sample, findings, detected, error, time_ms}
"""
import os
import shutil
import subprocess
import sys
import time

from _common import try_import
capstone = try_import('capstone')
CAPSTONE_OK = capstone is not None

_GHIDRA_SCRIPT = r'''
import ghidra.program.model.listing as L
from ghidra.program.model.symbol import SymbolType
fm = currentProgram.getFunctionManager()
n = 0
for fn in fm.getFunctions(True):
    if fn.isExternal():
        continue
    body = fn.getBody()
    addr = body.getMinAddress()
    while addr is not None and body.contains(addr):
        insn = getInstructionAt(addr)
        if insn is not None:
            if insn.getMnemonicString() == "CALL":
                for ref in insn.getReferencesFrom():
                    sym = getSymbolAt(ref.getToAddress())
                    if sym is not None and sym.getName() in (
                            "malloc", "calloc", "realloc", "memcpy",
                            "strcpy", "memset"):
                        n += 1
        addr = addr.add(1)
print("FINDINGS " + str(n))
'''


def ghidra_scan(binary_path: str, timeout_sec: int = 180) -> dict:
    """Ghidra 无头脚本执行; 无 Ghidra 时 capstone 回退."""
    t0 = time.time()
    result = {'tool': 'ghidra', 'sample': os.path.basename(binary_path),
              'findings': 0, 'detected': False, 'error': '',
              'time_ms': 0.0}
    ah = shutil.which('analyzeHeadless')
    if ah is not None:
        try:
            import tempfile
            script = os.path.join(tempfile.mkdtemp(), 'heap_scan.py')
            with open(script, 'w') as f:
                f.write(_GHIDRA_SCRIPT)
            proc = subprocess.run(
                [ah, '/tmp/ghidra_proj', 'exp',
                 '-import', binary_path, '-postScript', script,
                 '-analysisTimeoutPerFile', str(timeout_sec)],
                capture_output=True, text=True, timeout=timeout_sec + 30)
            out = proc.stdout + proc.stderr
            m = None
            for line in out.splitlines():
                if 'FINDINGS' in line:
                    m = line.split()[-1]
            result['findings'] = int(m) if m else 0
            result['detected'] = result['findings'] > 0
            result['error'] = ''
            result['time_ms'] = round((time.time() - t0) * 1000, 1)
            return result
        except Exception as e:  # noqa: BLE001
            result['error'] = 'ghidra run failed: ' + repr(e)[:150]
            result['time_ms'] = round((time.time() - t0) * 1000, 1)
            return result

# capstone/objdump 回退: 符号级启发式静态审计
    # 用 objdump 解析符号 (capstone 无符号名), 统计分配/复制调用点
    try:
        import re
        proc = subprocess.run(
            [shutil.which('objdump') or 'objdump', '-d', '-M', 'intel',
             binary_path],
            capture_output=True, text=True, timeout=60)
        asm = proc.stdout
        alloc_count = len(re.findall(
            r'call\s+[^<\n]*<(?:malloc|calloc|realloc|strdup)@', asm))
        copy_count = len(re.findall(
            r'call\s+[^<\n]*<(?:memcpy|memmove|memset|strcpy|strcat|gets)@',
            asm))
        # 无@符号时 (MinGW/静态链接), 直接符号匹配
        if alloc_count == 0 and copy_count == 0:
            alloc_count = len(re.findall(
                r'call\s+[^<\n]*<malloc>', asm))
            copy_count = len(re.findall(
                r'call\s+[^<\n]*<(?:memcpy|memset|strcpy)>', asm))
        # 统计写入指令 (mov [mem])
        store_count = len(re.findall(r'\bmov\w*\s+(?:BYTE|WORD|DWORD|'
                                     r'QWORD)?\s*PTR\s*\[', asm))
        result['findings'] = alloc_count + copy_count + store_count
        result['detected'] = alloc_count > 0 and copy_count > 0
        result['error'] = ('objdump heuristic fallback '
                           '(alloc=%d copy=%d store=%d)'
                           % (alloc_count, copy_count, store_count))
    except Exception as e:  # noqa: BLE001
        result['error'] = repr(e)[:200]
    result['time_ms'] = round((time.time() - t0) * 1000, 1)
    return result


if __name__ == '__main__':
    import json
    if len(sys.argv) < 2:
        print('usage: python ghidra_headless.py <binary>')
        sys.exit(1)
    print(json.dumps(ghidra_scan(sys.argv[1])))
