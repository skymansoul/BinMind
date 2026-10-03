"""QEMU user mode 对比实验脚本 — 轻量插桩 + 运行时内存操作抓取.

设计决策:
  - 为什么用 QEMU user mode 而非 system mode: user mode 不需要启动完整OS,
    启动快 (<1s), 适合批量实验。
  - 为什么用 -d cpu,in_asm 而非自定义 plugin: 自定义 QEMU plugin 需要编译
    整个 QEMU, 复杂度高。解析已有 trace 格式的代价更低。
"""

import json
import os
import re
import subprocess
import sys
import time


def find_qemu_user() -> str:
    """查找 QEMU user mode 可执行文件."""
    for name in ['qemu-x86_64', 'qemu-x86_64-static']:
        try:
            result = subprocess.run(['which', name],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            pass
    # 常见路径
    for p in ['/usr/bin/qemu-x86_64', '/usr/local/bin/qemu-x86_64']:
        if os.path.isfile(p):
            return p
    return ''


def analyze_with_qemu(binary_path: str,
                       args: list = None) -> dict:
    """QEMU user mode + trace 解析."""
    result = {
        'binary': os.path.basename(binary_path),
        'vulns_found': 0, 'vulns': [],
        'elapsed_sec': 0.0, 'memory_accesses': 0,
        'error': '',
    }

    qemu = find_qemu_user()
    if not qemu:
        result['error'] = 'qemu-x86_64 not found'
        return result

    start = time.time()
    try:
        cmd = [qemu, '-d', 'in_asm,cpu', '-D', '/dev/stdout', binary_path]
        if args:
            cmd.extend(args)

        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)

        mem_pattern = re.compile(
            r'(LOD|STO|MOV).*\[(0x[0-9a-f]+)\]', re.IGNORECASE)
        accesses = mem_pattern.findall(proc.stdout + proc.stderr)
        result['memory_accesses'] = len(accesses)

        heap_funcs = re.findall(
            r'(malloc|calloc|realloc|free|memcpy|strcpy)',
            proc.stdout + proc.stderr, re.IGNORECASE)
        for hf in set(heap_funcs):
            result['vulns'].append({
                'func': hf, 'addr': '0x0',
                'note': 'heap operation detected via QEMU trace',
            })
        result['vulns_found'] = len(result['vulns'])

        result['elapsed_sec'] = round(time.time() - start, 2)

    except subprocess.TimeoutExpired:
        result['error'] = 'QEMU execution timeout (>30s)'
        result['elapsed_sec'] = 30.0
    except FileNotFoundError:
        result['error'] = 'qemu-x86_64 not found'
    except Exception as e:
        result['error'] = str(e)[:200]
        result['elapsed_sec'] = round(time.time() - start, 2)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'usage: run_qemu.py <binary> [args]'}))
        sys.exit(1)
    binary = sys.argv[1]
    extra_args = sys.argv[2:] if len(sys.argv) > 2 else None
    result = analyze_with_qemu(binary, extra_args)
    print(json.dumps(result, indent=2))
