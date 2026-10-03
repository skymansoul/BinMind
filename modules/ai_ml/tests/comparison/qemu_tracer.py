# QEMU user mode插桩——捕获运行时内存操作作为ground truth
# 通过QEMU的 -trace 或 -d 选项记录所有内存访问，
# 后处理提取危险函数的实际调用参数→建立误报ground truth基线
#
# 使用方式: qemu-x86_64 -d exec,cpu -D trace.log ./target < input

import subprocess
import re
import json
import sys
import time
from pathlib import Path

QEMU_BINARIES = ['qemu-x86_64', 'qemu-x86_64-static',
                 'qemu-i386', 'qemu-aarch64']


def find_qemu() -> str:
    for qb in QEMU_BINARIES:
        try:
            r = subprocess.run([qb, '--version'], capture_output=True, timeout=5)
            if r.returncode == 0:
                return qb
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ''


def trace_binary(binary_path: str, input_data: bytes = b'',
                 timeout: int = 30) -> dict:
    t0 = time.perf_counter()
    result = {'tool': 'qemu', 'binary': binary_path,
              'available': False, 'vulns': [], 'mem_ops': [],
              'time_ms': 0, 'error': ''}

    qemu = find_qemu()
    if not qemu:
        result['error'] = 'QEMU user mode not found in PATH'
        return result
    result['available'] = True

    trace_file = Path(binary_path).parent / 'qemu_trace.log'
    try:
        proc = subprocess.run(
            [qemu, '-d', 'cpu,exec', '-D', str(trace_file), binary_path],
            input=input_data, capture_output=True, timeout=timeout)
        result['exit_code'] = proc.returncode

        # 解析trace log中的内存写操作
        if trace_file.exists():
            mem_writes = []
            addr_re = re.compile(r'vaddr=0x([0-9a-f]+)')
            size_re = re.compile(r'size=(\d+)')
            with open(trace_file, errors='ignore') as f:
                for line in f:
                    addr_m = addr_re.search(line)
                    size_m = size_re.search(line)
                    if addr_m:
                        mem_writes.append({
                            'addr': int(addr_m.group(1), 16),
                            'size': int(size_m.group(1)) if size_m else 0,
                        })
            result['mem_ops'] = mem_writes[:500]  # 截断
    except subprocess.TimeoutExpired:
        result['error'] = 'QEMU trace timed out'
    except Exception as e:
        result['error'] = str(e)[:500]

    result['time_ms'] = (time.perf_counter() - t0) * 1000
    if trace_file.exists():
        trace_file.unlink()
    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': '用法: python qemu_tracer.py <binary> [input]'}))
        sys.exit(0)
    inp = sys.argv[2].encode() if len(sys.argv) > 2 else b''
    r = trace_binary(sys.argv[1], inp)
    print(json.dumps(r, indent=2))
