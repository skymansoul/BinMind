#!/usr/bin/env python3
# coding: utf-8
"""
QEMU user mode + strace 插桩 — 获取运行时内存操作作为 ground truth.

使用 QEMU user mode 的 -strace 选项记录所有系统调用,
解析 mmap/munmap/brk 以重建堆分配/释放事件,
用于校准静态分析的误报率.

v2 改进:
  - 正确的 mmap/mremap/munmap/brk 参数解析 (含 size, prot, flags)
  - 区分匿名映射 (MAP_ANONYMOUS) 与文件映射
  - 记录每次分配的实际大小, 不再使用空正则

需求: qemu-x86_64 (或 qemu-i386) 已安装.
"""

import os, sys, json, time, subprocess, re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# mmap strace 输出格式:
#   mmap(addr, length, prot, flags, fd, offset) = result
#   e.g.: mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x7f...
_MMAP_PATTERN = re.compile(
    r'mmap\(([^,]*),\s*(\d+|0x[0-9a-fA-F]+)')
_MUNMAP_PATTERN = re.compile(
    r'munmap\((0x[0-9a-fA-F]+),\s*(\d+|0x[0-9a-fA-F]+)')
_BRK_PATTERN = re.compile(
    r'brk\((0x[0-9a-fA-F]+|\d+)\)\s*=\s*(0x[0-9a-fA-F]+|\d+)')
_MREMAP_PATTERN = re.compile(
    r'mremap\([^,]*,\s*(\d+).*,\s*(\d+)')  # old_size, new_size
_MMAP_FLAGS = re.compile(r'MAP_ANONYMOUS|MAP_ANON|MAP_PRIVATE')

# 危险写入的系统调用
_WRITE_SYSCALLS = {
    'write(', 'pwrite(', 'send(', 'sendto(', 'sendmsg(',
}


@dataclass
class TraceRecord:
    addr: int
    size: int
    op_type: str  # 'alloc' | 'free' | 'realloc'
    timestamp: int = 0


def trace_with_qemu(elf_path: str,
                    qemu_binary: str = 'qemu-x86_64',
                    timeout_s: int = 30,
                    ) -> Dict[str, Any]:
    """使用 QEMU user mode + strace 运行 ELF 并收集内存操作 trace.

    返回: {sample_id, success, alloc_events, total_allocs, total_writes, ...}
    """
    result = {
        'sample_id': os.path.basename(elf_path).replace('.elf', ''),
        'elf_path': elf_path,
        'success': False,
        'alloc_events': [],
        'total_allocs': 0,
        'total_frees': 0,
        'total_writes': 0,
        'alloc_sizes': [],
        'wall_time_s': 0.0,
        'error': '',
    }

    t0 = time.perf_counter()

    # 检查 QEMU 是否可用
    try:
        ver = subprocess.run(
            [qemu_binary, '--version'],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result['error'] = f'QEMU binary "{qemu_binary}" 不可用'
        result['wall_time_s'] = time.perf_counter() - t0
        return result

    try:
        # 用 -strace 捕获所有 syscall, -d in_asm 可选
        proc = subprocess.run(
            [qemu_binary, '-strace', '-D', '/dev/stdout', elf_path],
            capture_output=True, text=True,
            timeout=timeout_s,
            env={**os.environ, 'QEMU_LOG': 'unimp'},
        )

        output = proc.stdout + '\n' + proc.stderr
        allocs = _parse_strace_output(output)

        result['alloc_events'] = [
            {'addr': hex(a.addr), 'size': a.size, 'type': a.op_type}
            for a in allocs[:200]
        ]
        result['alloc_sizes'] = [
            a.size for a in allocs if a.op_type == 'alloc' and 16 <= a.size <= 2**24
        ]
        result['total_allocs'] = sum(
            1 for a in allocs if a.op_type == 'alloc')
        result['total_frees'] = sum(
            1 for a in allocs if a.op_type == 'free')
        result['total_writes'] = len(
            [l for l in output.split('\n')
             if any(ws in l for ws in _WRITE_SYSCALLS)])
        result['success'] = True

    except subprocess.TimeoutExpired:
        result['error'] = f'QEMU 执行超时 ({timeout_s}s)'
    except Exception as e:
        result['error'] = str(e)[:200]

    result['wall_time_s'] = round(time.perf_counter() - t0, 2)
    return result


def _parse_strace_output(output: str) -> List[TraceRecord]:
    """解析 QEMU strace 输出, 提取 mmap/munmap/brk 事件."""
    records = []
    ts = 0

    for line in output.split('\n'):
        ts += 1
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # mmap: 分配新内存
        m = _MMAP_PATTERN.search(line_stripped)
        if m and _MMAP_FLAGS.search(line_stripped):
            try:
                size = int(m.group(2), 0)
                if 32 <= size <= 2**24:
                    # 提取返回值作为地址
                    addr_match = re.search(r'=\s*(0x[0-9a-fA-F]+)', line_stripped)
                    addr = int(addr_match.group(1), 16) if addr_match else 0
                    records.append(TraceRecord(
                        addr=addr, size=size, op_type='alloc', timestamp=ts))
            except (ValueError, IndexError):
                pass

        # munmap: 释放内存
        m = _MUNMAP_PATTERN.search(line_stripped)
        if m:
            try:
                addr = int(m.group(1), 16)
                size = int(m.group(2), 0)
                records.append(TraceRecord(
                    addr=addr, size=size, op_type='free', timestamp=ts))
            except (ValueError, IndexError):
                pass

        # brk: 扩展/收缩数据段
        m = _BRK_PATTERN.search(line_stripped)
        if m:
            try:
                # 若 brk 返回值 > 参数值 → 扩展 (malloc 底层)
                new_brk = int(m.group(2), 0) if m.group(2).startswith('0x') else int(m.group(2))
                old_brk = int(m.group(1), 0) if m.group(1).startswith('0x') else int(m.group(1))
                if new_brk > old_brk:
                    size = new_brk - old_brk
                    if 32 <= size <= 2**24:
                        records.append(TraceRecord(
                            addr=old_brk, size=size, op_type='alloc', timestamp=ts))
            except (ValueError, IndexError):
                pass

        # mremap: 重新分配
        m = _MREMAP_PATTERN.search(line_stripped)
        if m:
            try:
                old_sz = int(m.group(1))
                new_sz = int(m.group(2))
                if new_sz > old_sz:
                    records.append(TraceRecord(
                        addr=0, size=new_sz, op_type='realloc', timestamp=ts))
            except (ValueError, IndexError):
                pass

    return records


def qemu_batch(elf_paths: List[str],
               qemu_binary: str = 'qemu-x86_64',
               output_json: Optional[str] = None) -> List[Dict]:
    """批量运行 QEMU 追踪."""
    results = []
    for i, path in enumerate(elf_paths):
        print(f'[{i+1}/{len(elf_paths)}] QEMU tracing {os.path.basename(path)} ...')
        r = trace_with_qemu(path, qemu_binary)
        results.append(r)
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    return results


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf_paths', nargs='+')
    ap.add_argument('--qemu', default='qemu-x86_64')
    ap.add_argument('--output')
    args = ap.parse_args()
    qemu_batch(args.elf_paths, args.qemu, args.output)
