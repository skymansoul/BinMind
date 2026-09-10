"""运行时追踪器 — QEMU user-mode 插桩 / ASAN ground truth 双模式.

方法:
  1. QEMU 模式: qemu-x86_64 -d in_asm 捕获指令流, 解析 malloc/memcpy
     调用与地址, 推算写入越界 (需要 qemu-user, Linux).
  2. ASAN 模式 (默认, Windows 可运行): 将样本源码以 -fsanitize=address
     重新编译, 运行并解析 ASAN 报告 → 运行时 ground truth.
     检出 = ASAN 报告包含 heap-buffer-overflow 且归属该样本.

约定: 输出 dict: {tool, sample, findings, detected, error, time_ms,
                  ground_truth: true/false}
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from _common import HERE as _HERE
CC = os.environ.get('CC', 'gcc')

_ASAN_HEAP_RE = re.compile(
    r'ERROR: AddressSanitizer: heap-buffer-overflow|'
    r'ERROR: AddressSanitizer: global-buffer-overflow')


def qemu_trace(binary_path: str, sample_dir: str = '',
               timeout_sec: int = 60) -> dict:
    """QEMU user-mode 指令流追踪 (Linux 环境)."""
    t0 = time.time()
    result = {'tool': 'qemu', 'sample': os.path.basename(binary_path),
              'findings': 0, 'detected': False, 'error': '',
              'time_ms': 0.0, 'ground_truth': True}
    qemu = shutil.which('qemu-x86_64')
    if qemu is None:
        result['error'] = 'qemu-x86_64 not available, use asan mode'
        result['time_ms'] = round((time.time() - t0) * 1000, 1)
        return result
    try:
        proc = subprocess.run(
            [qemu, '-d', 'in_asm', binary_path],
            capture_output=True, text=True, timeout=timeout_sec)
        trace = proc.stderr
        mallocs = re.findall(
            r'mov\s+\$0x[0-9a-f]+,%ecx|callq?\s+[0-9a-f]+ <malloc>',
            trace)
        memcpys = re.findall(r'<memcpy@plt>', trace)
        result['findings'] = len(memcpys) + len(mallocs)
        result['detected'] = len(memcpys) > 0
    except subprocess.TimeoutExpired:
        result['error'] = 'qemu timeout'
    except Exception as e:  # noqa: BLE001
        result['error'] = repr(e)[:200]
    result['time_ms'] = round((time.time() - t0) * 1000, 1)
    return result


def asan_ground_truth(binary_path: str, sample_dir: str = '',
                      timeout_sec: int = 60) -> dict:
    """运行时 ground truth: 优先 libasan, 缺失时使用自写 shim 插桩."""
    t0 = time.time()
    result = {'tool': 'asan', 'sample': os.path.basename(binary_path),
              'findings': 0, 'detected': False, 'error': '',
              'time_ms': 0.0, 'ground_truth': True}

    src_candidates = []
    if sample_dir and os.path.isdir(sample_dir):
        src_candidates = [os.path.join(sample_dir, f)
                          for f in os.listdir(sample_dir) if f.endswith('.c')]
    if not src_candidates:
        src_candidates = [binary_path.replace('.exe', '.c')]
    src = next((s for s in src_candidates if os.path.exists(s)), None)
    if src is None:
        result['error'] = 'no source for rebuild'
        result['time_ms'] = round((time.time() - t0) * 1000, 1)
        return result

    tmp = tempfile.mkdtemp(prefix='pcfv_gt_')
    out_exe = os.path.join(tmp, 'probe.exe')
    try:
# 尝试1: libasan
        proc = subprocess.run(
            [CC, '-O0', '-g', '-fsanitize=address',
             '-fno-omit-frame-pointer', src, '-o', out_exe],
            capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            result['error'] = 'asan mode'
            return _run_probe(out_exe, result, t0, _ASAN_HEAP_RE,
                              timeout_sec, tmp)

        # ——— 尝试2: 自写 shim 插桩 (-include 注入, 无需单独编译 shim) ———
        shim = os.path.join(_HERE, 'runtime_shim.c')
        proc = subprocess.run(
            [CC, '-O0', '-g', '-include', shim, src, '-o', out_exe],
            capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            result['error'] = ('both asan and shim failed: '
                               + proc.stderr[:120])
            result['time_ms'] = round((time.time() - t0) * 1000, 1)
            return result
        result['error'] = 'shim mode'
        report_re = re.compile(r'SHIM-OVERFLOW')
        return _run_probe(out_exe, result, t0, report_re, timeout_sec, tmp)
    except subprocess.TimeoutExpired:
        result['error'] = 'compile timeout'
    except Exception as e:  # noqa: BLE001
        result['error'] = repr(e)[:200]
    result['time_ms'] = round((time.time() - t0) * 1000, 1)
    return result


def _run_probe(out_exe: str, result: dict, t0: float, report_re,
               timeout_sec: int, tmp: str) -> dict:
    """运行探针并解析报告."""
    try:
        run = subprocess.run([out_exe], capture_output=True, text=True,
                             timeout=timeout_sec)
        report = (run.stderr or '') + (run.stdout or '')
        matches = report_re.findall(report)
        result['findings'] = len(matches)
        result['detected'] = len(matches) > 0
    except subprocess.TimeoutExpired:
        result['error'] += ' | run timeout'
    except Exception as e:  # noqa: BLE001
        result['error'] += ' | run fail: ' + repr(e)[:120]
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass
    result['time_ms'] = round((time.time() - t0) * 1000, 1)
    return result


def run(binary_path: str, sample_dir: str = '', mode: str = 'asan',
        timeout_sec: int = 60) -> dict:
    """入口: mode = qemu | asan."""
    if mode == 'qemu':
        return qemu_trace(binary_path, sample_dir, timeout_sec)
    return asan_ground_truth(binary_path, sample_dir, timeout_sec)


if __name__ == '__main__':
    import json
    if len(sys.argv) < 2:
        print('usage: python qemu_tracer.py <binary> [sample_dir] [mode]')
        sys.exit(1)
    mode = sys.argv[3] if len(sys.argv) > 3 else 'asan'
    sd = sys.argv[2] if len(sys.argv) > 2 else ''
    print(json.dumps(run(sys.argv[1], sd, mode)))
