# QEMU user mode tracer — 抓取运行时内存操作作为 ground truth
# 用于统计对比工具的误报/漏报

import subprocess, sys, time, json, shutil

def trace_binary(binary_path: str, input_data: str = '') -> dict:
    """QEMU user mode + strace 追踪binary运行时行为

    返回: {crashed, syscalls, time_ms, error}
    """
    t0 = time.perf_counter()
    result = {'tool': 'QEMU', 'binary': binary_path, 'crashed': False,
              'syscalls': 0, 'signals': [], 'time_ms': 0, 'error': ''}
    qemu = shutil.which('qemu-x86_64') or shutil.which('qemu-x86_64-static')
    if not qemu:
        result['error'] = 'qemu-x86_64 not found in PATH'
        result['time_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        return result
    try:
        cmd = [qemu, '-strace', '-E', 'LD_LIBRARY_PATH=/usr/lib', binary_path]
        r = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=15)
        result['crashed'] = ('SIGSEGV' in r.stderr or 'SIGABRT' in r.stderr
                             or 'SIGILL' in r.stderr or 'SIGBUS' in r.stderr)
        result['syscalls'] = len([l for l in r.stderr.split('\n') if '=' in l])
        for sig in ['SIGSEGV','SIGABRT','SIGILL','SIGBUS','SIGFPE']:
            if sig in r.stderr:
                result['signals'].append(sig)
    except subprocess.TimeoutExpired:
        result['error'] = 'timeout (15s)'
    except Exception as e:
        result['error'] = str(e)[:200]
    result['time_ms'] = round((time.perf_counter() - t0) * 1000, 1)
    return result

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('binary'); p.add_argument('--json', action='store_true')
    args = p.parse_args()
    r = trace_binary(args.binary)
    if args.json: print(json.dumps(r, indent=2))
    else: print(f'QEMU: crashed={r["crashed"]}, syscalls={r["syscalls"]}, {r["time_ms"]}ms')
