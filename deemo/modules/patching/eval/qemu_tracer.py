# QEMU user mode tracer — 运行时内存操作捕获作为 ground truth
"""通过运行时执行获取崩溃行为作为检测ground truth。

策略:
  1. 若存在 qemu-x86_64 (Linux ELF环境) → 用QEMU user mode运行,
     检测SIGSEGV/SIGABRT等信号。
  2. Windows/MinGW环境 → 本地执行PE, 捕获异常退出码
     (如 0xC0000005 访问冲突 = 越界写证据)。
  3. 两者都无法运行时标记error, 输出结构保持一致。

自写轻量插桩说明:
  QEMU完整插桩(trace-mem插件)需要custom build, 本脚本以
  "运行-崩溃"二元信号作为ground truth锚, 可扩展性保留。

输出JSON: {tool, crashed, exit_code, signal, time_secs, error}
"""

import os, sys, json, time, subprocess, tempfile, re

_CRASH_MARKERS = [
    (0xC0000005, 'ACCESS_VIOLATION'),   # Windows 访问冲突
    (0xC0000374, 'HEAP_CORRUPTION'),    # Windows 堆损坏
    (0xC00000FD, 'STACK_OVERFLOW'),     # Windows 栈溢出
]

# 已知导致堆越界的样本参数(触发溢出路径)
_CRASH_ARGS = {
    'CVE-2025-TP001': ['512'],
    'CVE-2025-TP002': ['107374183'],
    'CVE-2025-TP003': ['1024', '2048'],
    'CVE-2025-TP004': ['A' * 64],
    'CVE-2025-TP005': ['-1', 'A' * 64],
    'CVE-2025-TP006': ['16', 'A' * 32],
    'CVE-2025-TP007': ['64', 'A' * 80],
    'CVE-2025-TP008': ['107374183'],
    'CVE-2025-TP009': ['64', 'A' * 96],
    'CVE-2025-TP010': ['16', '64'],
    'CVE-2025-TP011': ['64', 'A' * 128],
    'CVE-2025-TP012': ['4096'],
    'CVE-2025-TP013': ['A' * 32, 'B' * 64],
    'CVE-2025-TP014': ['6'],
    'CVE-2025-TP015': ['A' * 64, 'B' * 16],
    'CVE-2025-TP016': ['A' * 64],
    'CVE-2021-3156': ['-c', '1', 'x'],
    'CVE-2015-0235': ['AAAA', '1'],
    'CVE-2023-27997': ['256', 'A' * 600],
}


def _pick_args(binary_path: str) -> list:
    base = os.path.basename(os.path.dirname(binary_path))
    for key, args in _CRASH_ARGS.items():
        if key in base:
            return list(args)
    return []


def _is_qemu_available() -> bool:
    try:
        r = subprocess.run(['qemu-x86_64', '--version'],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _run_qemu(binary_path: str, args: list) -> dict:
    """QEMU user mode执行; 若存在memtrace插件则同时采集内存操作。"""
    try:
        plugin = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'qemu_memtrace.so')
        cmd = ['qemu-x86_64', binary_path] + args
        if os.path.isfile(plugin):
            cmd = ['qemu-x86_64', '-plugin', plugin, '-d', 'plugin',
                   binary_path] + args
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=15)
        rc = proc.returncode
        mem = {}
        # 解析MEMTRACE插件输出
        m = re.search(r'MEMTRACE total_access=(\d+) heap_writes=(\d+) '
                      r'range=\[0x([0-9a-f]+), 0x([0-9a-f]+)\]',
                      proc.stderr)
        if m:
            mem = {'total_access': int(m.group(1)),
                   'heap_writes': int(m.group(2)),
                   'min_addr': int(m.group(3), 16),
                   'max_addr': int(m.group(4), 16)}
        return {'crashed': rc < 0, 'exit_code': rc,
                'signal': -rc if rc < 0 else 0, 'mem_ops': mem}
    except FileNotFoundError:
        return {'crashed': False, 'exit_code': 0, 'signal': 0,
                'error': 'qemu-x86_64 not found'}
    except subprocess.TimeoutExpired:
        return {'crashed': False, 'exit_code': 0, 'signal': 0,
                'error': 'timeout'}


def _run_native(binary_path: str, args: list) -> dict:
    """Windows下原生执行PE, 用退出码/异常码判断崩溃。"""
    try:
        proc = subprocess.run([binary_path] + args,
                              capture_output=True, timeout=15)
        rc = proc.returncode
        if rc < 0:
            return {'crashed': True, 'exit_code': rc,
                    'signal': -rc}
        # Windows异常以高位退出码形式出现
        unsigned = rc & 0xFFFFFFFF
        if unsigned >= 0xC0000000:
            for code, name in _CRASH_MARKERS:
                if unsigned == code:
                    return {'crashed': True, 'exit_code': rc,
                            'signal': name}
            return {'crashed': True, 'exit_code': rc,
                    'signal': f'EXCEPTION 0x{unsigned:08X}'}
        return {'crashed': False, 'exit_code': rc, 'signal': 0}
    except subprocess.TimeoutExpired:
        return {'crashed': False, 'exit_code': 0, 'signal': 0,
                'error': 'timeout'}
    except Exception as e:
        return {'crashed': False, 'exit_code': 0, 'signal': 0,
                'error': str(e)[:100]}


def trace_binary(binary_path: str, args: list = None) -> dict:
    t0 = time.time()
    result = {"tool": "QEMU+Trace", "binary": binary_path,
              "crashed": False, "exit_code": 0, "signal": 0,
              "time_secs": 0, "error": None}
    if args is None:
        args = _pick_args(binary_path)

    if _is_qemu_available():
        r = _run_qemu(binary_path, args)
    else:
        r = _run_native(binary_path, args)

    result.update(r)
    result["time_secs"] = round(time.time() - t0, 2)
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python qemu_tracer.py <binary> [args...]"); sys.exit(1)
    r = trace_binary(sys.argv[1], sys.argv[2:] if len(sys.argv) > 2 else None)
    print(json.dumps(r, indent=2))
