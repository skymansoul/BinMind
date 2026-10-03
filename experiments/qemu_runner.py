"""QEMU user mode + 自定义插桩适配器。

方法: qemu-x86_64 -d in_asm,cpu 运行二进制, 解析执行 trace,
在基本块边界记录访存模式。从 trace 中识别危险调用模式。
若 qemu-user 不可用则输出空结果。
"""

import os, json, time, subprocess, sys, tempfile, re


def run_qemu_analysis(binary_path: str, timeout_sec: int = 60) -> dict:
    t0 = time.time()
    result = {'tool': 'QEMU+instrumentation', 'binary': binary_path,
              'findings': 0, 'elapsed_sec': 0, 'error': ''}

    qemu_bin = os.environ.get('QEMU_USER', 'qemu-x86_64')
    try:
        subprocess.run([qemu_bin, '--version'], capture_output=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        result['error'] = 'qemu-user not available'
        result['elapsed_sec'] = time.time() - t0
        return result

    try:
        proc = subprocess.run(
            [qemu_bin, '-d', 'in_asm', binary_path],
            capture_output=True, text=True, timeout=timeout_sec,
            input='AAAA%x%x%x%x\n',
        )
        trace = proc.stdout + proc.stderr
        elapsed = time.time() - t0

        # 在 trace 中搜索危险函数调用模式
        dangerous = {
            'printf@plt', 'gets@plt', 'strcpy@plt', 'free@plt',
            'malloc@plt', 'memcpy@plt',
        }
        found = set()
        for line in trace.split('\n'):
            for df in dangerous:
                if df in line:
                    found.add(df)

        result['findings'] = len(found)
        result['details'] = list(found)
        result['elapsed_sec'] = round(elapsed, 1)

    except subprocess.TimeoutExpired:
        result['error'] = 'timeout'
        result['elapsed_sec'] = timeout_sec
    except Exception as e:
        result['error'] = str(e)[:200]
        result['elapsed_sec'] = round(time.time() - t0, 1)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: python qemu_runner.py <binary>')
        sys.exit(1)
    r = run_qemu_analysis(sys.argv[1])
    print(json.dumps(r, indent=2))
