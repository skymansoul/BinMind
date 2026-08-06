"""
QEMU user mode 对比实验 —— 轻量插桩抓取运行时内存操作。

使用 QEMU user mode (-d in_asm,nochain) + 解析日志提取内存读写大小,
作为 ground truth 辅助统计静态分析工具的误报。

原理: QEMU -d in_asm 输出每条 guest 指令, 解析其中的内存操作数,
记录每次 load/store 的地址和大小。若静态工具报告某处有溢出,
但 QEMU trace 显示该分配块的实际访问从未超出边界 → 可能是误报。
"""

import os, sys, subprocess, json, re, time, argparse, tempfile

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)

_MEM_ACCESS_PAT = re.compile(
    r'(?:mov|lea|add|sub|cmp|push|pop|call|jmp)\s+.*?'
    r'(?:\[|\()(?:%?\w+:)?(0x[0-9a-fA-F]+)'
)

_ALLOC_PAT = re.compile(
    r'(?:mmap|brk|malloc|calloc|realloc)\s*\(\s*(0x[0-9a-fA-F]+)?'
)


def trace_with_qemu(binary_path: str, timeout: int = 30) -> dict:
    """
    使用 QEMU user mode 追踪二进制执行。

    返回追踪到的内存操作列表。
    """
    result = {
        'binary': binary_path, 'tool': 'qemu-user',
        'memory_accesses': [], 'alloc_events': [],
        'error': '', 'elapsed_ms': 0,
    }

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ['qemu-x86_64', '-d', 'in_asm,nochain', '-D', '/dev/stdout',
             binary_path],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        output = proc.stdout + proc.stderr
        for m in _MEM_ACCESS_PAT.finditer(output):
            result['memory_accesses'].append(m.group(0)[:80])
        for m in _ALLOC_PAT.finditer(output):
            result['alloc_events'].append(m.group(0)[:80])
    except FileNotFoundError:
        result['error'] = 'qemu-x86_64 not found in PATH'
    except subprocess.TimeoutExpired:
        result['error'] = f'timeout after {timeout}s'
    except Exception as e:
        result['error'] = str(e)[:200]
    finally:
        result['elapsed_ms'] = (time.perf_counter() - t0) * 1000

    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', help='Path to ELF binary')
    ap.add_argument('--timeout', type=int, default=30)
    ap.add_argument('--output', default='')
    args = ap.parse_args()
    result = trace_with_qemu(args.binary, args.timeout)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
    print(f"Memory accesses: {len(result['memory_accesses'])}")
    print(f"Errors: {result['error'] or 'none'}")
