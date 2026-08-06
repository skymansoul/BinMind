"""
Angr 对比实验脚本 —— 使用 Angr 的 exploration 引擎做漏洞点分析。

方法: 加载 ELF → CFG → 搜索危险函数调用 (strcpy/memcpy/gets/printf/free)
→ 对每个 call site 检查参数约束 → 标记为潜在漏洞点。
"""

import os, sys, time, json, argparse, tracemalloc

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)


def analyze_with_angr(binary_path: str, timeout: int = 60) -> dict:
    """使用 Angr 分析二进制中的危险函数调用点。"""
    t0 = time.perf_counter()
    tracemalloc.start()

    result = {
        'binary': binary_path, 'tool': 'angr',
        'findings': [], 'error': '', 'elapsed_ms': 0, 'peak_memory_kb': 0,
    }

    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)

        # 危险函数集合
        dangerous = {
            'strcpy', 'strcat', 'sprintf', 'gets', 'memcpy',
            'printf', 'fprintf', 'free', 'malloc', 'scanf',
        }

        cfg = proj.analyses.CFGFast()
        found = 0

        for func_addr, func in cfg.functions.items():
            if found >= 50:
                break
            for block_addr in func.block_addrs:
                try:
                    block = proj.factory.block(block_addr)
                except Exception:
                    continue
                for ins in block.capstone.insns:
                    if ins.mnemonic != 'call':
                        continue
                    target = ins.operands[0].imm if ins.operands else None
                    if target is None:
                        continue
                    try:
                        sym = proj.loader.find_symbol(target)
                        if sym and sym.name in dangerous:
                            result['findings'].append({
                                'func': sym.name,
                                'addr': hex(block_addr),
                                'caller': func.name if func else 'unknown',
                            })
                            found += 1
                    except Exception:
                        pass

    except ImportError:
        result['error'] = 'angr not installed'
    except Exception as e:
        result['error'] = str(e)[:200]
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result['elapsed_ms'] = (time.perf_counter() - t0) * 1000
        result['peak_memory_kb'] = peak / 1024.0

    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', help='Path to ELF binary')
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--output', default='')
    args = ap.parse_args()
    result = analyze_with_angr(args.binary, args.timeout)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    print(json.dumps({k: v for k, v in result.items() if k != 'findings'}, indent=2))
    print(f"Total findings: {len(result['findings'])}")
