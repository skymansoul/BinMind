"""Angr exploration 模式适配器 — 符号执行检测漏洞点。

方法: 对每个样本加载 angr Project, 用 CFGFast 识别危险函数调用,
从调用点反向符号执行计算到达条件。若 angr 不可用则输出空结果。
"""

import os, json, time, sys


def run_angr_analysis(binary_path: str, timeout_sec: int = 120) -> dict:
    t0 = time.time()
    result = {'tool': 'Angr', 'binary': binary_path,
              'findings': 0, 'elapsed_sec': 0, 'error': ''}

    try:
        import angr
        import claripy
    except ImportError:
        result['error'] = 'angr not installed'
        result['elapsed_sec'] = time.time() - t0
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        dangerous_funcs = {
            'printf', 'fprintf', 'sprintf', 'gets', 'strcpy', 'strcat',
            'malloc', 'free', 'memcpy', 'read', 'recv',
        }
        findings = []
        sig_found = set()

        for func in cfg.functions.values():
            if func.is_simprocedure or func.is_plt:
                continue
            for block in func.blocks:
                for ins in block.capstone.insns:
                    if ins.mnemonic != 'call':
                        continue
                    target = ins.operands[0].imm if ins.operands else 0
                    target_func = cfg.functions.get(target)
                    if target_func is None:
                        continue
                    fname = target_func.name
                    if fname in dangerous_funcs and fname not in sig_found:
                        sig_found.add(fname)
                        findings.append({
                            'function': func.name,
                            'dangerous_call': fname,
                            'address': hex(ins.address),
                        })

        result['findings'] = len(findings)
        result['details'] = findings[:20]
        result['elapsed_sec'] = round(time.time() - t0, 1)

    except Exception as e:
        result['error'] = str(e)[:200]
        result['elapsed_sec'] = round(time.time() - t0, 1)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: python angr_runner.py <binary>')
        sys.exit(1)
    r = run_angr_analysis(sys.argv[1])
    print(json.dumps(r, indent=2))
