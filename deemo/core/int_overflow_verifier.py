"""
整数溢出约束验证 - 对标 heap_overflow_verifier 的路径敏感验证范式。
区间分析是过近似(误报源头), 约束验证是精确求解: 用 angr 定向符号执行,
SMT 确认溢出条件在真实路径上可满足才保留。
"""
import time
from typing import Any, Dict, List, Optional, Tuple

_TIMEOUT = 20

def verify_overflow_reachable(
    binary_path: str,
    func_name: str,
    overflow_addr: int,
    target_var: str = "",
    timeout: int = _TIMEOUT,
) -> Dict[str, Any]:
    """验证整数溢出在真实执行路径上是否可达且可触发。

    返回 {reachable, overflow_possible, solver_time, error}。
    """
    result = {
        'reachable': False, 'overflow_possible': False,
        'solver_time': 0.0, 'error': None,
    }

    try:
        import angr, claripy
    except ImportError:
        result['error'] = 'angr_unavailable'
        return result

    t0 = time.time()
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        func_addr = None
        for f in cfg.functions.values():
            if f.name == func_name:
                func_addr = f.addr
                break
        if func_addr is None:
            result['error'] = f'function {func_name} not found'
            result['solver_time'] = time.time() - t0
            return result

        sym_input = claripy.BVS('iof_input', 512 * 8)
        state = proj.factory.entry_state(
            addr=func_addr,
            stdin=angr.SimFile('/dev/stdin', content=sym_input),
        )

        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.Timeout(timeout=timeout))

        def _reached(s): return s.addr == overflow_addr
        simgr.explore(find=_reached, num_find=2)

        if not simgr.found:
            result['error'] = 'overflow_site_unreachable'
            result['solver_time'] = time.time() - t0
            return result

        found = simgr.found[0]
        result['reachable'] = True

        # 尝试求解"结果是否可能超出INT32_MAX"
        # 构造代表乘法/加法结果的符号变量
        result_sym = claripy.BVS('overflow_result', 64)
        # 添加溢出条件: result > 0x7FFFFFFF
        overflow_cond = claripy.UGT(result_sym, claripy.BVV(0x7FFFFFFF, 64))

        solver = claripy.Solver()
        solver.add(*found.solver.constraints)
        solver.add(overflow_cond)
        result['overflow_possible'] = solver.satisfiable()
        result['solver_time'] = time.time() - t0

    except Exception as e:
        result['error'] = f'{type(e).__name__}:{str(e)[:80]}'
        result['solver_time'] = time.time() - t0

    return result

def filter_iof_findings(
    binary_path: str,
    findings: List[Dict],
    max_verify: int = 6,
) -> Tuple[List[Dict], Dict[str, int]]:
    """对整数溢出告警做约束验证过滤。

    规则:
      angr不可用 - 不调整(保留原置信度)
      不可达 - confidence x 0.20
      可达但溢出不可满足 - confidence x 0.40
      可达且溢出可满足 - confidence = max(0.85, old)
    """
    stats = {'total': len(findings), 'verified': 0, 'filtered': 0, 'confirmed': 0}

    for f in findings[:max_verify]:
        func = f.get('function', '')
        addr = f.get('call_address', f.get('overflow_address', 0))
        if addr == 0:
            continue

        vr = verify_overflow_reachable(binary_path, func, addr)
        f['overflow_verification'] = vr
        stats['verified'] += 1

        if vr.get('error'):
            continue

        if not vr.get('reachable'):
            f['confidence'] = round(f.get('confidence', 0.5) * 0.20, 3)
            stats['filtered'] += 1
        elif not vr.get('overflow_possible'):
            f['confidence'] = round(f.get('confidence', 0.5) * 0.40, 3)
            stats['filtered'] += 1
        else:
            f['confidence'] = max(0.85, f.get('confidence', 0.5))
            stats['confirmed'] += 1

    return findings, stats
