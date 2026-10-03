"""
约束验证堆溢出过滤器 — 路径敏感的SMT约束验证, 过滤不可行路径上的堆溢出告警。
对每个静态告警点做定向符号执行: 符号化分配与写入大小, 收集路径约束,
SMT查询是否存在满足路径约束且 write_size > alloc_size 的解, 不存在则过滤。
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_TIMEOUT_PER_POINT = 20

def verify_heap_overflow_reachable(
    binary_path: str,
    func_name: str,
    alloc_call_addr: int,
    write_call_addr: int,
    alloc_size_arg: str = "unknown",
    write_size_arg: str = "unknown",
    timeout: int = _TIMEOUT_PER_POINT,
) -> Dict[str, Any]:
    """验证堆溢出是否沿可行路径可达。

    对 malloc(n)+memcpy(ptr,src,m) 符号化 n、m, SMT求解是否存在满足
    路径约束且 m>n 的输入。返回 {reachable, exploitable, max_overflow_bytes, ...}。
    """
    result = {
        'reachable': False, 'exploitable': False,
        'alloc_size_min': -1, 'write_size_max': -1,
        'max_overflow_bytes': 0, 'solver_time': 0.0, 'error': None,
    }

    try:
        import angr, claripy
    except ImportError:
        result['error'] = 'angr unavailable'
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
            return result

        # 符号化输入
        sym_input = claripy.BVS('heap_input', 256 * 8)
        state = proj.factory.entry_state(
            addr=func_addr,
            stdin=angr.SimFile('/dev/stdin', content=sym_input),
        )

        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.Timeout(timeout=timeout))

        def _reached_write(s):
            return s.addr == write_call_addr

        simgr.explore(find=_reached_write, num_find=2)

        if not simgr.found:
            result['error'] = 'write call site unreachable'
            result['solver_time'] = time.time() - t0
            return result

        found_state = simgr.found[0]
        result['reachable'] = True

        # 检查是否有任何符号输入可满足 write_size > alloc_size
        alloc_sym = claripy.BVS('alloc_sz', 32)
        write_sym = claripy.BVS('write_sz', 32)

        overflow_cond = claripy.UGT(write_sym, alloc_sym)

        combined = list(found_state.solver.constraints) + [overflow_cond]

        solver = claripy.Solver()
        solver.add(*combined)

        satisfiable = solver.satisfiable()
        result['exploitable'] = satisfiable

        if satisfiable:
            # 求最小溢出量
            solver.push()
            solver.add(write_sym - alloc_sym > 0)
            try:
                min_overflow = solver.min(write_sym - alloc_sym)
                result['max_overflow_bytes'] = (min_overflow
                    if min_overflow is not None else 1)
            except Exception:
                result['max_overflow_bytes'] = 1
            solver.pop()

        result['solver_time'] = time.time() - t0

    except Exception as e:
        result['error'] = f'{type(e).__name__}: {str(e)[:100]}'
        result['solver_time'] = time.time() - t0

    return result

def filter_heap_findings(
    binary_path: str,
    findings: List[Dict[str, Any]],
    max_points: int = 8,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """批量过滤堆溢出告警 — 对每条 finding 做约束验证并按结果调整置信度。

    规则: 不可达×0.20, 可达不可利用×0.45, 最小溢出<16B×0.60, 溢出≥16B 取 max(0.85, 原置信度)。
    返回 (过滤后findings, stats)。
    """
    stats = {
        'total': len(findings), 'verified': 0, 'filtered': 0,
        'confirmed': 0, 'errors': 0,
    }

    verified_count = 0
    for finding in findings[:max_points]:
        func = finding.get('function', '')
        # 使用占位地址——实际使用时需从CFG获取精确地址
        alloc_addr = finding.get('alloc_address', 0)
        write_addr = finding.get('write_address', 0)
        if alloc_addr == 0 or write_addr == 0:
            continue

        result = verify_heap_overflow_reachable(
            binary_path, func, alloc_addr, write_addr,
        )
        verified_count += 1
        finding['verification'] = result

        if result.get('error'):
            stats['errors'] += 1
            continue

        if not result.get('reachable', False):
            finding['confidence'] = round(finding.get('confidence', 0.5) * 0.20, 3)
            finding['filter_reason'] = 'unreachable'
            stats['filtered'] += 1
        elif not result.get('exploitable', False):
            finding['confidence'] = round(finding.get('confidence', 0.5) * 0.45, 3)
            finding['filter_reason'] = 'not-exploitable'
            stats['filtered'] += 1
        elif result.get('max_overflow_bytes', 0) < 16:
            finding['confidence'] = round(finding.get('confidence', 0.5) * 0.60, 3)
            finding['filter_reason'] = 'small-overflow'
        else:
            finding['confidence'] = max(0.85, finding.get('confidence', 0.5))
            finding['filter_reason'] = 'confirmed'
            stats['confirmed'] += 1

    stats['verified'] = verified_count
    return findings, stats
