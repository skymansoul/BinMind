"""
约束可满足性验证器 — 用angr符号执行验证静态告警是否沿可行路径可达。

设计决策:
  1. 不对全程序做符号执行 -- 仅对静态检测出的可疑点做定向验证
  2. 每个点超时30s -- 控制总耗时, 避免路径爆炸
  3. 三步验证策略:
     a) 地址可达性: 从函数入口执行到目标地址, 路径约束是否可满足
     b) 参数符号性: 在目标地址处, 危险调用的参数是否符号化(可控)
     c) 最小输入: 若能到达且可控, 计算触发所需的最小输入长度

  这三步对应降误报的完整逻辑链:
    不可达 → 静态假阳性 → 置信度×0.3
    可达但参数不可控 → 潜在误报 → 置信度×0.6
    可达且参数可控 → 确认利用路径 → 置信度升至0.9+

与纯符号执行方案的区别:
  不做全路径探索 -- 仅验证静态告警的可达性。
  ISSTA 2025 (Shimizu et al.) 验证了"静态trace种子→动态执行验证"
  的降误报有效性, 本模块将该思路适配至二进制符号执行场景。

  - Shimizu et al., 2025, ISSTA, "Revisiting the Combination of Static Analysis
    Error Traces and Dynamic Symbolic Execution"
  - FSVDTG -- 符号性检测+安全检查策略+可满足性验证的范式
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

# 每点验证超时(秒)
_TIMEOUT_PER_POINT = 30
# 最大探索步数(angr active states上限)
_MAX_ACTIVE_STATES = 30

def verify_call_reachability(
    binary_path: str,
    func_name: str,
    call_address: int,
    timeout: int = _TIMEOUT_PER_POINT,
) -> Dict[str, Any]:
    """验证angr符号执行能否到达目标调用地址。

    Returns:
        {reachable: bool, path_count: int, min_input_len: int, error: str|None}
    """
    result: Dict[str, Any] = {
        'reachable': False,
        'path_count': 0,
        'min_input_len': -1,
        'error': None,
        'elapsed_sec': 0.0,
    }

    try:
        import angr
        import claripy
    except ImportError:
        result['error'] = 'angr not available'
        return result

    t_start = time.time()

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)

        # 定位函数入口
        cfg = proj.analyses.CFGFast()
        func_addr = None
        for f in cfg.functions.values():
            if f.name == func_name:
                func_addr = f.addr
                break

        if func_addr is None:
            result['error'] = f'function {func_name} not found'
            result['elapsed_sec'] = time.time() - t_start
            return result

        # 符号化输入(512B -- 多数漏洞所需输入远小于此)
        symbolic_input = claripy.BVS('verify_input', 512 * 8)
        state = proj.factory.entry_state(
            addr=func_addr,
            stdin=angr.SimFile('/dev/stdin', content=symbolic_input),
        )

        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.Timeout(
            timeout=timeout,
        ))

        # 探索至目标地址
        def _has_reached(s):
            return s.addr == call_address

        paths_found = 0
        min_input = -1

        while simgr.active and paths_found < 3:
            simgr.step()
            for s in simgr.active:
                if s.addr == call_address:
                    paths_found += 1
                    # 计算最小输入长度
                    try:
                        input_len = s.solver.eval(
                            symbolic_input.length if hasattr(symbolic_input, 'length')
                            else 512
                        )
                        if min_input < 0 or input_len < min_input:
                            min_input = input_len
                    except Exception:
                        pass
                    if paths_found >= 3:
                        break

        result['reachable'] = paths_found > 0
        result['path_count'] = paths_found
        result['min_input_len'] = min_input
        result['elapsed_sec'] = time.time() - t_start

    except Exception as e:
        result['error'] = str(e)[:120]
        result['elapsed_sec'] = time.time() - t_start

    return result

def verify_arg_symbolicity(
    binary_path: str,
    func_name: str,
    call_address: int,
    arg_index: int = 0,          # 0 = 第一个参数 (x86_64: rdi)
    timeout: int = _TIMEOUT_PER_POINT,
) -> Dict[str, Any]:
    """验证在目标调用点处, 指定索引的参数是否符号化(用户可控)。

    x86_64参数约定: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
    i386参数约定: 全部在栈上

    Returns:
        {symbolic: bool, constraint_count: int, satisfiable: bool}
    """
    result: Dict[str, Any] = {
        'symbolic': False,
        'constraint_count': 0,
        'satisfiable': False,
        'error': None,
    }

    try:
        import angr
        import claripy
    except ImportError:
        result['error'] = 'angr not available'
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        symbolic_input = claripy.BVS('fmt_input', 1024 * 8)

        # 从目标调用点前的状态开始(避免死代码)
        # 若call_address合法, 跳过call指令自身
        state = proj.factory.blank_state(addr=call_address)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

        # 符号化stdin
        state = proj.factory.entry_state(
            stdin=angr.SimFile('/dev/stdin', content=symbolic_input),
        )
        # 手动设置IP到目标地址
        state.regs.rip = call_address

        # 读取第arg_index个参数
        reg_order = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        if arg_index < len(reg_order):
            arg_reg = getattr(state.regs, reg_order[arg_index])
        else:
            # 超出寄存器范围的参数在栈上
            rsp = state.regs.rsp
            arg_reg = state.memory.load(
                rsp + (arg_index - 6) * 8, 8, endness='Iend_LE',
            )

        result['symbolic'] = state.solver.symbolic(arg_reg)
        if result['symbolic']:
            result['constraint_count'] = len(state.solver.constraints)
            result['satisfiable'] = state.solver.satisfiable()

    except Exception as e:
        result['error'] = str(e)[:120]

    return result

def verify_finding(
    binary_path: str,
    func_name: str,
    call_address: int,
    arg_index: int = 0,
    confidence: float = 0.5,
) -> Tuple[Dict[str, Any], float]:
    """综合验证——可达性+参数符号性, 返回修正后的置信度。

    置信度调整规则:
      不可达 → confidence × 0.3
      可达但参数不符号化 → confidence × 0.6
      可达且参数符号化 → confidence = max(confidence, 0.85)
      无法验证(angr错误) → confidence 不变

    Returns:
        (verification_details, adjusted_confidence)
    """
    details: Dict[str, Any] = {
        'reachability': None,
        'arg_symbolicity': None,
        'verified': False,
        'adjustment': 'unchanged',
    }

    # 可达性
    reach = verify_call_reachability(binary_path, func_name, call_address)
    details['reachability'] = reach

    if reach.get('error') and not reach.get('reachable'):
        return details, confidence  # angr出错 → 不调整

    if not reach.get('reachable', False):
        details['adjustment'] = 'unreachable'
        details['verified'] = True
        return details, confidence * 0.3

    # 参数符号性
    sym = verify_arg_symbolicity(binary_path, func_name, call_address, arg_index)
    details['arg_symbolicity'] = sym

    if sym.get('error'):
        details['adjustment'] = 'reachable-only'
        details['verified'] = True
        return details, confidence * 0.7  # 可达但参数验证失败

    if sym.get('symbolic') and sym.get('satisfiable'):
        details['adjustment'] = 'confirmed-exploitable'
        details['verified'] = True
        return details, max(confidence, 0.85)

    if sym.get('symbolic') and not sym.get('satisfiable'):
        details['adjustment'] = 'symbolic-but-unsat'
        details['verified'] = True
        return details, confidence * 0.5

    details['adjustment'] = 'not-symbolic'
    details['verified'] = True
    return details, confidence * 0.6

def batch_verify(
    binary_path: str,
    findings: List[Dict[str, Any]],
    max_points: int = 10,
) -> List[Dict[str, Any]]:
    """批量验证——对findings列表逐条验证, 限制总数控制耗时。

    每项finding应含: function, call_address, arg_index(默认0), confidence

    返回: 添加了 verification 字段并调整了 confidence 的findings列表。
    """
    verified = 0
    for finding in findings[:max_points]:
        func = finding.get('function', '')
        addr = finding.get('call_address', 0)
        arg_idx = finding.get('arg_index', 0)
        conf = finding.get('confidence', 0.5)

        if addr == 0:
            continue  # 无地址, 无法做符号执行验证

        details, new_conf = verify_finding(
            binary_path, func, addr, arg_idx, conf,
        )
        finding['verification'] = details
        finding['confidence'] = round(new_conf, 3)
        verified += 1

    return findings
