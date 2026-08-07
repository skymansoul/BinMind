"""
栈溢出符号执行分析 —— 基于angr计算输入缓冲区到返回地址的偏移。

"""


import logging
from typing import Any, Dict

_log = logging.getLogger(__name__)


def symbolic_overflow_analysis(
    binary_path: str,
    func_name: str,
) -> Dict[str, Any]:
    """
    通过 angr 符号执行分析栈溢出。

    对目标函数进行符号执行，追踪符号化输入在栈上的位置，
    计算到返回地址的偏移。若 angr 不可用则返回空结果。
    """
    result: Dict[str, Any] = {'overflowable': False, 'padding': 0, 'insights': []}

    try:
        import angr
        import claripy
    except ImportError:
        _log.debug("angr unavailable, skipping symbolic overflow analysis")
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        func_addr = None
        cfg = proj.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name == func_name:
                func_addr = f.addr
                break

        if func_addr is None:
            _log.debug("Function %s not found in CFG", func_name)
            return result

        # 符号化 STDIN 输入
        symbolic_input = claripy.BVS('input', 2048 * 8)
        state = proj.factory.entry_state(
            addr=func_addr,
            stdin=angr.SimFile('/dev/stdin', content=symbolic_input),
        )

        # 探索直到遇到返回指令
        simgr = proj.factory.simulation_manager(state)
        simgr.run(until=lambda s: len(s.active) > 50 or len(s.deadended) > 5)

        for path_state in simgr.deadended:
            if path_state.regs.rsp.symbolic:
                continue
            try:
                rsp_val = path_state.solver.eval(path_state.regs.rsp)
                # 读取栈上保存的返回地址
                ret_addr_bytes = path_state.memory.load(rsp_val, 8, endness='Iend_LE')
                ret_addr_val = path_state.solver.eval(ret_addr_bytes)

                # 如果返回地址包含符号输入，说明可能溢出
                if path_state.solver.symbolic(ret_addr_bytes):
                    # 计算最小偏移
                    min_offset = compute_padding_from_state(
                        path_state, symbolic_input, rsp_val
                    )
                    if min_offset > 0:
                        result['overflowable'] = True
                        result['padding'] = min_offset
                        result['insights'].append(
                            f"Symbolic execution confirms overflow at offset {min_offset}"
                        )
                        break
            except (angr.SimUnsatError, angr.SimError) as e:
                _log.debug("Symbolic path dead: %s", e)
                continue

    except Exception as e:
        _log.debug("Symbolic overflow analysis error: %s", e)

    return result


def compute_padding_from_state(state, symbolic_input, rsp_val: int) -> int:
    """从符号执行状态中计算输入到返回地址的偏移量。"""
    try:
        # 搜索输入缓冲区在栈上的起始地址
        for offset in range(0, 4096, 8):
            mem_at = state.memory.load(rsp_val - offset, 8, endness='Iend_LE')
            if symbolic_input.variables & mem_at.variables:
                # 符号输入第0字节与 rsp-offset 处符号重叠
                # 偏移量 = offset - 8 (跳过保存的 rbp) + 8 (对齐)
                # 简化: offset 即是 padding
                return max(0, offset + 8)
    except Exception:
        pass
    return 0
