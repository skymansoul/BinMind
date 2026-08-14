"""
污点引导的约束精简 — 仅对影响目标分支的输入字节执行符号化。
核心算法: 动态污点标记输入字节 → 分支处检查污点来源 → 仅符号化
受污染的偏移, 符号变量数从 O(N) 降到 O(K), K 通常为 4-32 字节。
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

def identify_tainted_offsets(
    binary_path: str,
    input_bytes: bytes,
    target_branch_addr: int,
    max_input_len: int = 4096,
) -> Set[int]:
    """
    识别输入中影响目标分支的字节偏移。

    执行污点追踪, 标记输入的每个字节为独立污点源, 在目标分支地址处
    检查 eflags/条件寄存器受哪些字节影响。
    参数: binary_path 目标二进制, input_bytes 具体输入,
    target_branch_addr 目标条件分支地址, max_input_len 输入最大长度。
    返回 {offset} 影响目标分支的输入字节偏移集合,
    空集合表示无法确定 (回退为全符号化)。
    """
    tainted: Set[int] = set()

    try:
        import angr
    except ImportError:
        _log.debug("angr unavailable for taint debloating")
        return tainted

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)

        # 将输入字节逐一标记为独立符号变量
        input_len = min(len(input_bytes), max_input_len)
        symbolic_vars = {}
        state = proj.factory.entry_state()

        for i in range(input_len):
            bv_name = f"taint_byte_{i}"
            sym_byte = state.solver.BVS(bv_name, 8)
            symbolic_vars[i] = sym_byte
            state.memory.store(state.posix.stdin.addr + i, sym_byte)

        stdin_base = state.posix.stdin.addr

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=target_branch_addr, num_find=1)

        if not simgr.found:
            _log.debug("Target branch 0x%x unreachable with given input",
                       target_branch_addr)
            return tainted

        branch_state = simgr.found[0]

        # 检查分支条件 (eflags) 的符号依赖
        try:
            eflags = branch_state.regs.eflags
            vars_in_eflags = _extract_symbolic_vars(eflags)
            for var_name in vars_in_eflags:
                if var_name.startswith("taint_byte_"):
                    offset = int(var_name.split("_")[-1])
                    tainted.add(offset)
        except Exception:
            pass

        # 检查最后一条指令的操作数（cmp/test 的结果影响分支）
        try:
            last_insn = branch_state.block().capstone.insns[-1]
            for op in last_insn.operands:
                if hasattr(op, 'reg'):
                    reg_val = getattr(branch_state.regs, op.reg.name.lower(), None)
                    if reg_val is not None:
                        for var_name in _extract_symbolic_vars(reg_val):
                            if var_name.startswith("taint_byte_"):
                                offset = int(var_name.split("_")[-1])
                                tainted.add(offset)
        except Exception:
            pass

        _log.debug("Taint debloat: %d/%d bytes tainted for branch 0x%x",
                   len(tainted), input_len, target_branch_addr)

    except Exception as e:
        _log.debug("Taint debloating failed: %s", e)

    return tainted

def _extract_symbolic_vars(expr) -> Set[str]:
    """从符号表达式中递归提取所有符号变量名。"""
    try:
        if hasattr(expr, 'variables'):
            return set(expr.variables)
        if hasattr(expr, 'get_variables'):
            return set(v.get_variables(expr))
    except Exception:
        pass
    return set()

def build_debloated_input(
    input_bytes: bytes,
    tainted_offsets: Set[int],
) -> Tuple[List[int], List[int]]:
    """
    构建精简后的符号化方案。

    将输入分为两类偏移: symbol_offsets 为需符号化的字节位置,
    concret_offsets 为保持具体值的字节位置。符号执行时仅对前者
    创建符号变量, 后者使用原始输入的具体值。
    返回 (symbol_offsets, concrete_offsets) 两个偏移列表。
    """
    total = len(input_bytes)
    sym_offs = sorted(tainted_offsets)
    conc_offs = [i for i in range(total) if i not in tainted_offsets]
    return sym_offs, conc_offs

def estimate_debloat_ratio(
    input_len: int,
    tainted_count: int,
) -> float:
    """
    估算约束精简比例。

    原始约束变量数 = 输入字节数 × 8 (每个bit一个符号变量)
    精简后 = tainted字节数 × 8
    精简比例 = 1 - (tainted / total)

    返回值在 [0, 1]，越接近 1 说明精简效果越好。
    若 tainted 为空（无法确定），返回 0.0。
    """
    if input_len <= 0 or tainted_count <= 0:
        return 0.0
    return round(1.0 - tainted_count / input_len, 3)

def debloat_symbolic_state(
    state,
    input_bytes: bytes,
    tainted_offsets: Set[int],
) -> Any:
    """
    在 angr state 上应用部分符号化。

    将 state 的 stdin 缓冲区中非污点字节替换为具体值，
    仅保留污点字节的符号变量。直接修改 state。

    边界条件:
      - tainted_offsets 为空 → 全符号化（回退到默认行为）
      - 输入字节全部被污点 → 等价于全符号化（无性能损失）
    """
    if not tainted_offsets:
        return state

    try:
        stdin_addr = state.posix.stdin.addr
    except Exception:
        return state

    for i in range(len(input_bytes)):
        if i not in tainted_offsets:
            # 替换为具体值 → 约束求解器不再跟踪此字节
            state.memory.store(
                stdin_addr + i,
                state.solver.BVV(input_bytes[i], 8),
            )

    return state
