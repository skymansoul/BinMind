# 全局数组索引寻址辅助: 从 indexed store/load 回溯到 lea [rip+global].

import re
from typing import Dict, Optional

from .disasm_util import norm_reg, resolve_rip_relative


_BASE_REGS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
              "r8", "r9", "r10", "r11", "r12", "r13")


def resolve_global_array_base(operand: str,
                              ins_snapshot: Dict[int, dict],
                              current_addr: int) -> Optional[int]:
    """回溯 indexed store 目标的 base 寄存器到 lea [rip+global].

    模式: lea rax,[rip+g_items]; lea rdx,[idx*8]; mov [rdx+rax], rcx
    对每个 base 寄存器只取最近一条 lea, resolve 失败则换下一个.
    """
    op_s = operand.strip().lower()
    if "[" not in op_s: return None
    inner = op_s[op_s.find("[")+1:op_s.rfind("]")]
    regs = re.findall(r'[a-z]+', inner)
    base_regs = [r for r in regs if r in _BASE_REGS]
    for br in base_regs:
        for a in sorted(ins_snapshot.keys(), reverse=True):
            if a >= current_addr: continue
            past = ins_snapshot[a]
            pm = past.get("mnemonic", "").lower()
            if pm == "ret": break
            if pm != "lea": continue
            po = past.get("operands", [])
            if len(po) < 2: continue
            if norm_reg(po[0].strip()) != br: continue
            ga = resolve_rip_relative(past, po[1].strip(), a)
            if ga is not None: return ga
            break
    return None


def match_global_array_elem(ins: dict, src_raw: str,
                            addr: int,
                            addr_to_obj: Dict[int, int]) -> Optional[int]:
    """RIP相对加载全局数组元素 [rip+global_base+offset].

    若 _addr_to_obj 中有同基地址的映射, 视为同一对象的数组元素.
    """
    abs_addr = resolve_rip_relative(ins, src_raw, addr)
    if abs_addr is None: return None
    for gbase, oid in addr_to_obj.items():
        if gbase <= abs_addr < gbase + 64:
            return oid
    return None


def extract_base_reg(operand: str) -> Optional[str]:
    """从 [reg] 或 [reg+offset] 提取唯一的 base 寄存器.

    仅当内存操作数含且仅含一个寄存器时返回该寄存器.
    """
    op_s = operand.strip().lower()
    if "[" not in op_s or "]" not in op_s: return None
    inner = op_s[op_s.find("[")+1:op_s.rfind("]")]
    regs = re.findall(r'[a-z]+', inner)
    base_regs = [r for r in regs if r in _BASE_REGS]
    if len(base_regs) == 1:
        return base_regs[0]
    return None


__all__ = ["resolve_global_array_base", "match_global_array_elem",
           "extract_base_reg"]
