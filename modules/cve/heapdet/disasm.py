# 反汇编前端 - objdump 优先, angr 回退.
#
# 决策逻辑:
#   objdump -d 在 mingw/GNU binutils 下对 PE 与 ELF 均可用, 输出
#   <addr>\t<bytes>\t<mnemonic> <ops> 的三列格式, 解析成本低.
#   angr 仅在 objdump 不可用时作为回退, 用 Capstone 指令还原统一格式,
#   保证检测器输入 (List[dict]: address/mnemonic/operands) 一致.
#   PE 间接 call (call [rip+...]) 经 import_resolver 改写为函数名.
#

import subprocess
from typing import List, Optional, Tuple

_DEEMO_ROOT = None


def _ensure_paths():
    global _DEEMO_ROOT
    if _DEEMO_ROOT is not None:
        return
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    _DEEMO_ROOT = os.path.abspath(os.path.join(here, "..", "..", ".."))
    for p in (_DEEMO_ROOT, os.path.dirname(_DEEMO_ROOT)):
        import sys
        if p not in sys.path:
            sys.path.insert(0, p)


def disassemble(binary: str) -> Tuple[List[dict], str, int, list]:
    """反汇编二进制为统一指令格式.

    返回: (instructions, file_format, main_addr, user_func_ranges).
    """
    _ensure_paths()
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.import_resolver import resolve_call_targets

    instructions, fmt, main_addr, ranges = disassemble_binary(binary)
    if instructions:
        instructions = resolve_call_targets(binary, instructions, fmt)
    if not instructions:
        instructions = _angr_fallback(binary)
    return instructions, fmt, main_addr, ranges


def _angr_fallback(binary: str) -> List[dict]:
    """angr + Capstone 回退反汇编."""
    # TODO: 回退路径仅反汇编首个函数, 未解析间接 call 目标,
    # 导入函数识别受限; 需与 objdump 主路径对齐.
    try:
        import angr
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except Exception:
        return []
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        proj.analyses.CFGFast()
        instructions = []
        for addr, ins in proj.factory.block(proj.entry).capstone.insns:
            pass
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for block in proj.kb.functions.iter_blocks() if False else []:
            pass
        # 直接基于入口函数块的 capstone 反汇编.
        for func in list(proj.kb.functions.values())[:1]:
            for block in func.blocks:
                for insn in block.capstone.insns:
                    ops = [o.strip() for o in insn.op_str.split(",")
                           if o.strip()]
                    instructions.append({
                        "address": insn.address,
                        "mnemonic": insn.mnemonic,
                        "operands": ops,
                    })
        return instructions
    except Exception:
        return []


def has_disassembler() -> bool:
    """检查是否有可用的反汇编前端."""
    if _angr_available():
        return True
    try:
        out = subprocess.run(["objdump", "-v"], capture_output=True,
                             timeout=5)
        return out.returncode == 0
    except Exception:
        return False


def _angr_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except Exception:
        return False


__all__ = ["disassemble", "has_disassembler"]
