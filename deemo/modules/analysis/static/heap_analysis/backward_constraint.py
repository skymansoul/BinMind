# 后向约束窄化器 - 在危险调用点逆向查找条件分支, 窄化参数区间.
# 当 absint 引擎无法静态确定 memcpy 的 size 参数时, 逆向扫描 cmp+jcc
# 分支条件, 提取对 size 参数的上界约束.

from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from ..path_condition import CondOp


# jcc 助记符 → 条件操作符 (CondOp)
_JCC_COND = {
    "je": CondOp.EQ, "jz": CondOp.EQ,
    "jne": CondOp.NE, "jnz": CondOp.NE,
    "ja": CondOp.ABOVE, "jae": CondOp.ABOVE_EQ, "jnbe": CondOp.ABOVE,
    "jb": CondOp.BELOW, "jbe": CondOp.BELOW_EQ, "jnae": CondOp.BELOW,
    "jg": CondOp.GT, "jge": CondOp.GE, "jnle": CondOp.GT,
    "jl": CondOp.LT, "jle": CondOp.LE, "jnge": CondOp.LT,
    "jmp": None,  # 无条件跳转, 不产生约束
}

# 32→64 位寄存器归一化
_W32_TO_W64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
    "r10d": "r10", "r11d": "r11", "r12d": "r12", "r13d": "r13",
    "r14d": "r14", "r15d": "r15",
}


def _norm(r: str) -> str:
    """归一化寄存器名 → 64bit."""
    r = r.strip().lower()
    return _W32_TO_W64.get(r, r)

def _try_int(s: str) -> Optional[int]:
    """安全解析整数."""
    s = s.strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.lstrip("-").isdigit():
            return int(s)
    except ValueError:
        pass
    return None

def _extract_jmp_target(ins: ParsedInstruction) -> Optional[int]:
    """提取跳转目标地址, 处理 113d <main+0x3d> 格式."""
    if not ins.operands:
        return None
    op = ins.operands[0].strip()
    # 取空格前的纯地址部分: "113d <main+0x3d>" → "113d"
    addr_part = op.split()[0] if op else ""
    # objdump 跳转目标为十六进制地址 - 先按 hex 解析
    try:
        return int(addr_part, 16)
    except ValueError:
        return _try_int(addr_part)


class BackwardConstraintNarrower:
    """逆向约束窄化器 - 在危险调用点查找 bounds check 条件.

    使用方式:
      narrower = BackwardConstraintNarrower()
      lo, hi = narrower.narrow(insns, call_idx, "r8")
    """

    def narrow(self, insns: List[ParsedInstruction],
               call_idx: int, size_reg: str) -> Tuple[int, int]:
        """逆向窄化 size_reg 在 call_idx 前的值区间.

        返回 (min_val, max_val), 其中 min_val ≥ 0, max_val ≤ 2^31-1.
        若无有效约束, 返回 (0, 2**31 - 1).
        """
        target_reg = _norm(size_reg)
        best_hi = 2**31 - 1
        best_lo = 0

        # 逆向扫描: 在 call_idx 前最多 30 条指令
        start = max(0, call_idx - 30)
        window = insns[start:call_idx]

        i = len(window) - 1
        while i >= 0:
            ins = window[i]
            mn = ins.mnemonic.lower()
            # 检测 cmp+jcc 对: 从 jcc 往回找 cmp
            if mn in _JCC_COND and _JCC_COND[mn] is not None:
                jcc_idx = i + start
                jcc_ins = ins
                jcc_target = _extract_jmp_target(jcc_ins)

                # 在 jcc 前找 cmp
                cmp_ins = None
                for j in range(i - 1, max(-1, i - 6), -1):
                    if j < 0:
                        break
                    if window[j].mnemonic in ("cmp", "test"):
                        cmp_ins = window[j]
                        break

                if cmp_ins is None or len(cmp_ins.operands) < 2:
                    i -= 1
                    continue

                # 检查 cmp 的操作数是否涉及目标寄存器
                op0_norm = _norm(cmp_ins.operands[0])
                op1_norm = _norm(cmp_ins.operands[1])
                imm_val = _try_int(cmp_ins.operands[1])

                if op0_norm != target_reg or imm_val is None:
                    i -= 1
                    continue

                # 判断哪条路径通向调用点
                # jcc 的下一条指令 = fallthrough (条件为 false)
                fallthrough_addr = None
                for k in range(jcc_idx + 1, min(jcc_idx + 3, len(insns))):
                    ft = insns[k]
                    if ft.address > jcc_ins.address:
                        fallthrough_addr = ft.address
                        break

                # 判断 call 在 taken 还是 fallthrough 路径
                call_addr = insns[call_idx].address if call_idx < len(insns) else 0
                on_taken = (jcc_target is not None
                            and fallthrough_addr is not None
                            and abs(call_addr - jcc_target)
                                < abs(call_addr - fallthrough_addr))

                cond = _JCC_COND[mn]

                # 应用约束
                if on_taken:
                    # 跳转被采纳 → 条件为 true
                    lo, hi = _apply_cond(cond, True, imm_val)
                else:
                    # fallthrough → 条件为 false
                    lo, hi = _apply_cond(cond, False, imm_val)

                if hi is not None and hi < best_hi:
                    best_hi = hi
                if lo is not None and lo > best_lo:
                    best_lo = lo

            i -= 1

        return (best_lo, best_hi)


def _apply_cond(cond: CondOp, is_true: bool, imm: int) -> Tuple[Optional[int], Optional[int]]:
    """根据条件操作符和真假值, 返回 (lo, hi) 约束.

    条件为 true: cmp reg, imm; jcc → reg 满足 cond(reg, imm)
    条件为 false: 未跳转 → 对偶条件

    例如: cmp r8, 256; ja .skip
      jcc=ja (ABOVE/GT_U), is_true=False (r8 未 > 256)
      → r8 <= 256 → hi=256
    """
    if not is_true:
        cond = _negate_cond(cond)

    if cond == CondOp.EQ:
        return (imm, imm)
    elif cond == CondOp.NE:
        return (None, None)
    elif cond in (CondOp.LT, CondOp.BELOW):
        return (None, imm - 1)
    elif cond in (CondOp.LE, CondOp.BELOW_EQ):
        return (None, imm)
    elif cond in (CondOp.GT, CondOp.ABOVE):
        return (imm + 1, None)
    elif cond in (CondOp.GE, CondOp.ABOVE_EQ):
        return (imm, None)
    return (None, None)


def _negate_cond(cond: CondOp) -> CondOp:
    """取反条件."""
    _map = {
        CondOp.EQ: CondOp.NE, CondOp.NE: CondOp.EQ,
        CondOp.LT: CondOp.GE, CondOp.GE: CondOp.LT,
        CondOp.LE: CondOp.GT, CondOp.GT: CondOp.LE,
        CondOp.BELOW: CondOp.ABOVE_EQ, CondOp.ABOVE_EQ: CondOp.BELOW,
        CondOp.ABOVE: CondOp.BELOW_EQ, CondOp.BELOW_EQ: CondOp.ABOVE,
    }
    return _map.get(cond, cond)


# smoke test
def _check():
    from .instruction_parser import InstructionParser

    # 模式: cmp r8, 256; ja .skip; mov rcx, buf; mov r8, rcx; call memcpy
    # ja 未跳转 → r8 <= 256
    asm = """
    1100:       41 81 f8 00 01 00 00    cmp    r8d,0x100
    1107:       0f 87 30 00 00 00       ja     113d <main+0x3d>
    110d:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
    1111:       48 89 c1                mov    rcx,rax
    1114:       e8 e7 fe ff ff          call   1000 <memcpy>
    """
    insns = InstructionParser.parse(asm)
    # 找到 memcpy 的索引
    call_idx = next(i for i, ins in enumerate(insns) if ins.mnemonic == "call")

    narrower = BackwardConstraintNarrower()
    lo, hi = narrower.narrow(insns, call_idx, "r8")

    assert hi == 256, f"expected hi=256 (r8 bounded to <=256), got hi={hi}"
    assert lo == 0, f"expected lo=0, got lo={lo}"
    print(f"[OK] backward_constraint: r8 ∈ [{lo}, {hi}]")


if __name__ == "__main__":
    _check()
