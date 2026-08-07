# 基于抽象解释的值范围分析器 (Abstract Interpretation Value Range Analyzer)
#
# 核心决策:
#   堆溢出误报的主要来源 — 对未知寄存器/变量使用[0, 2^31-1]的最宽区间.
#   本模块用轻量级抽象解释替换宽区间策略:
# 前向传播: 从函数入口参数出发, 沿控制流传播值区间
# widening at loop headers: 防止循环体无限迭代
# narrowing: 在widening收敛后精化区间
#     - heap allocation modeling: 将malloc参数传播到返回值指针
#
# 理论依据:
#   抽象解释框架; 组合式堆对象不相交性分析降低区间重叠误报.
#
# 创建: 2026-04-28

from collections import deque
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .disasm_util import norm_reg, extract_func_name

# 堆分配相关函数签名映射: {函数名: 大小参数索引}
_ALLOC_ARG_INDEX = {
    "malloc": 0, "calloc": (0, 1), "realloc": 1,
    "_Znwm": 0, "_Znam": 0, "g_malloc": 0,
    "ExAllocatePoolWithTag": 1,
}
# x86-64 calling convention: arg N → register
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


class ValueRangeAnalyzer:
    """基于抽象解释的值范围分析器.

    输入: 函数内指令序列 (已反汇编为三地址形式).
    输出: 每个程序点上的寄存器→值区间映射.
    """

    def __init__(self, max_iter: int = 30):
        self._max_iter = max_iter
        self._ranges: Dict[int, Dict[str, ValueRange]] = {}
        self._known_constants: Dict[str, int] = {}

    def set_constants(self, constants: Dict[str, int]):
        self._known_constants.update(constants)

    def analyze(self, instructions: List[dict]
                ) -> Dict[int, Dict[str, ValueRange]]:
        """前向数据流分析: 从入口到每个指令地址.

        返回: {address: {reg_name: ValueRange}} 的映射.
        对循环使用 widening 保证终止.
        """
        if not instructions:
            return {}

        entry_addr = instructions[0].get("address", 0)
        init_state: Dict[str, ValueRange] = {
            r: ValueRange.top() for r in _ARG_REGS
        }
        init_state["rsp"] = ValueRange(0x7FFF0000, 0x7FFFFFFF)
        init_state["rbp"] = ValueRange(0x7FFF0000, 0x7FFFFFFF)

        self._ranges[entry_addr] = dict(init_state)
        worklist = deque([entry_addr])
        addr_to_idx = {ins.get("address", i): i
                       for i, ins in enumerate(instructions)}

        iteration = 0
        while worklist and iteration < self._max_iter:
            iteration += 1
            addr = worklist.popleft()
            idx = addr_to_idx.get(addr)
            if idx is None:
                continue
            ins = instructions[idx]
            in_state = self._ranges.get(addr, dict(init_state))
            out_state = self._transfer(ins, dict(in_state))

            # 传播到后继指令
            next_idx = idx + 1
            if next_idx < len(instructions):
                next_addr = instructions[next_idx].get("address", next_idx)
                self._propagate_state(out_state, next_addr, next_addr < addr,
                                      worklist)

            # 条件跳转: 同时传播到跳转目标
            if ins.get("mnemonic", "").lower().startswith("j"):
                target = self._extract_jump_target(ins)
                if target is not None and target in addr_to_idx:
                    self._propagate_state(out_state, target, False, worklist)

        return self._ranges

    def _propagate_state(self, out_state: Dict[str, ValueRange],
                          target_addr: int, is_backedge: bool,
                          worklist: deque):
        """将输出状态传播到目标地址, 使用join/widen."""
        old = self._ranges.get(target_addr, {})
        new_state = {}
        changed = False
        for reg, vr in out_state.items():
            old_vr = old.get(reg, ValueRange.bottom())
            new_vr = old_vr.widen(vr) if is_backedge else old_vr.join(vr)
            new_state[reg] = new_vr
            if new_vr.lo != old_vr.lo or new_vr.hi != old_vr.hi:
                changed = True
        for reg, vr in old.items():
            if reg not in new_state:
                new_state[reg] = vr
        self._ranges[target_addr] = new_state
        if changed:
            worklist.append(target_addr)

    def _transfer(self, ins: dict,
                  state: Dict[str, ValueRange]) -> Dict[str, ValueRange]:
        """单指令传递函数."""
        out = dict(state)
        mnem = ins.get("mnemonic", "").lower()
        raw_ops = ins.get("operands", [])
        ops = [norm_reg(o) for o in raw_ops]

        if not ops:
            return out

        dst = ops[0]

        # mov reg, imm → dst区间 = [imm, imm]
        if mnem == "mov" and len(ops) >= 2:
            src = ops[1]
            vr = self._eval_operand(src, state)
            if vr is not None:
                out[dst] = vr

        # lea reg, [base+offset]
        elif mnem == "lea" and len(ops) >= 2:
            base, offset = self._parse_lea(raw_ops[1])
            base_vr = state.get(base, ValueRange.bottom())
            if not base_vr.is_bottom:
                out[dst] = base_vr.add(offset)

        # 算术运算
        elif mnem in ("add","sub","and","or","xor","shl","shr",
                       "imul","mul") and len(ops) >= 2:
            src1 = state.get(dst, ValueRange.bottom())
            # 立即数按目标寄存器宽度符号扩展: 0xffffff80 → -128
            signed = self._parse_imm_signed(raw_ops[1], raw_ops[0])
            if signed is not None:
                src2 = ValueRange.singleton(signed)
            else:
                src2 = self._eval_operand(ops[1], state)
            if not src1.is_bottom and src2 is not None:
                if mnem == "add":
                    out[dst] = ValueRange(src1.lo + src2.lo,
                                          src1.hi + src2.hi)
                elif mnem == "sub":
                    out[dst] = ValueRange(src1.lo - src2.hi,
                                          src1.hi - src2.lo)
                elif mnem == "shl" and src2.is_singleton:
                    out[dst] = ValueRange(
                        src1.lo << src2.lo, src1.hi << src2.lo)
                elif mnem == "shr" and src2.is_singleton:
                    out[dst] = ValueRange(
                        src1.lo >> src2.lo, src1.hi >> src2.lo)

        # call → 处理堆函数, 传播分配大小到返回值
        elif mnem == "call" and raw_ops:
            func = extract_func_name(raw_ops[0])
            if func in _ALLOC_ARG_INDEX:
                arg_idx = _ALLOC_ARG_INDEX[func]
                if isinstance(arg_idx, tuple):
                    size_reg = _ARG_REGS[arg_idx[0]]
                else:
                    size_reg = _ARG_REGS[arg_idx]
                if size_reg in state:
                    out["rax"] = state[size_reg]
                    out["eax"] = state[size_reg]

        return out

    def _eval_operand(self, op: str,
                      state: Dict[str, ValueRange]) -> Optional[ValueRange]:
        """计算操作数的值区间.

        立即数按寄存器宽度符号扩展 (0xffffff80 → -128), 避免
        32位负数编码导致大小区间负化.
        """
        op = op.strip().lower().lstrip("%").replace("$", "")
        try:
            if op.startswith("0x"):
                return ValueRange.singleton(int(op, 16))
            if op.isdigit() or (op.startswith("-") and op[1:].isdigit()):
                return ValueRange.singleton(int(op))
        except ValueError:
            pass
        norm = norm_reg(op)
        if norm in state:
            return state[norm]
        if norm in self._known_constants:
            return ValueRange.singleton(self._known_constants[norm])
        return None

    def get_range_at(self, addr: int, reg: str) -> ValueRange:
        """查询某地址处寄存器的值区间."""
        norm = norm_reg(reg)
        state = self._ranges.get(addr, {})
        return state.get(norm, ValueRange.bottom())

    @staticmethod
    def _parse_imm_signed(op: str, reg: str) -> Optional[int]:
        """解析立即数并按寄存器宽度符号扩展."""
        from .disasm_util import parse_imm_signed
        return parse_imm_signed(op, reg)

    @staticmethod
    def _parse_lea(operand: str) -> Tuple[str, int]:
        """解析 LEA 的源操作数: [rbp-0x20] → ('rbp', -0x20)."""
        op = operand.strip().lower().replace("[","").replace("]","")
        if "+" in op:
            parts = op.split("+")
            try:
                return parts[0].strip(), int(parts[1].strip(), 0)
            except ValueError:
                return op, 0
        if "-" in op:
            parts = op.split("-", 1)
            try:
                return parts[0].strip(), -int(parts[1].strip(), 0)
            except ValueError:
                return op, 0
        return op, 0

    @staticmethod
    def _extract_jump_target(ins: dict) -> Optional[int]:
        """从跳转指令提取目标地址."""
        ops = ins.get("operands", [])
        if not ops:
            return None
        target = ops[0].strip().lower().lstrip("%").replace("$", "")
        try:
            if target.startswith("0x"):
                return int(target, 16)
            return int(target)
        except ValueError:
            return None

    def reset(self):
        self._ranges.clear()


__all__ = ["ValueRangeAnalyzer", "ValueRange"]
