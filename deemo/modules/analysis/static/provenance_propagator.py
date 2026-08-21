# 来源传播器 (Provenance Propagator) - PcWBI来源约束写界推断.
#
# 决策逻辑:
#   逐指令前向传播每个寄存器/栈槽的来源值. 传播规则与符号传播器互补:
#   符号传播器只关心"线性表达式", 来源传播器额外维护"该表达式从何而来",
#   并在 call 边界处理三类信号:
#     - 外部输入函数 (read/recv/argv) → 返回值来源为 INPUT_TAINTED
#     - 堆分配函数 (malloc/calloc)  → 返回值来源为 ALLOC_LINKED,
#       且其 size 参数来源被绑定为分配来源
#     - cmp/test + jcc 守卫          → 被比较对象来源升级为 GUARDED
#   传播结果是 {address: {reg: ProvValue}} 的映射, 供写界推断器在
#   危险调用点查询写入大小操作数的来源.
#   指令级规则 (mov/lea/算术/守卫) 位于 _prov_insn_handlers.
#

from typing import Dict, List, Optional, Tuple

from .disasm_util import norm_reg, extract_func_name
from .provenance_domain import ProvClass, ProvValue
from .sym_size_correlator import SymExpr
from ._prov_insn_handlers import ProvInsnHandlerMixin

_TAINT_FUNCS = {"read", "recv", "recvfrom", "recvmsg", "fread", "fgets",
                "gets", "scanf", "__isoc99_scanf", "getenv", "getpwuid",
                "atoi", "atol", "atoll", "strtol", "strtoul",
                "strtoll", "strtoull", "strlen", "strnlen"}
_TAINT_PARAM_SRC = {"main", "winmain", "wmain"}


class ProvenancePropagator(ProvInsnHandlerMixin):
    """指令级来源传播器.

    与 HeapOverflowDetector.analyze_instruction() 并行调用,
    通过 handle_instruction() 维护状态; finalize 阶段用
    get_at(addr, reg) 查询写入大小操作数的来源.
    """

    _ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                    "g_malloc", "g_try_malloc", "ExAllocatePoolWithTag"}

    def __init__(self, arg_regs=None, use_win64_abi: bool = False):
        self._arg_regs = arg_regs or (
            ("rcx", "rdx", "r8", "r9") if use_win64_abi
            else ("rdi", "rsi", "rdx", "rcx", "r8", "r9"))
        self._regs: Dict[str, ProvValue] = {}
        self._stack: Dict[str, ProvValue] = {}
        self._at: Dict[int, Dict[str, ProvValue]] = {}
        self._guarded: Dict[int, Dict[str, int]] = {}
        self._alloc_arg_sources: Dict[int, ProvValue] = {}
        self._instructions: List[dict] = []
        self._taint_counter: int = 0
        self._init_params()

    def _init_params(self):
        for i, reg in enumerate(self._arg_regs):
            self._regs[reg] = ProvValue.param(i)
        self._regs["rax"] = ProvValue.unknown()

    def set_instructions(self, instructions: List[dict]):
        self._instructions = instructions

    def reset(self):
        self._regs.clear()
        self._stack.clear()
        self._at.clear()
        self._guarded.clear()
        self._alloc_arg_sources.clear()
        self._init_params()

    def handle_instruction(self, ins: dict, in_main: bool = False):
        """处理单条指令, 更新来源状态."""
        addr = ins.get("address", 0)
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])

        self._at[addr] = dict(self._regs)

        if not ops:
            return

        if mnem == "call":
            self._handle_call(ops, addr, in_main)
        elif mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            self._handle_mov(ops)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(ops)
        elif mnem in ("add", "sub", "shl", "shr") and len(ops) >= 2:
            self._handle_arith(mnem, ops)
        elif mnem in ("imul", "mul") and len(ops) >= 2:
            self._handle_imul(ops)
        elif mnem.startswith("cmov") and len(ops) >= 2:
            src = self._regs.get(norm_reg(ops[1]))
            if src is not None:
                self._regs[norm_reg(ops[0])] = src
        elif mnem in ("cmp", "test") and len(ops) >= 2:
            self._record_compare(ops)

    def _handle_call(self, ops: List[str], addr: int, in_main: bool):
        func = extract_func_name(ops[0])

        if func in self._ALLOC_FUNCS:
            arg_src = self._alloc_arg_source(func)
            self._alloc_arg_sources[addr] = arg_src
            self._regs["rax"] = ProvValue(
                ProvClass.ALLOC_LINKED,
                note=f"alloc@{addr:x}")
            return

        if func in _TAINT_FUNCS or (in_main and func in _TAINT_PARAM_SRC):
            self._taint_counter += 1
            self._regs["rax"] = ProvValue(
                ProvClass.INPUT_TAINTED,
                expr=SymExpr(var=f"taint_{self._taint_counter}"),
                note=f"input:{func}")
            return

        # 未知调用: 返回值来源无法追踪
        self._regs["rax"] = ProvValue.unknown()

    def _alloc_arg_source(self, func: str) -> ProvValue:
        """提取分配 size 参数寄存器当前的来源值."""
        if func == "realloc":
            idx = 1
        else:
            idx = 0
        reg = self._arg_regs[idx] if idx < len(self._arg_regs) else "rdi"
        return self._regs.get(reg, ProvValue.unknown())

    def mark_call_guard(self, reg: str, upper: Optional[int]):
        """call 边界前由检测器显式注入的守卫信息."""
        cur = self._regs.get(norm_reg(reg))
        if cur is None:
            return
        self._regs[norm_reg(reg)] = ProvValue(
            ProvClass.GUARDED, expr=cur.expr, bound=upper,
            guard_upper=upper, note="guard-injected")

    def get_at(self, addr: int, reg: str) -> Optional[ProvValue]:
        """查询某地址处寄存器的来源值."""
        return self._at.get(addr, {}).get(norm_reg(reg))

    def get_alloc_arg_source(self, alloc_addr: int) -> Optional[ProvValue]:
        """查询分配点 size 参数的来源值."""
        return self._alloc_arg_sources.get(alloc_addr)

    def _handle_mov(self, ops: List[str]):
        dst_raw = ops[0].strip()
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        dst_reg = norm_reg(dst_raw)

        val = self._parse_imm(src_raw)
        if val is not None:
            pv = ProvValue.constant(val)
        elif "[" in src_raw.lower():
            slot = extract_stack_slot(src_raw)
            pv = self._stack.get(slot, ProvValue.unknown()) if slot \
                else ProvValue.unknown()
        else:
            pv = self._regs.get(norm_reg(src_raw), ProvValue.unknown())

        if "[" in dst_raw.lower():
            slot = extract_stack_slot(dst_raw)
            if slot:
                self._stack[slot] = pv
            return
        self._regs[dst_reg] = pv

    def _handle_lea(self, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src = ops[1].strip()
        coeffs, offset = self._parse_lea_terms(src)
        pv = None
        if len(coeffs) == 1:
            reg, c = next(iter(coeffs.items()))
            if reg in self._regs:
                cur = self._regs[reg]
                if cur.expr is not None:
                    expr = cur.expr.scale(c)
                    if offset:
                        expr = expr.add_const(offset)
                    pv = ProvValue(cur.cls, expr=expr, bound=cur.bound,
                                   guard_upper=cur.guard_upper,
                                   note=f"lea {c}*{reg}"
                                   + (f"+{offset}" if offset else ""))
                else:
                    pv = cur
        self._regs[dst_reg] = pv if pv is not None else ProvValue.unknown()

    def _handle_arith(self, mnem: str, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        cur = self._regs.get(dst_reg, ProvValue.unknown())
        imm = self._parse_imm(src_raw)

        if imm is not None:
            if cur.cls == ProvClass.CONSTANT and cur.bound is not None:
                new_bound = cur.bound + imm if mnem == "add" \
                    else cur.bound - imm if mnem == "sub" \
                    else (cur.bound << imm) if mnem == "shl" \
                    else (cur.bound >> imm)
                self._regs[dst_reg] = ProvValue.constant(new_bound)
            else:
                expr = self._shift_expr(cur, mnem, imm)
                self._regs[dst_reg] = ProvValue(cur.cls, expr=expr,
                                                note=f"{mnem} {imm}")
            return

        src = self._regs.get(norm_reg(src_raw), ProvValue.unknown())
        if mnem == "add":
            self._regs[dst_reg] = self._binop_add(cur, src)
        else:
            self._regs[dst_reg] = ProvValue(
                join_class(cur.cls, ProvClass.UNKNOWN), note=f"{mnem} reg")

    def _binop_add(self, a: ProvValue, b: ProvValue) -> ProvValue:
        """add dst, src - 常量平移或同源翻倍 (reg+reg 同源)."""
        if b.cls == ProvClass.CONSTANT and b.bound is not None:
            expr = a.expr.add_const(b.bound) if a.expr is not None else None
            return ProvValue(a.cls, expr=expr, note="add const")
        if (a.expr is not None and b.expr is not None
                and a.expr.var is not None and a.expr.var == b.expr.var):
            expr = SymExpr(a.expr.var, a.expr.coeff + b.expr.coeff,
                           a.expr.const + b.expr.const)
            return ProvValue(a.cls, expr=expr, note="add same-src")
        return ProvValue(join_class(a.cls, b.cls), note="add reg")

    def _shift_expr(self, pv: ProvValue, mnem: str,
                    imm: int) -> Optional[SymExpr]:
        """对来源值应用移位/平移, 生成新的符号表达式."""
        if pv.expr is None:
            return None
        if mnem == "shl":
            return pv.expr.scale(1 << imm)
        if mnem == "shr":
            return None
        if mnem == "add":
            return pv.expr.add_const(imm)
        return pv.expr.add_const(-imm)

    def _handle_imul(self, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        cur = self._regs.get(dst_reg, ProvValue.unknown())
        imm = self._parse_imm(src_raw)
        if imm is not None and cur.expr is not None:
            self._regs[dst_reg] = ProvValue(cur.cls,
                                            expr=cur.expr.scale(imm),
                                            note=f"imul {imm}")
        else:
            # TODO: reg*reg 非立即数乘法暂降级为 UNKNOWN, 可扩展为
            # 双变量线性模型 (与 lea 的寄存器系数表对齐).
            self._regs[dst_reg] = ProvValue(
                join_class(cur.cls, ProvClass.UNKNOWN), note="imul reg")

    def _record_compare(self, ops: List[str]):
        """记录 cmp/test - 被比较对象在当前路径之后被守卫.

        支持寄存器与栈槽两种操作数 (O0 编译常将局部变量驻留栈槽).
        """
        target_raw = ops[0].strip().lower()
        cur = None
        if "[" in target_raw:
            slot = extract_stack_slot(target_raw)
            if slot:
                cur = self._stack.get(slot)
        else:
            reg = norm_reg(target_raw)
            cur = self._regs.get(reg)
        if cur is None:
            return

        other_raw = ops[1].strip().lstrip("$")
        other_val = self._parse_imm(other_raw)
        guard_upper = other_val
        if guard_upper is None:
            other_reg = norm_reg(other_raw)
            other_pv = self._regs.get(other_reg)
            if other_pv is not None and other_pv.bound is not None:
                guard_upper = other_pv.bound
        # 零值比较 (cmp reg, 0; jle/jg) 是正性检查而非上界守卫:
        # 写入路径要求 reg>0, 并不约束上界. 0 作为 guard_upper 会让
        # 写界推断把任意正写入误判为 benign. 此情形不设上界.
        if guard_upper == 0:
            guard_upper = None
        if guard_upper is None:
            guard_upper = cur.guard_upper

        guarded = ProvValue(ProvClass.GUARDED, expr=cur.expr,
                            bound=guard_upper,
                            guard_upper=guard_upper,
                            note="bounds-checked")
        # 副本经 mov/movsxd 共享同一 ProvValue 对象 (对象同一性),
        # 将守卫同步到当前仍指向该对象的所有寄存器/栈槽别名.
        for r in list(self._regs.keys()):
            if self._regs[r] is cur:
                self._regs[r] = guarded
        for s in list(self._stack.keys()):
            if self._stack[s] is cur:
                self._stack[s] = guarded
        if "[" in target_raw:
            slot = extract_stack_slot(target_raw)
            if slot:
                self._stack[slot] = guarded
        else:
            self._regs[norm_reg(target_raw)] = guarded

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lower().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    @staticmethod
    def _parse_lea_terms(operand: str) -> Tuple[Dict[str, int], int]:
        """解析 lea 操作数为 (寄存器系数表, 常量偏移).

        [rax+rax*1] → ({rax:2}, 0); [rax+0x1] → ({rax:1}, 1);
        [rax+rcx*4] → ({rax:1, rcx:4}, 0); [rip+...] → ({}, 0).
        """
        op = operand.strip().lower()
        if "[" not in op or "]" not in op:
            return {}, 0
        inner = op.split("[", 1)[1].split("]", 1)[0]
        coeffs: Dict[str, int] = {}
        offset = 0
        for term in inner.split("+"):
            term = term.strip()
            if not term or term.startswith("rip"):
                continue
            if "*" in term:
                reg, mul = term.split("*", 1)
                reg = reg.strip()
                if reg.startswith("rip"):
                    continue
                try:
                    coeffs[norm_reg(reg)] = coeffs.get(norm_reg(reg), 0) \
                        + int(mul.strip(), 0)
                except ValueError:
                    continue
            else:
                try:
                    offset += int(term, 0)
                except ValueError:
                    reg = norm_reg(term)
                    if reg:
                        coeffs[reg] = coeffs.get(reg, 0) + 1
        return coeffs, offset


__all__ = ["ProvenancePropagator"]
