# 来源传播器指令级处理器 — mov/lea/算术/cmp守卫 的指令语义.
#
# 决策逻辑:
#   - mov/lea 保留来源类别与符号表达式; lea 支持寄存器系数表
#     ([rax+rax*1] → 2*rax).
#   - 算术 (add/sub/shl/shr/imul): 常量平移/缩放保留类别;
#     reg+reg 同源时合并系数 (add same-src).
#   - cmp/test 守卫: 被比较对象 (寄存器或栈槽) 升级为 GUARDED,
#     通过对象同一性同步到所有当前别名, 解决 O2 下守卫作用于副本.
#

from typing import Dict, List, Optional, Tuple

from .disasm_util import norm_reg, extract_stack_slot, is_32bit_reg
from .provenance_domain import ProvClass, ProvValue, join_class
from .sym_size_correlator import SymExpr


class ProvInsnHandlerMixin:
    """指令级来源处理器, 由 ProvenancePropagator 继承."""

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
        if imm is not None and is_32bit_reg(ops[0]) and imm >= 0x80000000:
            imm -= 0x100000000

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
        """add dst, src — 常量平移或同源翻倍 (reg+reg 同源)."""
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
        """记录 cmp/test — 被比较对象在当前路径之后被守卫.

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


__all__ = ["ProvInsnHandlerMixin"]
