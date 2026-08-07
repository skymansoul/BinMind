# 符号传播器复杂指令处理.
# 包含lea地址计算和imul乘法的符号表达式更新.
# 创建: 2026-06-05

import re
from typing import Dict, List

from .sym_size_correlator import SymExpr
from .disasm_util import norm_reg


class SymComplexHandlerMixin:
    """lea/imul复杂指令的符号表达式处理, 由SymbolicPropagator继承."""

    def _handle_lea(self, ops: List[str]):
        """lea dst, [base + index*scale + offset] — 完整x86内存地址计算.

        支持: [rbp-0x8], [rax+rax*1], [rcx+rdx*8+0x10] 等形式.
        符号表达式: result = base_expr + index_expr*scale + offset
        """
        dst_reg = norm_reg(ops[0])
        src = ops[1].strip()
        src = src.split("#")[0].strip()
        src_lower = src.lower().replace("[", "").replace("]", "").strip()

        terms = re.split(r'\s*([+-])\s*', src_lower)
        base_expr = None
        index_expr = None
        index_scale = 0
        const_offset = 0

        first_term = terms[0].strip() if terms else ""
        if first_term:
            parsed = self._parse_lea_term(first_term)
            if parsed:
                kind, reg, scale, val = parsed
                if kind == "reg":
                    base_expr = self._tracker.get_expr(reg)
                elif kind == "reg_scale":
                    index_expr = self._tracker.get_expr(reg)
                    index_scale = scale
                elif kind == "const":
                    const_offset = val

        i = 1
        while i < len(terms):
            sign = 1 if terms[i] == "+" else -1
            term = terms[i + 1].strip() if i + 1 < len(terms) else ""
            if term:
                parsed = self._parse_lea_term(term)
                if parsed:
                    kind, reg, scale, val = parsed
                    if kind == "reg" and base_expr is None:
                        base_expr = self._tracker.get_expr(reg)
                    elif kind == "reg":
                        idx = self._tracker.get_expr(reg)
                        if idx:
                            if sign > 0:
                                if index_expr is None:
                                    index_expr = idx
                                    index_scale = scale if scale > 0 else 1
                                else:
                                    index_expr = None
                            else:
                                index_expr = None
                    elif kind == "reg_scale":
                        idx = self._tracker.get_expr(reg)
                        if idx:
                            if sign > 0 and index_expr is None:
                                index_expr = idx
                                index_scale = scale
                            else:
                                index_expr = None
                    elif kind == "const":
                        const_offset += sign * val
            i += 2

        if base_expr is None and index_expr is None:
            self._tracker.clear(dst_reg)
            return

        result = base_expr if base_expr else None
        if index_expr:
            scaled = index_expr.scale(index_scale) if index_scale != 1 else index_expr
            if result:
                if result.var == scaled.var:
                    result = SymExpr(result.var,
                                     result.coeff + scaled.coeff,
                                     result.const + scaled.const)
                else:
                    result = None
            else:
                result = scaled

        if result is None:
            self._tracker.clear(dst_reg)
            return

        if const_offset != 0:
            result = result.add_const(const_offset)
        self._tracker.set_expr(dst_reg, result)

    def _parse_lea_term(self, term: str):
        """解析lea内存操作数的单个项: rax, rax*1, 0x10."""
        term = term.strip()
        if "*" in term:
            parts = term.split("*")
            reg = parts[0].strip()
            try:
                scale = int(parts[1].strip(), 0)
            except (ValueError, IndexError):
                return None
            if reg and not reg.isdigit():
                return ("reg_scale", norm_reg(reg), scale, 0)
            return None
        if term.startswith("0x") or term.isdigit() or \
           (term.startswith("-") and term[1:].isdigit()):
            val = int(term, 16) if term.startswith("0x") else int(term)
            return ("const", "", 0, val)
        if term and not term.isdigit():
            return ("reg", norm_reg(term), 1, 0)
        return None

    def _handle_imul(self, ops: List[str],
                     constants: Dict[str, int]):
        """imul dst, src[, imm] — 乘法更新符号表达式.

        三操作数: imul dst, src, imm → dst = src * imm (线性, 可精确追踪)
        两操作数: imul dst, src → dst = dst * src
          若dst和src持有同一变量的符号表达式, 合并系数
          超出线性形式的乘积标记为None
        """
        dst_reg = norm_reg(ops[0])
        if len(ops) >= 3:
            imm = self._parse_imm(ops[2])
            if imm is not None:
                cur = self._tracker.get_expr(dst_reg)
                if cur:
                    self._tracker.set_expr(dst_reg, cur.scale(imm))
                    constants.pop(dst_reg, None)
            return

        if len(ops) == 2:
            dst_expr = self._tracker.get_expr(dst_reg)
            src_str = ops[1].strip().lstrip("$").split("#")[0].strip()
            src_reg = norm_reg(src_str)
            src_expr = self._tracker.get_expr(src_reg)
            if dst_expr is None or src_expr is None:
                self._tracker.clear(dst_reg)
                constants.pop(dst_reg, None)
                return
            if dst_expr.is_const() and src_expr.is_const():
                product = dst_expr.const * src_expr.const
                self._tracker.set_expr(dst_reg, SymExpr(None, 0, product))
                constants[dst_reg] = product
                return
            if dst_expr.var is not None and dst_expr.var == src_expr.var:
                total_coeff = dst_expr.coeff * src_expr.coeff
                total_const = dst_expr.const * src_expr.const
                self._tracker.set_expr(dst_reg,
                    SymExpr(dst_expr.var, total_coeff, total_const))
                constants.pop(dst_reg, None)
                return
            self._tracker.clear(dst_reg)
            constants.pop(dst_reg, None)
