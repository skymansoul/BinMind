"""
DDSSC符号传播器 (Symbolic Propagator) - 指令级符号表达式构建.

核心决策:
  在堆溢出检测器的指令分析循环中, 同步维护每个寄存器/栈槽的
  符号表达式. 当遇到malloc(size_reg)时, 为size_reg创建符号变量;
  当遇到memcpy(dst, src, len_reg)时, 提取len_reg的符号表达式,
  用于与分配符号进行关联分析.

  符号表达式仅支持线性形式 a*var+b, 覆盖最常见的模式.
  超出线性形式的表达式标记为None(未知).

创建: 2023-09-06
"""

import re
from typing import Dict, List, Optional
from .sym_size_correlator import SymExpr, SymbolicSizeTracker
from .disasm_util import norm_reg, extract_stack_slot, is_32bit_reg
from .heap_constraint import Interval


def is_32bit_reg(reg: str) -> bool:
    """判断归一化寄存器是否为32位名 (eax/ebx/.../r8d)."""
    r = reg.strip().lower()
    if r in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return True
    return r.endswith("d") and r[:-1] in (
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


class SymComplexHandlerMixin:
    """lea/imul复杂指令的符号表达式处理, 由SymbolicPropagator继承."""

    def _handle_lea(self, ops: List[str]):
        """lea dst, [base + index*scale + offset] - 完整x86内存地址计算.

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
        """imul dst, src[, imm] - 乘法更新符号表达式.

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


class SymbolicPropagator(SymComplexHandlerMixin):
    """指令级符号表达式传播器.

    与HeapOverflowDetector.analyze_instruction()并行调用,
    维护寄存器/栈槽的符号表达式状态.
    """

    _TAINT_FUNCS = {"read", "recv", "fgets", "fread", "gets",
                     "fgets_unlocked", "recvfrom", "recvmsg"}

    def __init__(self, tracker: SymbolicSizeTracker):
        self._tracker = tracker
        self._init_params: bool = False
        self._taint_counter: int = 0

    def init_function_params(self, args: List[str]):
        """在函数入口为参数寄存器创建初始符号变量."""
        for i, reg in enumerate(args):
            sym = f"param_{i}"
            self._tracker.set_expr(reg, SymExpr(var=sym))
        self._init_params = True

    def handle_instruction(self, ins: dict, known_constants: Dict[str, int]):
        """处理单条指令, 更新符号状态."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])

        if not ops:
            return

        if mnem == "mov" and len(ops) >= 2:
            self._handle_mov(ops, known_constants)
        elif mnem in ("movsxd", "movzx", "movsx") and len(ops) >= 2:
            self._handle_mov(ops, known_constants)
        elif mnem.startswith("cmov") and len(ops) >= 2:
            self._handle_cmov(ops)
        elif mnem in ("add", "sub", "shl", "shr") and len(ops) >= 2:
            self._handle_arith(mnem, ops, known_constants)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(ops)
        elif mnem in ("imul", "mul") and len(ops) >= 2:
            self._handle_imul(ops, known_constants)
        elif mnem == "call":
            self._handle_call(ops)

    def _handle_mov(self, ops: List[str], constants: Dict[str, int]):
        """mov dst, src - 传播符号表达式."""
        dst_raw = ops[0].strip()
        dst_reg = norm_reg(dst_raw)
        src = ops[1].strip().lstrip("$").split("#")[0].strip()
        dst_lower = dst_raw.lower()

        if src.startswith("0x") or src.isdigit() or \
           (src.startswith("-") and src[1:].isdigit()):
            val = int(src, 16) if src.startswith("0x") else int(src)
            if is_32bit_reg(dst_reg) and val >= 0x80000000:
                val -= 0x100000000
            if "[" in dst_lower and "rbp" in dst_lower:
                slot = extract_stack_slot(dst_raw)
                if slot:
                    self._tracker.set_stack_expr(slot, SymExpr(None, 0, val))
                return
            self._tracker.set_expr(dst_reg, SymExpr(None, 0, val))
            constants[dst_reg] = val
            return

        src_reg = norm_reg(src)

        if "[" in dst_lower and "rbp" in dst_lower:
            slot = extract_stack_slot(dst_raw)
            if slot:
                expr = self._tracker.get_expr(src_reg)
                if expr:
                    self._tracker.set_stack_expr(slot, expr)
                else:
                    self._tracker._stack_exprs.pop(slot, None)
            return

        if "[" in src.lower() and "rbp" in src.lower():
            slot = extract_stack_slot(src)
            if slot:
                expr = self._tracker.get_stack_expr(slot)
                if expr:
                    self._tracker.set_expr(dst_reg, expr)
                    return
            self._tracker.clear(dst_reg)
            constants.pop(dst_reg, None)
            return

        expr = self._tracker.get_expr(src_reg)
        if expr:
            self._tracker.set_expr(dst_reg, expr)
        else:
            self._tracker.clear(dst_reg)

    def _handle_cmov(self, ops: List[str]):
        """cmov* dst, src - 条件移动, 保守传播."""
        dst_reg = norm_reg(ops[0])
        src_reg = norm_reg(ops[1])
        expr = self._tracker.get_expr(src_reg)
        if expr:
            self._tracker.set_expr(dst_reg, expr)

    def _handle_arith(self, mnem: str, ops: List[str],
                      constants: Dict[str, int]):
        """add/sub/shl/shr - 线性算术更新."""
        dst_reg = norm_reg(ops[0])
        src = ops[1].strip().lstrip("$").split("#")[0].strip()

        cur = self._tracker.get_expr(dst_reg)
        if cur is None:
            return

        imm = self._parse_imm(src)
        if imm is not None and is_32bit_reg(ops[0]) and imm >= 0x80000000:
            imm -= 0x100000000  # 32位负数编码符号扩展
        src_reg = norm_reg(src)

        if imm is not None:
            if mnem == "add":
                self._tracker.set_expr(dst_reg, cur.add_const(imm))
                if dst_reg in constants:
                    constants[dst_reg] = constants[dst_reg] + imm
            elif mnem == "sub":
                self._tracker.set_expr(dst_reg, cur.add_const(-imm))
                if dst_reg in constants:
                    constants[dst_reg] = constants[dst_reg] - imm
            elif mnem == "shl" and (cur.var is not None or cur.is_const()):
                factor = 1 << imm
                self._tracker.set_expr(dst_reg, cur.scale(factor))
                constants.pop(dst_reg, None)
            elif mnem == "shr":
                self._tracker.clear(dst_reg)
                constants.pop(dst_reg, None)
        else:
            src_expr = self._tracker.get_expr(src_reg)
            if src_expr and src_expr.is_const() and cur.var is not None:
                if mnem == "add":
                    self._tracker.set_expr(dst_reg,
                                           cur.add_const(src_expr.const))
                elif mnem == "sub":
                    self._tracker.set_expr(dst_reg,
                                           cur.add_const(-src_expr.const))
            else:
                self._tracker.clear(dst_reg)
                constants.pop(dst_reg, None)

    def _handle_call(self, ops: List[str]):
        """call func - 调用后处理返回值寄存器.

        外部输入函数(read/recv等)的返回值创建为新的符号变量.
        不清除caller-saved寄存器: 检测器需在call指令处理中
        读取r8/r9作为size参数, 清除时机由检测器控制.
        """
        func_name = ""
        if ops:
            raw = ops[0].strip()
            if "<" in raw and ">" in raw:
                func_name = raw.split("<")[1].split(">")[0].strip()
            else:
                func_name = raw

        func_lower = func_name.lower()

        if func_lower in self._TAINT_FUNCS:
            sym = f"taint_{self._taint_counter}"
            self._taint_counter += 1
            self._tracker.set_expr("rax", SymExpr(var=sym))

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lower().replace("$", "").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    def get_size_expr(self, reg: str) -> Optional[SymExpr]:
        """获取寄存器当前的符号表达式."""
        return self._tracker.get_expr(norm_reg(reg))

    def get_alloc_size_expr(self, alloc_addr: int,
                            size_reg: str) -> SymExpr:
        """为分配点创建或获取符号变量.

        若size_reg已有符号表达式(如从函数参数传播而来),
        复制该表达式作为分配尺寸的符号表示.
        """
        existing = self._tracker.get_expr(norm_reg(size_reg))
        if existing and not existing.is_const():
            sym = self._tracker.new_alloc_symbol(alloc_addr, size_reg)
            self._tracker.set_expr(sym, existing)
            return existing
        sym = self._tracker.new_alloc_symbol(alloc_addr, size_reg)
        expr = self._tracker.get_expr(sym)
        if expr:
            return expr
        return SymExpr(var=sym)


__all__ = ["SymbolicPropagator"]
