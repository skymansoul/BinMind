"""
DDSSC符号传播器 (Symbolic Propagator) — 指令级符号表达式构建.

核心决策:
  在堆溢出检测器的指令分析循环中, 同步维护每个寄存器/栈槽的
  符号表达式. 当遇到malloc(size_reg)时, 为size_reg创建符号变量;
  当遇到memcpy(dst, src, len_reg)时, 提取len_reg的符号表达式,
  用于与分配符号进行关联分析.

  符号表达式仅支持线性形式 a*var+b, 覆盖最常见的模式.
  超出线性形式的表达式标记为None(未知).

创建: 2026-05-14
"""

from typing import Dict, List, Optional
from .sym_size_correlator import SymExpr, SymbolicSizeTracker
from .disasm_util import norm_reg, extract_stack_slot, is_32bit_reg
from .heap_constraint import Interval
from ._sym_complex_handler import SymComplexHandlerMixin


def is_32bit_reg(reg: str) -> bool:
    """判断归一化寄存器是否为32位名 (eax/ebx/.../r8d)."""
    r = reg.strip().lower()
    if r in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return True
    return r.endswith("d") and r[:-1] in (
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


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
        """mov dst, src — 传播符号表达式."""
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
        """cmov* dst, src — 条件移动, 保守传播."""
        dst_reg = norm_reg(ops[0])
        src_reg = norm_reg(ops[1])
        expr = self._tracker.get_expr(src_reg)
        if expr:
            self._tracker.set_expr(dst_reg, expr)

    def _handle_arith(self, mnem: str, ops: List[str],
                      constants: Dict[str, int]):
        """add/sub/shl/shr — 线性算术更新."""
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
        """call func — 调用后处理返回值寄存器.

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
