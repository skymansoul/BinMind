# 传播协调器: 将指令操作分发给各追踪器
# 铁律
# 职责: 协调 PointerProvenanceTracker + TaintTracker + ValueRangeDomain
#   的三方传播 — handle_mov, handle_lea, handle_arith, handle_mul_div_shift,
#   handle_xor_zero, handle_push, handle_pop, handle_bound_check
# 扩展: 自 FpReductionMixin 引入 SizeIdentityTracker 作为第四方传播,
#   维护分配/写入 size 参数的符号同一性 (值流耦合分析基础)
from typing import Optional

from .value_range import ValueRangeDomain
from .pointer_provenance import PointerProvenanceTracker
from .taint_propagation import TaintTracker
from .instruction_parser import InstructionParser
from .size_identity import SizeIdentityTracker


class PropagationCoordinator:
    """传播协调器: 将指令操作分发给各追踪器.

    每个方法对应一种指令类型, 协调:
      - PointerProvenanceTracker: 指针溯源更新
      - TaintTracker: 污点标记传播
      - ValueRangeDomain: 值域转移 (可选)
      - SizeIdentityTracker: size 符号同一性传播 (耦合分析)
    """

    def __init__(self, provenance: PointerProvenanceTracker,
                 taint: TaintTracker,
                 value_domain: Optional[ValueRangeDomain] = None):
        self._prov = provenance
        self._taint = taint
        self._vd = value_domain
        self.size_identity = SizeIdentityTracker()

    def handle_mov(self, dst: str, src: str, context: str = ""):
        """mov dst, src."""
        dst_c = InstructionParser.clean_reg(dst)
        src_c = InstructionParser.clean_reg(src)
        # 归一化到64位: mov r8d, 0x100 等价于 mov r8, 0x100
        dst64 = InstructionParser.normalize_reg64(dst_c)
        src64 = InstructionParser.normalize_reg64(src_c)
        # 寄存器→寄存器
        if InstructionParser.is_reg(dst) and InstructionParser.is_reg(src):
            self._prov.propagate_reg_to_reg(dst64, src64, context)
            self._taint.propagate_assign(dst64, src64)
            self.size_identity.mov_reg(dst64, src64)
            # 值域传播: 寄存器→寄存器
            if self._vd:
                src_vr = self._vd.get(src64)
                if not src_vr.is_top:
                    self._vd.set(dst64, src_vr)
        # 内存→寄存器: mov reg, [base+off]
        # MUST come before imm→reg check, otherwise DWORD PTR [rbp] is
        # mistaken for an immediate (has no '[' after SIZE_PREFIX stripping)
        elif InstructionParser.is_reg(dst) and ('[' in src or 'PTR' in src.upper()):
            base, off = InstructionParser.parse_mem(src)
            if base:
                self._prov.propagate_stack_to_reg(dst64, base, off, context)
                self.size_identity.mov_mem_to_reg(dst64, base, off)
                # 值域: 从内存槽位恢复到寄存器
                if self._vd:
                    mem_vr = self._vd.get_mem(off)
                    if not mem_vr.is_top:
                        self._vd.set(dst64, mem_vr)
                    else:
                        # 内存值未知 → 当前寄存器值域失效
                        from .value_range import ValueRange
                        self._vd.set(dst64, ValueRange.top())
        # 立即数→寄存器: mov reg, imm
        elif InstructionParser.is_reg(dst) and not InstructionParser.is_reg(src):
            imm_val = InstructionParser.parse_immediate(src)
            if imm_val is not None:
                self.size_identity.mov_const(dst64, imm_val)
            else:
                self.size_identity.mark_unknown(dst64)
            if imm_val is not None and self._vd:
                from .value_range import ValueRange
                self._vd.set(dst64, ValueRange.constant(imm_val))
            # 立即数覆写寄存器 → 清除指针溯源 (该寄存器不再持有指针)
            self._prov.clear_register(dst64)
        # 寄存器→内存: mov [base+off], reg
        elif ('[' in dst or 'PTR' in dst.upper()) and InstructionParser.is_reg(src):
            base, off = InstructionParser.parse_mem(dst)
            if base:
                self._prov.propagate_reg_to_stack(base, off, src64, context)
                self.size_identity.mov_reg_to_mem(base, off, src64)
                # 值域: 将寄存器值保存到内存槽位
                # 即使reg_vr为TOP也更新: 否则mov [rbp-0x4],eax在eax=TOP
                # (atoi返回后)时会保留旧常数值, 导致write_size被误判为安全
                if self._vd:
                    reg_vr = self._vd.get(src64)
                    self._vd.set_mem(off, reg_vr)
        # 立即数→内存: mov [base+off], imm (DWORD PTR [rbp-0x4], 0x80)
        elif ('[' in dst or 'PTR' in dst.upper()) and not InstructionParser.is_reg(src):
            base, off = InstructionParser.parse_mem(dst)
            imm_val = InstructionParser.parse_immediate(src)
            if imm_val is not None:
                self.size_identity.mov_const_to_mem(base, off, imm_val)
            if imm_val is not None and self._vd:
                from .value_range import ValueRange
                self._vd.set_mem(off, ValueRange.constant(imm_val))

    def handle_lea(self, dst: str, src: str, context: str = ""):
        """lea dst, [base+idx*scale+off]."""
        dst_c = InstructionParser.clean_reg(dst)
        base, off, idx, scale = InstructionParser.parse_lea_src(src)
        if base:
            self._prov.apply_lea(dst_c, base, off, idx, scale, context)
            if not idx:
                self.size_identity.lea(
                    InstructionParser.normalize_reg64(dst_c), base, off)
            else:
                self.size_identity.mark_unknown(
                    InstructionParser.normalize_reg64(dst_c))

    def handle_arith(self, op: str, dst: str, src: str, context: str = ""):
        """add/sub dst, src."""
        dst_c = InstructionParser.clean_reg(dst)
        dst64 = InstructionParser.normalize_reg64(dst_c)
        imm = InstructionParser.parse_immediate(src)
        if imm is not None and InstructionParser.is_reg(dst):
            delta = imm if op == "add" else -imm
            self._prov.apply_pointer_arith(dst_c, dst_c, delta, context)
            self.size_identity.arith(op, dst64, imm)
            # 值域: add/sub → 调整已知值域
            if self._vd:
                dst_vr = self._vd.get(dst64)
                if not dst_vr.is_top:
                    from .value_range import ValueRange
                    delta_vr = ValueRange.constant(delta)
                    if op == "add":
                        self._vd.set(dst64, dst_vr.add(delta_vr))
                    else:
                        self._vd.set(dst64, dst_vr.sub(delta_vr))
        elif (op == "add" and InstructionParser.is_reg(src)
              and InstructionParser.is_reg(dst)):
            # add dst, src (寄存器源): 编译器常先 lea 计算索引再叠加基址
            # (lea rdx,[rax*4]; add rdx,rax). dst 无溯源而 src 有溯源时,
            # 结果 = src + dst_值, 溯源转移并保守保持偏移.
            src64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(src))
            if self._prov.get_origin(dst64) is None:
                src_origin = self._prov.get_origin(src64)
                if src_origin is not None:
                    self._prov.propagate_reg_to_reg(dst64, src64, context)
        self._taint.propagate_arith(dst_c, dst_c, src)

    def handle_mul_div_shift(self, op: str, dst: str, src: str, context: str = ""):
        """imul/mul/shl/shr/sar dst, src — 乘法/移位操作.

        保守处理: 若源操作数非常数, 将目标寄存器值域设为TOP.
        移位操作: 视为乘法/shift因子.
        """
        if not self._vd:
            return
        dst_c = InstructionParser.clean_reg(dst)
        dst64 = InstructionParser.normalize_reg64(dst_c)
        dst_vr = self._vd.get(dst64)
        if dst_vr.is_top:
            return
        imm = InstructionParser.parse_immediate(src)
        from .value_range import ValueRange
        # 32 位乘法/移位可回绕 (curl CVE-2018-14618 模式):
        # identity 的 scale 模型不含宽度截断, 32 位算术结果一律退化
        is_32bit = (InstructionParser.reg_bit_width(dst_c) == 32)
        if op == "imul" or op == "mul":
            if imm is not None:
                self._vd.set(dst64, dst_vr.mul(ValueRange.constant(imm)))
                if is_32bit:
                    self.size_identity.mark_unknown(dst64)
                else:
                    self.size_identity.mul(dst64, imm)
            else:
                self.size_identity.mark_unknown(dst64)
                # 非常数乘数: 保守设为unsigned_range
                self._vd.set(dst64,
                    ValueRange.unsigned_range(0, min(dst_vr.umax * 256, 0x7FFFFFFF))
                    if dst_vr.umax < 0x100000 else ValueRange.top())
        elif op == "shl":
            if imm is not None and imm > 0:
                self._vd.set(dst64, dst_vr.mul(ValueRange.constant(1 << imm)))
                self.size_identity.mark_unknown(dst64)
            else:
                self.size_identity.mark_unknown(dst64)
                self._vd.set(dst64, ValueRange.top())
        elif op in ("shr", "sar"):
            self.size_identity.mark_unknown(dst64)
            # 右移: 保守地将范围缩小
            if imm is not None and imm > 0:
                shift = 1 << imm
                self._vd.set(dst64, ValueRange.unsigned_range(
                    max(0, dst_vr.umin // shift),
                    max(1, dst_vr.umax // shift)))
            else:
                self._vd.set(dst64, ValueRange.top())

    def handle_xor_zero(self, dst: str, src: str):
        """xor reg, reg — 清零寄存器."""
        if dst == src and InstructionParser.is_reg(dst):
            dst64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(dst))
            self._prov.clear_register(dst64)
            self.size_identity.zero(dst64)

    def handle_push(self, reg: str, context: str = ""):
        r = InstructionParser.clean_reg(reg)
        if r:
            self._prov.propagate_reg_to_stack("rsp", 0, r, context)

    def handle_pop(self, reg: str, context: str = ""):
        r = InstructionParser.clean_reg(reg)
        if r:
            self._prov.propagate_stack_to_reg(r, "rsp", 0, context)

    def handle_bound_check(self, var: str, bound: int):
        """cmp var, bound — 检测边界检查."""
        v = InstructionParser.clean_reg(var)
        if v:
            self._taint.detect_bound_check(v, bound)
