"""符号混淆检测器 — 有符号/无符号混用 + 隐式类型转换导致的溢出.

创建: 2026-08-02
目的: 检测二进制中因符号混淆导致的整数溢出。最常见的模式:
      1. 无符号比较 vs 有符号运算: if (unsigned_val < limit) 后做 signed 运算
      2. 隐式零扩展/符号扩展: movzx vs movsx 的错误选择
      3. 负值传给需要非负参数的函数 (如 malloc(-1) → 分配失败但不检查)

方法依据: CWE-681 (整数到无符号映射错误) 和 CWE-195 (有符号到无符号转换错误)
          是 CWE Top 25 中的常客。本模块检测二进制指令级别的符号混淆模式。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class SignMismatch:
    """一次符号混淆的实例."""
    insn_addr: int
    signed_reg: str             # 有符号解释的寄存器
    unsigned_reg: str           # 无符号解释的寄存器 (可能是同一寄存器)
    pattern: str                # 'movsx_after_movzx'|'cmp_jg_mismatch'|'neg_arg'
    passes_to_alloc: bool       # 混淆后的值传给 malloc/realloc
    risk: str                   # 'critical'|'high'|'medium'


class SignMismatchDetector:
    """符号混淆检测器 — 二进制指令级别的符号语义分析.

    检测三类模式:
      1. movsx after movzx: 零扩展后做符号扩展 → 值解释翻转
      2. cmp+jg/jl mismatch: 无符号比较后用有符号跳转 → 边界检查失效
      3. neg_arg: 可能为负的值传给 malloc(size_t) → 隐式转换为巨大无符号值

    使用方式:
      smd = SignMismatchDetector()
      smd.add_instruction(0x1000, 'movzx', 'eax', 'al')
      smd.add_instruction(0x1002, 'movsx', 'eax', 'al', same_reg=True)
      mismatches = smd.detect()
    """

    def __init__(self):
        # 指令序列
        self._instructions: List[Tuple[int, str, str, str]] = []
        # 检测结果
        self._mismatches: List[SignMismatch] = []

    def add_instruction(self, insn_addr: int, mnemonic: str,
                        dst: str, src: str,
                        same_reg: bool = False) -> None:
        """添加一条指令."""
        self._instructions.append((insn_addr, mnemonic, dst, src))
        # 保持窗口大小
        if len(self._instructions) > 100:
            self._instructions = self._instructions[-50:]

    def detect(self) -> List[SignMismatch]:
        """扫描指令序列检测符号混淆."""
        self._mismatches.clear()

        for i in range(len(self._instructions) - 1):
            addr_a, mnem_a, dst_a, src_a = self._instructions[i]
            addr_b, mnem_b, dst_b, src_b = self._instructions[i + 1]

            # 模式1: movzx → movsx on same register
            if (mnem_a == 'movzx' and mnem_b == 'movsx'
                    and dst_a == dst_b):
                self._mismatches.append(SignMismatch(
                    insn_addr=addr_a, signed_reg=dst_b,
                    unsigned_reg=dst_a,
                    pattern='movsx_after_movzx',
                    passes_to_alloc=False, risk='medium'))

            # 模式2: cmp+条件跳转 mismatch
            if mnem_a == 'cmp':
                if mnem_b in ('jg', 'jge', 'jl', 'jle'):
                    # 有符号跳转 — 但比较可能是无符号的
                    self._mismatches.append(SignMismatch(
                        insn_addr=addr_a,
                        signed_reg=dst_a if dst_a else src_a,
                        unsigned_reg=src_a if src_a else dst_a,
                        pattern='cmp_jg_mismatch',
                        passes_to_alloc=False, risk='high'))

            # 模式3: neg → call malloc (负值变巨大正值)
            if mnem_a == 'neg' and 'malloc' in str(dst_b).lower():
                self._mismatches.append(SignMismatch(
                    insn_addr=addr_a, signed_reg=dst_a,
                    unsigned_reg=dst_a,
                    pattern='neg_arg',
                    passes_to_alloc=True, risk='critical'))

        return self._mismatches

    def mark_alloc_passing(self, insn_addr: int) -> None:
        """标记某处的值传递给了分配函数."""
        for m in self._mismatches:
            if m.insn_addr == insn_addr:
                m.passes_to_alloc = True
                if m.risk == 'high':
                    m.risk = 'critical'

    def stats(self) -> dict:
        mismatches = self.detect()
        critical = sum(1 for m in mismatches if m.risk == 'critical')
        high = sum(1 for m in mismatches if m.risk == 'high')
        return {
            'instructions_scanned': len(self._instructions),
            'mismatches_found': len(mismatches),
            'critical': critical,
            'high_risk': high,
            'patterns': {
                'movsx_after_movzx': sum(1 for m in mismatches
                    if 'movsx' in m.pattern),
                'cmp_jg_mismatch': sum(1 for m in mismatches
                    if 'cmp_jg' in m.pattern),
                'neg_arg': sum(1 for m in mismatches
                    if m.pattern == 'neg_arg'),
            },
        }

    def clear(self) -> None:
        self._instructions.clear()
        self._mismatches.clear()
