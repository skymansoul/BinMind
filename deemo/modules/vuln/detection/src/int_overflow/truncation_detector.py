"""整数截断检测器 — 大位宽→小位宽赋值 + 隐式类型转换截断.

创建: 2025-04-17
目的: 检测因隐式类型转换导致的整数截断，这是除溢出/符号混淆外的
      第三大整数相关漏洞模式。常见场景:
      1. 64-bit size_t → 32-bit int (大文件处理)
      2. uint32_t → uint16_t (网络协议解析)
      3. memcpy(dst, src, short_len) 中 short_len 截断自 long_len

方法依据: CWE-197 (整数截断错误) — 当较大整数类型隐式转换为
          较小类型时，高位被丢弃，可能导致缓冲区分配过小。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


_SRC_WIDTH = {'eax': 32, 'rax': 64, 'ax': 16, 'al': 8,
             'ebx': 32, 'rbx': 64, 'bx': 16, 'bl': 8,
             'ecx': 32, 'rcx': 64, 'cx': 16, 'cl': 8,
             'edx': 32, 'rdx': 64, 'dx': 16, 'dl': 8,
             'esi': 32, 'rsi': 64, 'si': 16, 'sil': 8,
             'edi': 32, 'rdi': 64, 'di': 16, 'dil': 8,
             'r8d': 32, 'r8': 64, 'r8w': 16, 'r8b': 8,
}


@dataclass
class TruncationCandidate:
    insn_addr: int
    src_reg: str
    dst_reg: str
    src_width: int
    dst_width: int
    bits_lost: int             # 被截断的位数
    used_in_size_calc: bool    # 结果是否用于大小计算
    risk: str                  # 'critical'|'high'|'medium'


class TruncationDetector:
    """整数截断检测器 — 识别位宽收缩模式.

    使用方式:
      td = TruncationDetector()
      td.add_move('mov', 'rax', 'eax', 0x401000)  # 64→32 截断
      td.add_move('mov', 'eax', 'ax', 0x401002)    # 32→16 截断
      candidates = td.detect()
    """

    def __init__(self):
        self._moves: List[Tuple[str, str, str, int]] = []
        self._used_in_size: Set[int] = set()

    def add_move(self, mnemonic: str, src: str, dst: str,
                 insn_addr: int) -> None:
        """记录 mov 指令."""
        self._moves.append((mnemonic, src.lower(), dst.lower(), insn_addr))
        if len(self._moves) > 200:
            self._moves = self._moves[-100:]

    def mark_size_related(self, insn_addr: int) -> None:
        """标记该指令的结果用于大小计算 (malloc参数/循环边界/memcpy长度)."""
        self._used_in_size.add(insn_addr)

    def detect(self) -> List[TruncationCandidate]:
        """检测截断模式."""
        candidates = []
        for mnemonic, src, dst, addr in self._moves:
            src_w = _SRC_WIDTH.get(src, 0)
            dst_w = _SRC_WIDTH.get(dst, 0)

            # 不是已知寄存器 → 跳过
            if src_w == 0 or dst_w == 0:
                continue

            # 源宽度 > 目标宽度 → 截断
            if src_w > dst_w:
                bits_lost = src_w - dst_w
                risk = 'medium'
                if bits_lost >= 32:
                    risk = 'high'
                if addr in self._used_in_size:
                    risk = 'critical'

                candidates.append(TruncationCandidate(
                    insn_addr=addr, src_reg=src, dst_reg=dst,
                    src_width=src_w, dst_width=dst_w,
                    bits_lost=bits_lost,
                    used_in_size_calc=addr in self._used_in_size,
                    risk=risk))

        candidates.sort(key=lambda c: (
            {'critical': 0, 'high': 1, 'medium': 2}[c.risk]))
        return candidates

    def stats(self) -> dict:
        cands = self.detect()
        critical = sum(1 for c in cands if c.risk == 'critical')
        high = sum(1 for c in cands if c.risk == 'high')
        return {
            'moves_scanned': len(self._moves),
            'truncations_found': len(cands),
            'critical': critical,
            'high_risk': high,
            'mean_bits_lost': (
                sum(c.bits_lost for c in cands) / max(1, len(cands))
                if cands else 0),
        }

    def clear(self) -> None:
        self._moves.clear()
        self._used_in_size.clear()
