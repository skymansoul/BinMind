"""ROP gadget 检测器 — 栈溢出利用可行性评估.

创建: 2025-08-07
目的: stack_bound_infer.py 检测溢出风险, canary_bypass_analyzer.py 评估保护绕过,
      本模块完成利用链的最后一步: 检测二进制中是否存在可用的 ROP gadget,
      评估栈溢出被实际利用的可行性。

检测三类 gadget:
  1. pop rdi; ret — 设置第一个参数 (最常见的 ROP gadget)
  2. pop rsi; ret — 设置第二个参数
  3. ret — 裸返回 (用于栈 pivot)
  4. syscall; ret — 直接系统调用

方法依据: ROP 是栈溢出利用的最常见手段 (Shacham, CCS 2007).
          本模块从 .text 段搜索字节序列匹配已知的 gadget 模式。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# x86-64 常见 ROP gadget 的字节序列
_GADGET_PATTERNS = {
    'pop_rdi_ret': bytes([0x5f, 0xc3]),           # pop rdi; ret
    'pop_rsi_ret': bytes([0x5e, 0xc3]),           # pop rsi; ret
    'pop_rdx_ret': bytes([0x5a, 0xc3]),           # pop rdx; ret
    'pop_rcx_ret': bytes([0x59, 0xc3]),           # pop rcx; ret
    'pop_rax_ret': bytes([0x58, 0xc3]),           # pop rax; ret
    'ret': bytes([0xc3]),                          # ret
    'syscall_ret': bytes([0x0f, 0x05, 0xc3]),     # syscall; ret
    'pop_rdi_pop_rsi_ret': bytes([0x5f, 0x5e, 0xc3]),  # pop rdi; pop rsi; ret
    'pop_rdi_pop_rdx_ret': bytes([0x5f, 0x5a, 0xc3]),  # pop rdi; pop rdx; ret
}


@dataclass
class ROPGadget:
    """一个检测到的 ROP gadget."""
    name: str                    # gadget 名称
    address: int                 # 在二进制中的偏移
    bytes_sequence: bytes        # 匹配的字节序列
    usefulness: str              # 'critical'|'high'|'medium'|'low'


class ROPGadgetDetector:
    """ROP gadget 检测器 — 搜索可利用的代码片段.

    使用方式:
      detector = ROPGadgetDetector()
      detector.scan_text_section(open('binary', 'rb').read())
      gadgets = detector.find_all()
      if detector.can_build_chain():
          print('Exploitable: ROP chain can be constructed')
    """

    def __init__(self):
        self._gadgets: List[ROPGadget] = []
        self._text_base: int = 0

    def scan_text_section(self, data: bytes,
                          base_address: int = 0) -> None:
        """扫描二进制数据搜索 ROP gadget."""
        self._text_base = base_address
        self._gadgets.clear()

        for name, pattern in _GADGET_PATTERNS.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                usefulness = self._rate_usefulness(name)
                self._gadgets.append(ROPGadget(
                    name=name, address=base_address + pos,
                    bytes_sequence=pattern, usefulness=usefulness))
                offset = pos + 1

# 限制 gadget 数量防止 memory bomb
                if len(self._gadgets) > 500:
                    self._gadgets = self._gadgets[-300:]
                    return

    def _rate_usefulness(self, name: str) -> str:
        """评估 gadget 的利用价值."""
        if 'pop_rdi' in name and 'pop_rsi' in name:
            return 'critical'  # 同时控制两个参数
        if 'pop_rdi' in name:
            return 'high'       # 控制第一个参数
        if 'syscall' in name:
            return 'critical'   # 直接系统调用
        if 'pop_rax' in name:
            return 'high'       # 控制 syscall 号
        if name == 'ret':
            return 'medium'
        return 'low'

    def find_all(self) -> List[ROPGadget]:
        """返回所有检测到的 gadget."""
        return list(self._gadgets)

    def can_build_chain(self) -> bool:
        """检查是否有足够 gadget 构建 exploit 链.

        最小链: pop rdi; ret + 任意地址 + ret/systemcall
        """
        has_pop_rdi = any(g.name == 'pop_rdi_ret' for g in self._gadgets)
        has_ret = any(g.name == 'ret' for g in self._gadgets)
        return has_pop_rdi and has_ret

    def exploitability_score(self) -> float:
        """栈溢出利用可行性评分 [0,1]."""
        if not self._gadgets:
            return 0.0
        score = 0.0
        # 关键 gadget 各加 0.25
        for key in ('pop_rdi_ret', 'pop_rsi_ret', 'syscall_ret', 'pop_rax_ret'):
            if any(g.name == key for g in self._gadgets):
                score += 0.25
        # gadget 丰富度
        unique = len(set(g.name for g in self._gadgets))
        score += min(0.2, unique * 0.05)
        return min(1.0, score)

    def stats(self) -> dict:
        all_g = self.find_all()
        unique = len(set(g.name for g in all_g))
        return {
            'total_gadgets': len(all_g),
            'unique_patterns': unique,
            'can_build_chain': self.can_build_chain(),
            'exploitability': round(self.exploitability_score(), 2),
            'critical': sum(1 for g in all_g if g.usefulness == 'critical'),
            'high': sum(1 for g in all_g if g.usefulness == 'high'),
        }

    def clear(self) -> None:
        self._gadgets.clear()
        self._text_base = 0
