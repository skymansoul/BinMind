"""
轻量级控制流图构建器 —— 从反编译伪代码行构建简化 CFG。

不做完整反汇编级别的 CFG 恢复 (太慢且对 stripped binary 不稳定)。
只在 IR 行层面做模式识别: 在条件/调用/返回处拆分基本块。

设计决策: 用基于文本的模式识别而非 disassembly-level CFG, 因为:
  1. decompiled IR 的文本行已经包含了控制流结构
  2. 不需要完整的函数边界识别 (由调用方提供)
  3. 速度快 (<1ms), 适合批量扫描

  Cifuentes & Gough — Decompilation of Binary Programs
  Hex-Rays decompiler CFG reconstruction algorithm
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class BlockKind(Enum):
    ENTRY = "entry"
    BASIC = "basic"
    COND = "cond"
    CALL = "call"
    RETURN = "return"

@dataclass
class BasicBlock:
    """简化的基本块 —— 从伪代码行构建。"""
    id: int
    kind: BlockKind = BlockKind.BASIC
    lines: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    branch_cond: Optional[str] = None

class HeapCFGBuilder:
    """从 decompiled IR 行构建简化 CFG。

    拆分策略:
      · 条件语句 (if) → COND 块, 有两条 outgoing 边
      · 内存操作 (malloc/calloc/realloc/memcpy/strcpy/free) → CALL 块
      · 其他 → 每 5 行合并为一个 BASIC 块
    """

    CALL_KEYWORDS = {'malloc', 'calloc', 'realloc', 'memcpy',
                     'strcpy', 'strncpy', 'strcat', 'memset', 'free'}

    def __init__(self):
        self._blocks: List[BasicBlock] = []
        self._bid: int = 0
        self._current_lines: List[str] = []

    def build(self, lines: List[str]) -> List[BasicBlock]:
        """从 IR 行列表构建 CFG。"""
        self._blocks = []
        self._bid = 0
        self._current_lines = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            self._process_line(stripped)

        self._flush_block()
        self._link_successors()
        return self._blocks

    def _process_line(self, line: str) -> None:
        """处理单行 IR, 决定是否拆分块。"""
        # 条件语句
        if line.startswith('if ') or 'if (' in line:
            self._flush_block()
            self._bid += 1
            self._blocks.append(BasicBlock(
                id=self._bid, kind=BlockKind.COND, lines=[line]))
            self._bid += 1
            return

        # 堆/内存调用
        if any(kw in line for kw in self.CALL_KEYWORDS):
            if self._current_lines:
                self._flush_block()
                self._bid += 1
            self._blocks.append(BasicBlock(
                id=self._bid, kind=BlockKind.CALL, lines=[line]))
            self._bid += 1
            return

        # return 语句
        if line.startswith('return ') or line.strip() == 'return':
            if self._current_lines:
                self._flush_block()
                self._bid += 1
            self._blocks.append(BasicBlock(
                id=self._bid, kind=BlockKind.RETURN, lines=[line]))
            self._bid += 1
            return

        self._current_lines.append(line)
        if len(self._current_lines) >= 5:
            self._flush_block()
            self._bid += 1

    def _flush_block(self, kind=BlockKind.BASIC) -> int:
        if self._current_lines:
            self._blocks.append(BasicBlock(
                id=self._bid, kind=kind,
                lines=list(self._current_lines)))
            self._current_lines.clear()
            return self._bid
        return self._bid

    def _link_successors(self) -> None:
        """建立块间 successor 关系。"""
        for i, b in enumerate(self._blocks):
            if b.kind == BlockKind.COND:
                if i + 1 < len(self._blocks):
                    b.successors.append(self._blocks[i + 1].id)
                if i + 2 < len(self._blocks):
                    b.successors.append(self._blocks[i + 2].id)
            elif i + 1 < len(self._blocks):
                b.successors.append(self._blocks[i + 1].id)

def build_heap_cfg(lines: List[str]) -> List[BasicBlock]:
    """便捷入口: 从 IR 行构建堆分析用 CFG。"""
    return HeapCFGBuilder().build(lines)

__all__ = ['BlockKind', 'BasicBlock', 'HeapCFGBuilder', 'build_heap_cfg']
