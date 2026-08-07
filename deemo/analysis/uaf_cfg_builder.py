"""

功能:
  1. 从伪代码行识别基本块边界
  2. 分析块内 free/use 操作
  3. 连接CFG边 (顺序 + 条件分支)

设计决策: 从 UafPathVerifier 中提取为独立模块,
  使 CFG 构建可被其他 UAF 分析模块复用 (DRY).
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class UafBasicBlock:
    """UAF分析用简化基本块: 一个连续的线性指令序列。"""
    id: int
    start_line: int
    end_line: int
    lines: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    has_free: bool = False
    has_use: bool = False
    free_vars: Set[str] = field(default_factory=set)
    use_vars: Set[str] = field(default_factory=set)
    cond_expr: str = ""


class UafCFGBuilder:
    """UAF专用的轻量级CFG构建器。

    拆分策略:
      - 条件分支 (if/else/switch) → 新块边界
      - 跳转 (return/break/continue/goto) → 块结束
      - 边: 顺序边 + 条件分支边 (then+else)
    """

    BRANCH_KEYWORDS = (
        'if ', 'if(', 'else', 'for ', 'for(',
        'while ', 'while(', 'switch ', 'switch(',
    )
    END_KEYWORDS = ('return ', 'break;', 'continue;', 'goto ')

    def __init__(self):
        self._blocks: List[UafBasicBlock] = []
        self._adj: Dict[int, List[int]] = {}

    def build(self, pseudocode_lines: List[str]) -> List[UafBasicBlock]:
        """从伪代码行构建UAF分析用CFG。"""
        self._blocks = []
        self._adj = {}

        if not pseudocode_lines:
            return []

        boundaries = self._find_boundaries(pseudocode_lines)
        self._build_blocks(pseudocode_lines, boundaries)
        self._connect_edges(pseudocode_lines)
        return self._blocks

    def _find_boundaries(self, lines: List[str]) -> List[int]:
        """找到基本块边界 (行索引)。"""
        boundaries = [0]
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            if any(stripped.startswith(kw) for kw in self.BRANCH_KEYWORDS):
                if i not in boundaries:
                    boundaries.append(i)
            if any(stripped.startswith(kw) for kw in self.END_KEYWORDS):
                if i + 1 < len(lines) and (i + 1) not in boundaries:
                    boundaries.append(i + 1)
        boundaries.sort()
        return boundaries

    def _build_blocks(self, lines: List[str], boundaries: List[int]) -> None:
        """从边界列表构建 UafBasicBlock 对象。"""
        block_id = 0
        for i in range(len(boundaries)):
            start = boundaries[i]
            end = boundaries[i + 1] - 1 if i + 1 < len(boundaries) else len(lines) - 1
            start = max(0, min(start, len(lines) - 1))
            end = max(start, min(end, len(lines) - 1))

            block_lines = lines[start:end + 1]
            bb = UafBasicBlock(id=block_id, start_line=start, end_line=end,
                             lines=block_lines)
            self._analyze_ops(bb)
            self._blocks.append(bb)
            self._adj[block_id] = []
            block_id += 1

    def _analyze_ops(self, bb: UafBasicBlock) -> None:
        """分析基本块内的堆操作 (free/use)。"""
        block_text = '\n'.join(bb.lines)
        for m in re.finditer(r'free\s*\(\s*(?:&?\*?)(\w+)\s*\)', block_text):
            bb.has_free = True
            bb.free_vars.add(m.group(1))
        for m in re.finditer(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', block_text):
            var = m.group(1) or m.group(2) or m.group(3)
            if var and not var.startswith(('int', 'char', 'size')):
                bb.has_use = True
                bb.use_vars.add(var)

    def _connect_edges(self, lines: List[str]) -> None:
        """在基本块之间添加CFG边。"""
        n = len(self._blocks)
        for i in range(n - 1):
            if i + 1 not in self._adj.get(i, []):
                self._adj.setdefault(i, []).append(i + 1)

            bb = self._blocks[i]
            first_line = bb.lines[0].strip() if bb.lines else ""
            if first_line.startswith(('if ', 'if(')):
                else_idx = self._find_else(i, lines)
                if else_idx is not None and else_idx < n:
                    if else_idx not in self._adj.get(i, []):
                        self._adj.setdefault(i, []).append(else_idx)

    def _find_else(self, if_block_idx: int, lines: List[str]) -> Optional[int]:
        """查找与 if 块配对的 else 块。"""
        for j in range(if_block_idx + 1, len(self._blocks)):
            next_bb = self._blocks[j]
            if next_bb.lines and next_bb.lines[0].strip().startswith('else'):
                return j
        return None

    @property
    def blocks(self) -> List[UafBasicBlock]:
        return self._blocks

    @property
    def adjacency(self) -> Dict[int, List[int]]:
        return self._adj


__all__ = ['UafBasicBlock', 'UafCFGBuilder']
