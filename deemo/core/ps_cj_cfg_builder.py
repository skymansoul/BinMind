"""
路径敏感CFG构建器 — 从C源码/伪代码构建简化控制流图.

CJ求解器将所有约束收集到全局ConstraintSystem, 不区分控制流路径.
当guard条件 `if(n>100)exit` 和写入 `memcpy(buf,src,64)` 在不同分支时,
guard约束和写入约束被混合, 导致跨路径约束泄露.

PS-CJ在CFG路径上分离约束:
  1. 从源码提取基本块(顺序语句+分支/循环头)
  2. 构建CFG边(branch_taken, branch_not_taken, loop_back)
  3. 对每个(alloc,write)对枚举从alloc到write的有界路径集
  4. 每条路径携带独立的guard约束集

保守性: 路径数上限128 (可配置), 超限时不做路径敏感判定(回退到全局CJ).
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from core.cj_constraint_types import LinearConstraint
from core.ps_cj_cfg_types import (
    BasicBlock, CFGPath, extract_guard_from_cond,
)


class SimplifiedCFGBuilder:
    """从C源码行列表构建简化CFG.

    简化策略:
      - if/else/for/while/switch 行作为分支节点
      - 连续非控制流语句归入同一基本块
      - 分支节点的两个后继: taken(进入分支体)和not_taken(跳过分支体)
      - 循环体作为子图, 回边标记
    """

    _IF_RE = re.compile(
        r'\bif\s*\(\s*(.+?)\s*\)\s*\{?')
    _ELIF_RE = re.compile(
        r'\belse\s+if\s*\(\s*(.+?)\s*\)\s*\{?')
    _ELSE_RE = re.compile(r'\belse\s*\{?')
    _FOR_RE = re.compile(
        r'\bfor\s*\(\s*(?:\w+\s+)?(\w+)\s*=\s*(\d+)\s*;\s*'
        r'\w+\s*(<|<=)\s*(\w+|\d+)\s*;')
    _WHILE_RE = re.compile(r'\bwhile\s*\(\s*(.+?)\s*\)\s*\{?')
    _SWITCH_RE = re.compile(r'\bswitch\s*\(')
    _FUNC_DEF_RE = re.compile(
        r'\b(?:\w[\w]*\s+\*?\s*|\*\s*)?(\w[\w]*)\s*\([^)]*\)\s*\{')
    _GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|<|>=|<=|==|!=)\s*(\d+|0x[0-9a-fA-F]+)\s*\)')
    _RETURN_GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|<|>=|<=)\s*(\d+|0x[0-9a-fA-F]+)\s*\)\s*'
        r'\{?\s*(?:return|break|continue|exit|abort|goto)')
    _CLAMP_GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|<)\s*(\d+)\s*\)\s*\1\s*=\s*(\d+)')

    def __init__(self, max_paths: int = 128):
        self._max_paths = max_paths
        self._blocks: List[BasicBlock] = []
        self._line_to_block: Dict[int, int] = {}

    def build(self, lines: List[str]) -> List[BasicBlock]:
        """构建CFG, 返回基本块列表."""
        self._blocks = []
        self._line_to_block = {}
        current: Optional[BasicBlock] = None
        i = 0
        while i < len(lines):
            line_no = i + 1
            text = lines[i].strip()
            if not text or text.startswith(('//', '/*', '*/', '#')):
                i += 1
                continue
            ctrl = self._classify_line(text)
            if ctrl == 'func_def':
                if current:
                    self._blocks.append(current)
                current = BasicBlock(
                    start_line=line_no, end_line=line_no, stmts=[text])
                self._line_to_block[line_no] = len(self._blocks)
                i += 1
                continue
            if ctrl in ('if', 'elif', 'for', 'while', 'switch', 'else'):
                if current:
                    self._blocks.append(current)
                bb = BasicBlock(
                    start_line=line_no, end_line=line_no, stmts=[text])
                if ctrl == 'if' or ctrl == 'elif':
                    m = self._IF_RE.search(text) or self._ELIF_RE.search(text)
                    bb.branch_cond = m.group(1) if m else ""
                elif ctrl == 'for':
                    m = self._FOR_RE.search(text)
                    if m:
                        bb.is_loop_header = True
                        bb.loop_bound_var = m.group(4)
                        try:
                            bb.loop_bound_val = int(m.group(4), 0)
                        except ValueError:
                            pass
                elif ctrl == 'while':
                    m = self._WHILE_RE.search(text)
                    bb.branch_cond = m.group(1) if m else ""
                    bb.is_loop_header = True
                self._blocks.append(bb)
                self._line_to_block[line_no] = len(self._blocks) - 1
                current = None
                i += 1
                continue
            if ctrl == 'block_end':
                if current:
                    self._blocks.append(current)
                current = None
                i += 1
                continue
            if current is None:
                current = BasicBlock(
                    start_line=line_no, end_line=line_no, stmts=[text])
            else:
                current.end_line = line_no
                current.stmts.append(text)
            self._line_to_block[line_no] = (
                len(self._blocks) if current else len(self._blocks))
            i += 1
        if current:
            self._blocks.append(current)
        self._link_blocks()
        return self._blocks

    def _classify_line(self, text: str) -> str:
        """分类行类型."""
        if self._FUNC_DEF_RE.search(text) and not text.startswith(
                ('if', 'for', 'while', 'switch', 'else')):
            return 'func_def'
        if self._ELIF_RE.search(text):
            return 'elif'
        if self._IF_RE.search(text):
            return 'if'
        if self._FOR_RE.search(text):
            return 'for'
        if self._WHILE_RE.search(text):
            return 'while'
        if self._SWITCH_RE.search(text):
            return 'switch'
        if self._ELSE_RE.search(text):
            return 'else'
        if text.strip() == '}' or text.strip().endswith('}'):
            if '{' not in text:
                return 'block_end'
        return 'stmt'

    def _link_blocks(self) -> None:
        """连接基本块的跳边."""
        for i, bb in enumerate(self._blocks):
            if bb.is_loop_header or bb.branch_cond:
                bb.branch_taken_line = (
                    self._blocks[i + 1].start_line
                    if i + 1 < len(self._blocks) else 0)
                bb.branch_not_taken_line = self._find_next_after_branch(i)
            elif i + 1 < len(self._blocks):
                bb.branch_taken_line = self._blocks[i + 1].start_line
                bb.branch_not_taken_line = self._blocks[i + 1].start_line

    def _find_next_after_branch(self, block_idx: int) -> int:
        """找到分支体结束后的下一行(跳过分支体)."""
        depth = 0
        for j in range(block_idx + 1, len(self._blocks)):
            bb = self._blocks[j]
            for stmt in bb.stmts:
                depth += stmt.count('{') - stmt.count('}')
            if depth <= 0 and not bb.is_loop_header and not bb.branch_cond:
                return bb.start_line
        return 0

    def enumerate_paths(
        self, alloc_line: int, write_line: int,
    ) -> List[CFGPath]:
        """枚举从alloc_line到write_line的所有CFG路径."""
        if not self._blocks:
            return [CFGPath(description="empty CFG, single path")]

        start_block_idx = self._find_block_at_line(alloc_line)
        end_block_idx = self._find_block_at_line(write_line)
        if start_block_idx is None or end_block_idx is None:
            return [CFGPath(description="lines outside CFG")]
        if end_block_idx < start_block_idx:
            return [CFGPath(description="write before alloc")]

        paths: List[CFGPath] = []
        queue: List[Tuple[int, CFGPath]] = [(
            start_block_idx,
            CFGPath(blocks=[self._blocks[start_block_idx]],
                    description=f"alloc@{alloc_line}"))]

        while queue and len(paths) < self._max_paths:
            block_idx, path = queue.pop(0)
            if block_idx == end_block_idx:
                paths.append(path)
                continue
            if len(path.blocks) > 64:
                paths.append(path)
                continue
            bb = self._blocks[block_idx]
            successors = self._get_successors(bb, block_idx)
            for succ_idx, (taken, guard) in enumerate(successors):
                if succ_idx is None or succ_idx >= len(self._blocks):
                    continue
                if succ_idx in [self._blocks.index(b) for b in path.blocks[-8:]]:
                    continue
                new_path = CFGPath(
                    blocks=path.blocks + [self._blocks[succ_idx]],
                    guard_constraints=list(path.guard_constraints),
                    description=path.description)
                if guard:
                    new_path.guard_constraints.append(guard)
                queue.append((succ_idx, new_path))

        if not paths:
            paths.append(CFGPath(
                blocks=[self._blocks[start_block_idx]],
                description="single block path"))
        return paths

    def _find_block_at_line(self, line: int) -> Optional[int]:
        """找到包含指定行的基本块索引."""
        for i, bb in enumerate(self._blocks):
            if bb.start_line <= line <= bb.end_line:
                return i
        for i, bb in enumerate(self._blocks):
            if bb.start_line > line and i > 0:
                return i - 1
        return 0 if self._blocks else None

    def _get_successors(
        self, bb: BasicBlock, block_idx: int,
    ) -> List[Tuple[Optional[int], Optional[LinearConstraint]]]:
        """获取基本块的后继及对应的guard约束."""
        result: List[Tuple[Optional[int], Optional[LinearConstraint]]] = []
        if not bb.branch_cond and not bb.is_loop_header:
            if block_idx + 1 < len(self._blocks):
                result.append((block_idx + 1, None))
            return result
        taken_idx = self._find_block_at_line(bb.branch_taken_line) \
            if bb.branch_taken_line else None
        not_taken_idx = self._find_block_at_line(bb.branch_not_taken_line) \
            if bb.branch_not_taken_line else None
        taken_guard = extract_guard_from_cond(bb.branch_cond, taken=True)
        not_taken_guard = extract_guard_from_cond(bb.branch_cond, taken=False)
        if taken_idx is not None:
            result.append((taken_idx, taken_guard))
        if not_taken_idx is not None and not_taken_idx != taken_idx:
            result.append((not_taken_idx, not_taken_guard))
        elif not_taken_idx is None and block_idx + 1 < len(self._blocks):
            result.append((block_idx + 1, not_taken_guard))
        return result


__all__ = ['SimplifiedCFGBuilder']
