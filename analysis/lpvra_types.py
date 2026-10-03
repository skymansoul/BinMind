"""
包含: 数据类(Verdict/AllocInfo/WriteInfo/HeapVerdict/LPVRAResult),
      正则模式 + CFG辅助(_is_ctrl/_parse_cond).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from analysis.interval_domain import Interval


class Verdict(Enum):
    SAFE = "SAFE"
    OVERFLOW = "OVERFLOW"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class AllocInfo:
    """堆分配点信息."""
    line_no: int
    var: str
    func: str
    size_var: str = ""
    size_const: int = 0


@dataclass
class WriteInfo:
    """堆写入点信息."""
    line_no: int
    var: str
    offset: int
    size: int
    op: str
    size_var: str = ""  # v2: 变量大小的memcpy (如 memcpy(buf, src, n))


@dataclass
class HeapVerdict:
    """单个 alloc-write 对的判定结果."""
    alloc_var: str
    alloc_line: int
    alloc_size_iv: Interval
    write_var: str
    write_line: int
    write_offset: int
    write_size: int
    effective_boundary: int
    verdict: Verdict
    safe_paths: int = 0
    total_paths: int = 0
    reason: str = ""


@dataclass
class LPVRAResult:
    """LPVRA引擎的完整分析结果."""
    allocs: List[AllocInfo] = field(default_factory=list)
    writes: List[WriteInfo] = field(default_factory=list)
    verdicts: List[HeapVerdict] = field(default_factory=list)
    total_paths_explored: int = 0
    paths_filtered: int = 0


# 简化CFG构建 (C源码 -> 基本块) — 正则模式 + 辅助函数

_CTRL_KW = {'if', 'else', 'for', 'while', 'do', 'switch', 'case',
            'return', 'goto', 'break', 'continue'}

_ALLOC_RE = re.compile(
    r'(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(malloc|calloc|realloc)\s*\(',
    re.IGNORECASE)

_WRITE_RE = re.compile(
    r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf|scanf|fread|recv|read)',
    re.IGNORECASE)

_COND_RE = re.compile(
    r'(?:if|while|for)\s*\(\s*(\w[\w]*)\s*(<|<=|>|>=|==|!=)\s*(\d+|\w[\w]*)')

_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*(\d+|\w[\w]*)\s*;')

_MALLOC_ASSIGN_RE = re.compile(
    r'(?:\w+\s*\*?\s*)?(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(malloc|calloc|realloc)\s*\(\s*(\d+|\w[\w]*)',
    re.IGNORECASE)

_ARITH_RE = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*([+\-])\s*(\d+)\s*;')

_ARRAY_STORE_RE = re.compile(r'(\w[\w]*)\s*\[\s*(\d+|\w[\w]*)\s*\]\s*=')


def _is_ctrl(line: str) -> bool:
    """判断一行是否为控制流语句."""
    s = line.strip()
    return any(s.startswith(kw) for kw in _CTRL_KW) or s.startswith('}')


def _parse_cond(line: str) -> Optional[Tuple[str, str, int]]:
    """解析条件: (变量, 操作符, 常数值) 或 None."""
    m = _COND_RE.search(line)
    if m:
        try:
            return (m.group(1), m.group(2), int(m.group(3)))
        except ValueError:
            pass
    return None


def build_simple_cfg(lines: List[str]
                     ) -> Tuple[List[Dict], Dict[int, List[int]]]:
    """构建简化CFG — 被LPVRA和TemporalPathVerifier共享.

    控制结构识别依赖 _is_ctrl, 仅处理 if-else 分支.
    返回 (blocks, adj) 其中 blocks=[{id, start, end, stmts}, ...].
    """
    blocks: List[Dict] = []
    bb_start, bid = 0, 0
    for i, line in enumerate(lines):
        if _is_ctrl(line) and i > bb_start:
            blocks.append({'id': bid, 'start': bb_start,
                           'end': i - 1, 'stmts': lines[bb_start:i]})
            bid += 1
            bb_start = i
    if bb_start < len(lines):
        blocks.append({'id': bid, 'start': bb_start,
                       'end': len(lines) - 1, 'stmts': lines[bb_start:]})

    adj: Dict[int, List[int]] = {}
    for i, b in enumerate(blocks):
        succs: List[int] = []
        if i + 1 < len(blocks):
            succs.append(blocks[i + 1]['id'])
        first_stmt = (b['stmts'][0].strip() if b['stmts'] else '')
        if first_stmt.startswith('if'):
            else_idx = -1
            for j in range(i + 1, len(blocks)):
                fj = (blocks[j]['stmts'][0].strip()
                      if blocks[j]['stmts'] else '')
                if fj.startswith('} else') or fj.startswith('else'):
                    else_idx = j
                    break
            if else_idx >= 0:
                for j in range(else_idx + 1, len(blocks)):
                    fj = (blocks[j]['stmts'][0].strip()
                          if blocks[j]['stmts'] else '')
                    if fj.startswith('}'):
                        succs.append(blocks[j]['id'])
                        break
        adj[b['id']] = succs
    return blocks, adj
