"""
PTASM 类型定义 — Pointer Temporal Automaton State Machine.
指针时序自动机: 形式化建模指针生命周期, 状态转移驱动的UAF判定.

状态机:
  LIVE ──free(p)──▶ FREED ──*p──▶ USE_AFTER_FREE (UAF!)
  FREED ──p=NULL──▶ NULLIFIED (安全)
  FREED ──p=malloc──▶ REASSIGNED → LIVE (安全)
  NULLIFIED ──p=malloc──▶ LIVE (正常重新分配)

保守性: 仅当所有路径证明指针已 NULLIFIED 或 REASSIGNED 才 FILTER.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class PtrState(Enum):
    """指针时序状态."""
    LIVE = "LIVE"               # 指向有效内存
    FREED = "FREED"             # 已释放, 悬空
    NULLIFIED = "NULLIFIED"     # 置空 (安全)
    REASSIGNED = "REASSIGNED"   # 重新分配 (安全, 等价于LIVE)
    USE_AFTER_FREE = "USE_AFTER_FREE"  # 释放后使用 (UAF!)


@dataclass
class PtrTransition:
    """一次状态转移记录."""
    ptr_name: str
    from_state: PtrState
    to_state: PtrState
    line_no: int
    operation: str            # free/malloc/nullify/use/alias
    detail: str = ""          # 额外信息 (如 alias目标)


@dataclass
class PtrInfo:
    """单个指针的时序追踪信息."""
    name: str
    state: PtrState = PtrState.LIVE
    alloc_line: int = 0
    free_line: int = 0
    transitions: List[PtrTransition] = field(default_factory=list)
    aliases: Set[str] = field(default_factory=set)  # 别名集合
    is_field: bool = False    # p->field 形式的字段访问
    parent_ptr: str = ""      # 若为字段, 记录父指针名


@dataclass
class PTASMResult:
    """PTASM 分析结果."""
    ptr_name: str
    verdict: PtrState              # 最终状态
    uaf_detected: bool = False
    safe: bool = False             # 可证明安全
    free_line: int = 0
    use_line: int = 0
    guarded: bool = False          # 是否有 NULL guard
    aliases_involved: List[str] = field(default_factory=list)
    reason: str = ""


# 操作识别正则

_FREE_RE = re.compile(r'\bfree\s*\(\s*(?:&?\*?)(\w+(?:\[[^\]]*\])?(?:->\w+)?)\s*\)')
_MALLOC_RE = re.compile(r'(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(?:malloc|calloc)\s*\(')
_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*(?:\([^)]*\))?\s*;')
_NULL_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*(?:NULL|nullptr|0)\s*;')
# 使用模式: *p / p-> / p[ — 显式解引用 (不含函数参数, 避免regex贪婪匹配吞噬参数内部)
_DEREF_RE = re.compile(
    r'(?:\*(\w+))|'                  # 组1: *p
    r'(?:(\w+)\s*->)|'               # 组2: p->
    r'(?:(\w+)\s*\[)'                # 组3: p[
)
# 排除: 控制流关键字 + C类型关键字 + 分配函数 — 这些不是数据使用
_CTX_KEYWORDS = {
    'if', 'while', 'for', 'return', 'free', 'sizeof', 'else',
    # C 类型关键字
    'char', 'int', 'void', 'long', 'short', 'float', 'double',
    'unsigned', 'signed', 'const', 'static', 'volatile', 'struct',
    'enum', 'union', 'typedef', 'extern', 'size_t', 'ssize_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'bool', 'true', 'false', 'NULL', 'nullptr',
    # 分配函数 (参数不是数据使用)
    'malloc', 'calloc', 'realloc',
}
_COND_RE = re.compile(r'if\s*\(\s*!?\s*(\w+)\s*\)')
# 函数调用识别 (用于提取参数中的指针)
_FUNC_CALL_RE = re.compile(r'(\w+)\s*\(')


def _extract_paren_content(s: str, paren_pos: int) -> str:
    """从 '(' 位置提取匹配括号内的内容."""
    if paren_pos >= len(s) or s[paren_pos] != '(':
        return ''
    depth = 0
    start = paren_pos
    for i in range(paren_pos, len(s)):
        ch = s[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return s[start + 1:i]
    return ''


def parse_line_operations(line: str) -> List[Tuple[str, Dict]]:
    """解析一行代码, 返回操作列表 [(op_type, info_dict), ...].

    op_type: 'free', 'malloc', 'nullify', 'assign', 'use', 'cond_guard'

    保守原则: 不确定是否使用时 → 视为使用 (宁可保留UAF候选项).

    v2: 分离显式解引用 (DEREF_RE) 与函数参数提取,
        避免 func(..., p->field) 中 regex 贪婪匹配吞噬 p-> 模式.
    """
    ops = []
    s = line.strip()
    if not s or s.startswith('//') or s.startswith('/*') or s.startswith('*'):
        return ops

    # free(p) — 优先级最高
    fm = _FREE_RE.search(s)
    if fm:
        ptr_name = fm.group(1)
        # 规范化: items[i] → items, req->payload → req (保留基名)
        ptr_name = re.sub(r'\[[^\]]*\]', '', ptr_name)
        ops.append(('free', {'ptr': ptr_name}))
        return ops  # 一行通常只有一个 free

    # p = malloc(...) — 重新分配
    mm = _MALLOC_RE.search(s)
    if mm:
        ops.append(('malloc', {'ptr': mm.group(1)}))
        return ops

    # p = NULL — 空指针化
    nm = _NULL_ASSIGN_RE.search(s)
    if nm:
        ops.append(('nullify', {'ptr': nm.group(1)}))
        return ops

    # p = q (别名传播)
    am = _ASSIGN_RE.search(s)
    if am and not s.startswith('if') and not s.startswith('while'):
        lhs, rhs = am.group(1), am.group(2)
        if not rhs.isdigit() and rhs not in ('NULL', 'nullptr'):
            ops.append(('assign', {'lhs': lhs, 'rhs': rhs}))

    # *p / p-> / p[ — 显式解引用 (先于函数参数, 避免 greedy match 问题)
    for dm in _DEREF_RE.finditer(s):
        used = None
        for g in dm.groups():
            if g and not g.isdigit():
                used = g
                break
        if used:
            ops.append(('use', {'ptr': used}))

    # func(..., ptr, ...) — 函数参数中的指针名 → 视为使用
    # 独立提取每个函数调用的参数, 不依赖单个 regex 贪婪匹配
    for cm in _FUNC_CALL_RE.finditer(s):
        caller = cm.group(1)
        if caller in _CTX_KEYWORDS:
            continue
        paren_pos = cm.end() - 1  # '(' 的位置
        args_str = _extract_paren_content(s, paren_pos)
        # 提取参数中的每个标识符作为 use
        arg_names = []
        if args_str:
            for vm in re.finditer(r'\b(\w+)\b', args_str):
                var = vm.group(1)
                if var not in _CTX_KEYWORDS and not var.isdigit():
                    ops.append(('use', {'ptr': var}))
                    arg_names.append(var)
        # 记录函数调用 (供引擎级 free-wrapper 检测)
        ops.append(('call', {'func': caller, 'args': arg_names}))

    # if (p) — NULL guard
    cm = _COND_RE.search(s)
    if cm:
        ops.append(('cond_guard', {'ptr': cm.group(1)}))

    return ops


__all__ = [
    'PtrState', 'PtrTransition', 'PtrInfo', 'PTASMResult',
    'parse_line_operations',
]
