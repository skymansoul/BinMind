"""
C源码预处理 — 多行语句合并 + 结构体成员→父变量解析.
供 c_semantic_analyzer 使用, 解决单行正则无法匹配跨行语句的问题.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple


def join_multiline_statements(lines: List[str]) -> List[str]:
    """将多行C语句合并为单行.

    合并规则:
      - 行以 = 结尾 → 与下行合并
      - 行包含 (, 但 ) 未闭合 → 与下行合并
      - 类型声明跨行: Type *var =\n    (Type*)malloc(...);
    """
    joined: List[str] = []
    buf = ""
    paren_depth = 0

    for line in lines:
        s = line.strip()
        if not s:
            if buf:
                buf += " "
            continue

        # 去除行内注释
        s = re.sub(r'/\*.*?\*/', '', s).strip()
        if not s or s.startswith('//'):
            if buf:
                buf += " "
            continue

        if buf:
            buf += s
        else:
            buf = s

        # 跟踪括号深度
        for ch in s:
            if ch == '(':
                paren_depth += 1
            elif ch == ')':
                paren_depth -= 1

        # 检查是否需要继续合并
        needs_cont = False
        if paren_depth > 0:
            needs_cont = True  # 括号未闭合
        elif s.rstrip().endswith('='):
            needs_cont = True  # 赋值右端跨行
        elif re.match(
            r'^(?:const\s+)?(?:unsigned\s+)?\w[\w\s*]+\*?\s*\w+\s*$', s):
            # 类型声明行 (无初始化器): "HeartbeatResponse *resp"
            needs_cont = True

        if not needs_cont:
            joined.append(buf)
            buf = ""
        else:
            buf += " "  # 合并时加空格分隔

    if buf:
        joined.append(buf)

    return joined


def build_field_parent_map(lines: List[str]) -> Dict[str, str]:
    """构建结构体成员→父变量映射.

    识别模式:
      Type *p = malloc(...)  → p->field 的父变量为 p
      struct Type var;       → var.field 的父变量为 var
    对指针访问: resp->payload → {'payload': 'resp'}

    匹配写入目标时: 若 write_var='resp->payload', 查表得 parent='resp',
    与 alloc_var='resp' 匹配.
    """
    field_to_parent: Dict[str, str] = {}
    # Type *var = ... 或 Type var[N] 声明
    decl_re = re.compile(
        r'(?:struct\s+)?\w[\w\s*]+\s+(\w+)\s*(?:\[[^\]]*\])?\s*[=;]')

    for line in lines:
        s = line.strip()
        # 分配语句: var = malloc/calloc(...)
        m = re.search(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(', s)
        if m:
            var = m.group(1)
            # 预注册: 该var的->field成员都映射回var
            field_to_parent[var] = var  # 自身映射

        # 类型声明
        m = decl_re.search(s)
        if m:
            var = m.group(1)
            if var not in field_to_parent:
                field_to_parent[var] = var

    return field_to_parent


def resolve_write_target(write_var: str,
                         field_parent: Dict[str, str]) -> str:
    """将写入目标解析为父变量名.

    'resp->payload' → 'resp' (查 field_parent)
    'buf' → 'buf' (普通变量)
    'buf+offset' → 'buf'
    """
    # 去除偏移: buf + offset → buf
    write_var = re.sub(r'\s*\+.*$', '', write_var).strip()

    # 结构体指针成员: var->field
    m = re.match(r'(\w+)->(\w+)', write_var)
    if m:
        parent = m.group(1)
        # 返回父变量 (field_parent 中 self-mapped)
        return parent

    return write_var


def preprocess_source(source: str) -> Tuple[List[str], Dict[str, str]]:
    """完整预处理: 合并多行 + 构建父变量映射.

    Returns: (合并后的行列表, field→parent 映射).
    """
    raw_lines = source.splitlines()
    joined = join_multiline_statements(raw_lines)
    field_map = build_field_parent_map(joined)
    return joined, field_map


__all__ = [
    'join_multiline_statements', 'build_field_parent_map',
    'resolve_write_target', 'preprocess_source',
]
