"""
C 源码 → Ghidra 风格伪代码转换器: 将 malloc/calloc/realloc/memcpy/strcpy/memset 调用
重写为仿射边界验证 (Affine Bound Verification) 管线期望的格式 (变量名带类型、赋值显式), 并检测数组/指针手动写入, 插入合成 memcpy 标注。
"""

from __future__ import annotations

import re
from typing import Dict, List, Set


def convert(source: str) -> str:
    """主入口: C 源码 → 简化伪代码 (含合成 memcpy 标注)。"""
    lines = []

    # 阶段 0: 提取 #define 宏 (仅简单常量)
    macros: Dict[str, str] = {}
    for line in source.split('\n'):
        stripped = line.strip()
        m = re.match(r'#define\s+(\w+)\s+(.+?)(?:\s*//.*|\s*/\*.*)?$', stripped)
        if m:
            macros[m.group(1)] = m.group(2).strip()

    for line in source.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        if stripped.startswith('/*') or (stripped.startswith('*') and not stripped.startswith('*(')):
            continue
        if stripped.startswith('//'):
            continue
        if '//' in stripped:
            stripped = stripped[:stripped.index('//')]
        if not stripped or stripped in ('{', '}'):
            continue

        # 宏展开: 替换已知的 #define 常量
        for name, val in macros.items():
            stripped = re.sub(r'\b' + re.escape(name) + r'\b', val, stripped)

        stripped = _simplify_decl(stripped)
        stripped = re.sub(r'\(\s*(?:char|uint8_t|int16_t|void)\s*\*\s*\)\s*', '', stripped)
        lines.append(stripped)

    body = '\n'.join(lines)
    body = _extract_functions(body)

    # 后处理: 插入合成 memcpy 标注
    body = _inject_synthetic_writes(body)
    return body


def _simplify_decl(line: str) -> str:
    """简化类型声明: char *buf → buf = ; const int n → n = ..."""
    line = re.sub(r'\b(?:static|const|extern|volatile|register|inline)\s+', '', line)
    line = re.sub(
        r'(?:unsigned\s+)?(?:char|int|short|long|size_t|uint\d+_t|int\d+_t|float|double)\s*\*?\s*(\w+)\s*=\s*',
        r'\1 = ', line)
    return line


def _extract_functions(code: str) -> str:
    """提取函数体: 去除函数签名行。"""
    func_start = re.search(r'\w+\s+\w+\s*\([^)]*\)\s*\{?', code)
    if func_start:
        brace_pos = code.find('{', func_start.end())
        if brace_pos >= 0:
            return code[brace_pos:]
    return code


# 合成写入标注 ────────────────────────────────────────

_RE_MALLOC = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')

_RE_PTR_ALIAS = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(\w+)\s*;')

_RE_ARRAY_WRITE = re.compile(
    r'(\w[\w.\->]*)\[(?:[^\]]+)\]\s*=\s*')

_RE_PTR_DEREF_WRITE = re.compile(
    r'\*(\w[\w.\->]*)\s*=\s*')

_RE_PTR_DEREF_INC = re.compile(
    r'\*(\w[\w.\->]*)\+\+\s*=\s*')


def _inject_synthetic_writes(body: str) -> str:
    """检测手动数组/指针写入, 为堆变量插入合成 memcpy 标注。流程: 收集堆变量 (malloc/calloc/realloc 目标), 构建别名映射 (p = buf → p 为 buf 别名), 对含堆变量写入的行插入标注。"""
    heap_vars: Set[str] = set()
    alias_map: Dict[str, str] = {}

    # 阶段 1: 收集堆变量
    for line in body.split('\n'):
        m = _RE_MALLOC.search(line)
        if m:
            heap_vars.add(m.group(1))

    # 阶段 1b: 构建别名映射
    for line in body.split('\n'):
        m = _RE_PTR_ALIAS.search(line)
        if m:
            alias, target = m.group(1), m.group(2)
            if target in heap_vars:
                alias_map[alias] = target

    # 扩展堆变量集合: 别名也算
    extended_vars = heap_vars | set(alias_map.keys())

    if not extended_vars:
        return body

    # 阶段 2: 为堆变量写入插入合成 memcpy 调用
    out_lines = []
    for line in body.split('\n'):
        injected = False

        # 检测数组写入 buf[idx] = val
        for var in extended_vars:
            pattern = re.compile(
                r'\b' + re.escape(var) + r'\s*\[[^\]]+\]\s*=')
            if pattern.search(line):
                target_var = alias_map.get(var, var)
                out_lines.append(
                    f'memcpy({target_var}, __src__, __unbounded__);'
                    f'  /* SYNTH: 手动数组写入 */')
                injected = True
                break

        if not injected:
            # 检测指针解引用写入 *ptr = val 或 *ptr++ = val
            for var in extended_vars:
                pattern = re.compile(
                    r'\*\s*' + re.escape(var) + r'\s*(?:\+\+)?\s*=')
                if pattern.search(line):
                    target_var = alias_map.get(var, var)
                    out_lines.append(
                        f'memcpy({target_var}, __src__, __unbounded__);'
                        f'  /* SYNTH: 手动指针写入 */')
                    injected = True
                    break

        out_lines.append(line)

    return '\n'.join(out_lines)


def simplify_for_detection(source: str) -> str:
    """便捷入口: 产生仿射边界验证 (Affine Bound Verification) 管线可直接分析的伪代码。"""
    return convert(source)
