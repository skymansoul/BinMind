"""
源码直读桥接 — 反编译器不可用或平台不支持时, 直接读取C源码
模拟反编译输出, 使FP过滤管线可端到端测试。仅适用于静态启发式分析。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional


def _extract_functions(source: str) -> Dict[str, str]:
    """从C源码提取函数体.

    用大括号平衡计数分割函数, 返回 {函数名: 函数体}.
    对静态分析已足够精确.
    """
    # 去除预处理指令和注释
    cleaned = re.sub(r'#.*', '', source)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    cleaned = re.sub(r'//.*', '', cleaned)

    funcs: Dict[str, str] = {}
    # 匹配函数定义: 返回类型 函数名(参数) {
    pattern = re.compile(
        r'(?:static\s+|inline\s+|extern\s+|__attribute__\s*\(\([^)]*\)\)\s*)*'
        r'(?:void|int|char|long|short|float|double|size_t|ssize_t|'
        r'unsigned\s+(?:int|char|long|short)|uint\d+_t|int\d+_t|'
        r'struct\s+\w+|\w+\s*\*)\s+'
        r'(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE,
    )

    for m in pattern.finditer(cleaned):
        name = m.group(1)
        start = m.end() - 1  # 指向 {
        # 大括号平衡计数
        depth = 0
        end = start
        for i in range(start, len(cleaned)):
            if cleaned[i] == '{':
                depth += 1
            elif cleaned[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > start:
            body = cleaned[start:end]
            funcs[name] = f"/* function {name} */\n{body}"

    # 如果没匹配到函数, 将整个源文件作为单个函数返回
    if not funcs:
        funcs["_whole_file"] = cleaned

    return funcs


def read_source_as_pseudocode(source_path: str) -> Dict[str, str]:
    """读取C源文件, 返回 {函数名: 伪代码} 格式.

    适配 decompile_all_functions 的返回签名.
    """
    path = Path(source_path)
    if not path.exists():
        return {}

    # 也尝试同名.c文件
    if path.suffix == '.exe':
        stem = path.stem
        # 在exe所在目录或源码目录找.c文件
        candidates = [
            path.with_suffix('.c'),
            path.parent / f"{stem}.c",
        ]
        for c in candidates:
            if c.exists():
                path = c
                break

    if path.suffix not in ('.c', '.h', '.txt'):
        return {}

    try:
        source = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return {}

    return _extract_functions(source)


def read_binary_with_fallback(
    binary_path: str, source_dir: Optional[str] = None
) -> Dict[str, str]:
    """尝试反编译, 失败则回退到源码读取.

    优先使用反编译器, 不可用时自动回退.
    """
    try:
        from core.decompiler import list_functions, decompile_function
        funcs = list_functions(binary_path)
        if funcs:
            result = {}
            for fname in funcs:
                d = decompile_function(binary_path, fname)
                if d and d.get("pseudocode"):
                    result[fname] = d["pseudocode"]
            if result:
                return result
    except Exception:
        pass

    return read_source_as_pseudocode(binary_path)
