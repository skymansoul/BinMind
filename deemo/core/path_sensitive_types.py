"""路径敏感堆验证的数据结构与通用解析 helper。"""

import re
from dataclasses import dataclass

from .symbolic_range import AffineInterval, PathCondition


@dataclass
class AllocSite:
    """malloc 调用点记录, 含路径上下文。"""
    var_name: str; size_expr: str; size_range: AffineInterval
    path_cond: PathCondition; block_id: int; lineno: int; func_name: str = ""


@dataclass
class WriteSite:
    """堆写入点记录, 含路径上下文。"""
    var_name: str; write_size: AffineInterval; write_call: str
    path_cond: PathCondition; block_id: int; lineno: int


@dataclass
class VerifiedFinding:
    """路径敏感验证后的最终发现。"""
    alloc_site: AllocSite; write_site: WriteSite; verdict: str
    overflow_bytes: int; confidence: float; description: str


_RE_COMMENTS = re.compile(r'//[^\n]*|/\*.*?\*/', re.DOTALL)


def strip_comments(code: str) -> str:
    """剥离 C 风格注释, 避免注释中的 malloc/memcpy 文字被误解析为分配点。"""
    return _RE_COMMENTS.sub('', code)


def extract_paren_args(text: str, start: int) -> str:
    """从 text[start] 的 '(' 之后提取括号内参数 (处理嵌套括号)。"""
    depth, i = 1, start
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    return text[start:i-1] if depth == 0 else text[start:]
