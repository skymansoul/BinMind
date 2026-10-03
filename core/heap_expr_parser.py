"""
堆相关表达式解析 — 将 size 表达式文本转换为 AffineInterval。

支持表达式:
  - 常量: 64, 0x40
  - 变量: n, size
  - 仿射: n*4, n*4+8, n*2-16
  - sizeof: sizeof(int) → 4

供 path_sensitive_vrf.py 和其他分析模块使用。
"""


import re
from typing import Optional

from .symbolic_range import AffineInterval


# 常见 type → sizeof 映射
_SIZEOF_MAP = {
    'sizeof(int)': 4, 'sizeof(long)': 8, 'sizeof(char)': 1,
    'sizeof(short)': 2, 'sizeof(float)': 4, 'sizeof(double)': 8,
    'sizeof(void*)': 8, 'sizeof(size_t)': 8, 'sizeof(unsigned)': 4,
}


def parse_size_expr(expr: str, env: dict = None) -> AffineInterval:
    """将 size 表达式文本解析为 AffineInterval。

    env: {变量名: AffineInterval} 用于变量查找。
    不支持的表达式返回 TOP (保守)。
    """
    if env is None:
        env = {}

    expr = expr.strip().replace(' ', '')
    if not expr:
        return AffineInterval.top()

    # 无界输入标记 (scanf/gets 等)
    if expr == '__unbounded__':
        return AffineInterval.top()

    # sizeof (先于变量/常量, 避免混淆)
    if expr in _SIZEOF_MAP:
        return AffineInterval.constant(_SIZEOF_MAP[expr])

    # 变量 (先于 _try_parse_int: 避免 'a'→0xA=10 的 hex 误解析)
    if expr in env:
        return env[expr]

    # 单变量 (未在 env 中) — 必须在 _try_parse_int 之前,
    # 否则 'a','b','c','d','e','f' 被当作十六进制数字
    if re.match(r'^[a-zA-Z_]\w*$', expr):
        return AffineInterval.symbolic(expr)

    # 仿射模式: n*C, C*n, n*C+D, n*C-D, n+D, n-D
    ai = _parse_affine(expr)
    if ai is not None:
        return ai

    # 纯常量 (含 0x 前缀十六进制)
    v = _try_parse_int(expr)
    if v is not None:
        return AffineInterval.constant(v)

    return AffineInterval.top()


def _try_parse_int(s: str) -> Optional[int]:
    """解析整数: 十进制 或 0x/0X 前缀的十六进制。"""
    try:
        return int(s)
    except ValueError:
        pass
    # 仅显式 0x/0X 前缀才做 hex 解析——避免 'a','deadbeef' 等变量名被误解析
    if s.lower().startswith('0x'):
        try:
            return int(s, 16)
        except ValueError:
            pass
    return None


def _parse_affine(expr: str) -> Optional[AffineInterval]:
    """解析仿射表达式: n*C, n*C+D, n*C-D, n+D, n-D。"""
    patterns = [
        (r'^([a-zA-Z_]\w*)\*(\d+)\+(\d+)$',
         lambda m: AffineInterval.symbolic(m.group(1)) * int(m.group(2))
                   + AffineInterval.constant(int(m.group(3)))),
        (r'^([a-zA-Z_]\w*)\*(\d+)-(\d+)$',
         lambda m: AffineInterval.symbolic(m.group(1)) * int(m.group(2))
                   + AffineInterval.constant(-int(m.group(3)))),
        (r'^([a-zA-Z_]\w*)\*(\d+)$',
         lambda m: AffineInterval.symbolic(m.group(1)) * int(m.group(2))),
        (r'^(\d+)\*([a-zA-Z_]\w*)$',
         lambda m: AffineInterval.symbolic(m.group(2)) * int(m.group(1))),
        (r'^([a-zA-Z_]\w*)\+(\d+)$',
         lambda m: AffineInterval.symbolic(m.group(1))
                   + AffineInterval.constant(int(m.group(2)))),
        (r'^([a-zA-Z_]\w*)-(\d+)$',
         lambda m: AffineInterval.symbolic(m.group(1))
                   + AffineInterval.constant(-int(m.group(2)))),
    ]
    for pat, fn in patterns:
        m = re.match(pat, expr)
        if m:
            return fn(m)
    return None


def split_args(args_str: str) -> list:
    """按逗号分割函数参数, 处理嵌套括号。"""
    parts = []
    depth = 0
    cur = ""
    for ch in args_str:
        if ch == '(':
            depth += 1
            cur += ch
        elif ch == ')':
            depth -= 1
            cur += ch
        elif ch == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def judge_overflow(alloc: AffineInterval, write: AffineInterval) -> tuple:
    """判断 (分配大小, 写入大小) 是否构成溢出, 返回 (verdict, overflow_bytes, confidence)。"""
    ac = alloc.const_val
    wc = write.const_val

    if ac is not None and wc is not None:
        if wc > ac:
            return ("DEFINITE", wc - ac, 0.95)
        return ("SAFE", 0, 0.0)

    if write.dominates(alloc):
        return ("DEFINITE", write.hi - alloc.hi, 0.85)

    if write.may_exceed(alloc):
        return ("POSSIBLE", max(0, write.hi - alloc.hi), 0.50)

    if alloc.is_top or write.is_top:
        return ("POSSIBLE", 0, 0.35)

    return ("SAFE", 0, 0.05)
