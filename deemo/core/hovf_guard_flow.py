"""
HOVF 守卫支配值流.

误报的一类典型形态: 写入前存在安全守卫, 静态工具因路径合并丢失
守卫约束而误报. 例:
    if (n > cap) return;
    memcpy(buf, src, n);   // n <= cap, 实际安全
本模块提取函数内 `if (var <op> bound)` 形式的守卫, 计算守卫对变量的
区间约束, 并按文本支配关系绑定到写入语句. 只有位于写入之前且约束
同一变量的守卫才生效, 防止跨函数/跨块误绑定.

区间语义:
    if (n < K)   -> [lo, K-1]
    if (n <= K)  -> [lo, K]
    if (n > K)   -> [K+1, hi]  (逃逸守卫, 用于反向证明)
"""

import re
from typing import Dict, List, Optional

from core.hovf_types import ValueInterval

_GUARD_RE = re.compile(
    r'\bif\s*\(\s*([a-z_]\w*)\s*(<=|>=|<|>)\s*'
    r'((?:0x[0-9a-fA-F]+|\d+)|\w+)\s*\)')
_LOOP_RE = re.compile(
    r'\bfor\s*\(\s*[^;]*;\s*([a-z_]\w*)\s*(<=|>=|<|>)\s*'
    r'((?:0x[0-9a-fA-F]+|\d+)|\w+)\s*;')


class GuardFlow:
    """守卫区间收集与支配查询."""

    def __init__(self, ir: List[str]):
        self.ir = ir
        self._bounds: List[tuple] = []  # (line_idx, var, ValueInterval, op)
        self._scan()

    def _scan(self) -> None:
        for i, line in enumerate(self.ir):
            for m in _GUARD_RE.finditer(line):
                self._record(i, m.group(1), m.group(2), m.group(3))
            for m in _LOOP_RE.finditer(line):
                self._record(i, m.group(1), m.group(2), m.group(3))

    def _record(self, idx: int, var: str, op: str, bound: str) -> None:
        bound_val = self._const_or_none(bound)
        if bound_val is None:
            return
        if op == '<':
            iv = ValueInterval(0, max(0, bound_val - 1))
        elif op == '<=':
            iv = ValueInterval(0, bound_val)
        elif op == '>':
            iv = ValueInterval(bound_val + 1, 2**31 - 1)
        else:
            iv = ValueInterval(bound_val, 2**31 - 1)
        self._bounds.append((idx, var, iv, op))

    @staticmethod
    def _const_or_none(s: str) -> Optional[int]:
        try:
            return int(s, 0)
        except (ValueError, TypeError):
            return None

    def bound_for(self, var: str, write_idx: int) -> Optional[ValueInterval]:
        """返回支配写入点之前、约束 var 的最强守卫区间."""
        best: Optional[ValueInterval] = None
        for idx, gvar, iv, _op in self._bounds:
            if gvar != var or idx >= write_idx:
                continue
            if best is None or iv.hi < best.hi:
                best = iv
        return best

    def guard_lines_for(self, var: str, write_idx: int) -> List[int]:
        return [idx for idx, gvar, _iv, _op in self._bounds
                if gvar == var and idx < write_idx]


def extract_write_extent_var(line: str, mnemonic: str) -> Optional[str]:
    """提取写入范围变量: memcpy(p, s, n) 的 n, 数组写循环索引."""
    if mnemonic in ('memcpy', 'memmove', 'memset', 'strncpy'):
        m = re.search(r',\s*([a-z_]\w*)\s*\)\s*;?\s*$', line)
        if m:
            return m.group(1)
    return None
