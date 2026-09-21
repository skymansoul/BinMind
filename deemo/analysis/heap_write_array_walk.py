"""
数组索引游走写检测. 目标模式:

  char* user_args = malloc(size_needed);
  size_t write_idx = 0;
  for (i = 0; i < arg_len; i++) {
      user_args[write_idx++] = user_input_shellarg[i];
  }
  user_args[write_idx] = '\0';   # write_idx >= size_needed 时越界

与指针游走写 (*p++) 等价, 但通过数组下标表达, 常见于
`buf[idx++]` 形式.

判定路径与指针游走一致:
  1. 循环上界可定: max_idx = bound * per_iter 与分配大小比较
  2. 上界不可定但分配含 strlen: 比较索引增量系数与分配增长系数
"""

import re
from typing import List, Optional, Tuple

from analysis.heap_write_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import _is_comment_or_empty
from analysis.heap_write_walk_verify import (
    _find_strlen_var, asymptotic_check,
)

# arr[var++] = ...  或 arr[var] = ...; var++ 后递增
_ARR_POSTINC_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\+\+\s*\]\s*=')
_ARR_INDEX_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=')
_INDEX_INC_RE = re.compile(
    r'(\w[\w]*)\s*\+\+\s*;')
_LOOP_CONST_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\d+)\s*;')
_LOOP_VAR_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;')


def collect_array_walks(alloc_vars: set, lines: List[str],
                        valid_lines: Optional[set] = None
                        ) -> List[Tuple[int, str, str, int]]:
    """收集数组索引游走写: (write_line, arr, idx_var, loop_bound).

    loop_bound=-1 表示上界未知 (交由渐近判定).
    """
    out: List[Tuple[int, str, str, int]] = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = _ARR_POSTINC_WRITE_RE.search(text)
        arr = idx = None
        if m and m.group(1) in alloc_vars:
            arr, idx = m.group(1), m.group(2)
        if arr is None:
            m2 = _ARR_INDEX_WRITE_RE.search(text)
            if m2 and m2.group(1) in alloc_vars and \
                    _has_index_increment(m2.group(2), i, lines):
                arr, idx = m2.group(1), m2.group(2)
        if arr is None:
            continue
        bound = _find_loop_bound(i, lines)
        out.append((i, arr, idx, bound))
    return out


def _has_index_increment(idx_var: str, write_line: int,
                         lines: List[str]) -> bool:
    """检查索引变量在写入附近是否有自增 (arr[idx]=...; idx++)."""
    for j in range(write_line, min(len(lines) + 1, write_line + 8)):
        t = lines[j - 1].strip()
        if _is_comment_or_empty(t):
            continue
        if _INDEX_INC_RE.search(t):
            return True
        # 新循环或函数结束则停止
        if re.search(r'\b(for|while|if|return)\b', t):
            break
    return False


def _find_loop_bound(write_line: int, lines: List[str]) -> int:
    """从包围循环提取上界; -1=未知."""
    for i in range(max(0, write_line - 8), write_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        cm = _LOOP_CONST_RE.search(t)
        if cm:
            return int(cm.group(2))
        vm = _LOOP_VAR_RE.search(t)
        if vm:
            # 变量上界: 尝试解析常量赋值
            n = _bound_var(vm.group(2), lines, i)
            if n > 0:
                return n
            return -1
    return -1


def _bound_var(name: str, lines: List[str], line: int) -> int:
    """解析循环上界变量为常量."""
    for j in range(line - 1, -1, -1):
        t = lines[j].strip()
        m = re.search(rf'\b{name}\s*=\s*(\d+)\s*;', t)
        if m:
            return int(m.group(1))
        m = re.search(rf'\b{name}\s*=\s*strlen\s*\(', t)
        if m:
            return -1
    return -1


def verify_array_walk(alloc: ExtAlloc, line: int, idx_var: str,
                      loop_bound: int, lines: List[str]
                      ) -> Optional[ExtResult]:
    """验证数组索引游走写是否越界.

    max_write = loop_bound * per_iter (per_iter 保守取 1)
    alloc 为字节分配时, 与 usable 比较.
    上界未知或分配大小为变量时, 尝试渐近判定:
    分配表达式可回溯到 strlen (如 size_needed = strlen(x)+1),
    索引随输入长度增长, 比较索引增量系数与分配增长系数.
    """
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if loop_bound > 0 and usable > 0:
        write_end = loop_bound + 1  # +1 含终止符写入
        if write_end > usable:
            return ExtResult(
                verdict="VULN", alloc_line=alloc.line, write_line=line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=write_end, overflow_bytes=write_end - usable,
                confidence=0.80, kind="array_walk",
                reason=("'%s': malloc(%d) usable=%d, arr[%s] walks "
                        "bound=%d (+1 term) → %dB > usable"
                        % (alloc.var, alloc.size_const, usable, idx_var,
                           loop_bound, write_end)))
        return ExtResult(
            verdict="SAFE", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=write_end, confidence=0.88, kind="array_walk",
            reason="'%s': arr[%s] walk bound=%d <= usable %d"
                   % (alloc.var, idx_var, loop_bound, usable))
    # 分配大小为变量或上界未知: 渐近判定
    # 分配表达式含 strlen 或可回溯到 strlen (size_needed = strlen(x)+1)
    if _find_strlen_var(alloc.size_expr, lines, alloc.line) is not None:
        w = _WalkProxy(idx_var, alloc.size_expr, alloc.line, line)
        r = asymptotic_check(w, alloc, lines)
        if r:
            return r
    return None


class _WalkProxy:
    """为 asymptotic_check 提供 WalkWrite 形状的轻量代理."""

    def __init__(self, idx_var: str, size_expr: str, alloc_line: int,
                 write_line: int) -> None:
        self.is_str_loop = True
        # 转义处理 (如 sudo 的 \\ 分支) 可使单迭代双写, 保守取 2
        self.max_steps_per_iter = 2
        self.driver = idx_var
        self.ptr = idx_var
        self.base = ""
        self.loop_line = alloc_line
        self.write_line = write_line
        self.loop_bound = -1
        self.trailing_write = 1
        self.elem_size = 1


__all__ = [
    'collect_array_walks', 'verify_array_walk',
    '_has_index_increment', '_find_loop_bound',
]
