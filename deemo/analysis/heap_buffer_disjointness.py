"""
堆/栈缓冲区正交性分析 — 区分堆分配和栈分配, 消除堆检测器对栈溢出的交叉误报.
核心问题: 基准数据显示 77.8% 的栈溢出样本被堆检测器标记 (交叉误报).
根本原因: malloc+memcpy 模式匹配未区分写入目标是堆还是栈.

方法:
  1. 识别栈缓冲区: char buf[N] / int arr[N] 局部变量声明
  2. 识别栈指针传递: &buf 作为 memcpy 目标 → 栈操作, 非堆
  3. 标记栈操作: 若 memcpy 目标解析为栈变量 → 不应触发堆告警
  4. 全局缓冲区识别: static/全局 char buf[N] → 既非堆也非栈, 单独分类

参考: NDSS 2023 "SUTURE" 的 heap/stack disambiguation, ISSTA 2024 "Heap Disjointness".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# 栈缓冲区识别
# char buf[SIZE]; int arr[N]; uint8_t data[LEN];
_RE_STACK_ARRAY = re.compile(
    r'\b(char|unsigned\s+char|uint8_t|int8_t|uint16_t|int16_t|'
    r'uint32_t|int32_t|uint64_t|int64_t|int|long|float|double|'
    r'short|size_t|ssize_t|wchar_t)\s+(\w+)\s*\[\s*(\d+|\w+)\s*\]')

# 结构体栈变量: struct foo bar; (非指针)
_RE_STACK_STRUCT = re.compile(
    r'\bstruct\s+\w+\s+(\w+)\s*;')

# 全局/静态缓冲区
_RE_GLOBAL_BUF = re.compile(
    r'^(?:static\s+)?(?:const\s+)?(?:char|unsigned\s+char|int|uint\w+_t)\s+'
    r'(\w+)\s*\[\s*(\d+|\w+)\s*\]\s*=\s*\{?')

# malloc 及其接收变量
_RE_MALLOC_PTR = re.compile(r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')

# memcpy 等写入函数的目标提取
_RE_WRITE_FUNC = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|read|fread|recv)\s*\(\s*([^,]+)')


@dataclass
class BufferInfo:
    """缓冲区描述."""
    name: str
    kind: str           # "heap" | "stack" | "global" | "param" | "unknown"
    size_expr: str = ""
    line_no: int = 0
    element_type: str = ""


class BufferDisjointness:
    """堆/栈/全局缓冲区正交分解.

    将函数内的缓冲区按来源分类, 用于 memcpy 点判定:
      - 目标是堆缓冲 → 堆分析管线处理
      - 目标是栈缓冲 → 栈分析管线处理, 堆管线跳过
      - 目标是全局缓冲 → 独立处理
    """

    def __init__(self):
        self._buffers: Dict[str, BufferInfo] = {}
        self._aliases: Dict[str, str] = {}  # var → canonical buffer name

    def clear(self):
        self._buffers.clear()
        self._aliases.clear()

    def scan_function(self, code: str) -> Dict[str, BufferInfo]:
        """扫描函数, 建立缓冲区分类, 返回 {变量名: BufferInfo} 映射。"""
        self.clear()
        lines = code.split('\n')

        for i, raw in enumerate(lines):
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            # 1. malloc/calloc/realloc → 堆
            mm = _RE_MALLOC_PTR.search(line)
            if mm:
                ptr, func = mm.group(1), mm.group(2)
                # 提取 size
                paren_start = line.index('(', mm.start())
                size_text = _match_paren(line, paren_start)
                # 对于 calloc(nmemb, size), 提取第二个参数
                if func.lower() == 'calloc':
                    parts = [p.strip() for p in size_text.split(',')]
                    size_text = parts[1] if len(parts) > 1 else size_text
                self._buffers[ptr] = BufferInfo(
                    name=ptr, kind='heap', size_expr=size_text,
                    line_no=i, element_type='void*')
                self._aliases[ptr] = ptr
                continue

            # 2. 栈数组声明
            sm = _RE_STACK_ARRAY.search(line)
            if sm:
                elem_type, name = sm.group(1), sm.group(2)
                size_expr = sm.group(3)
                if name not in self._buffers:
                    self._buffers[name] = BufferInfo(
                        name=name, kind='stack', size_expr=size_expr,
                        line_no=i, element_type=elem_type)
                    self._aliases[name] = name
                continue

            # 3. 全局/静态缓冲区
            gm = _RE_GLOBAL_BUF.search(line)
            if gm:
                name = gm.group(1)
                self._buffers[name] = BufferInfo(
                    name=name, kind='global', size_expr=gm.group(2),
                    line_no=i)
                self._aliases[name] = name
                continue

            # 4. 指针赋值: q = p (传递引用)
            assign_m = re.search(r'(\w+)\s*=\s*(\w+)\s*;', line)
            if assign_m and not line.startswith('if'):
                lhs, rhs = assign_m.group(1), assign_m.group(2)
                if rhs in self._aliases:
                    self._aliases[lhs] = self._aliases[rhs]
                continue

            # 5. q = p->field
            arrow_m = re.search(r'(\w+)\s*=\s*(\w+)\s*->\s*\w+\s*;', line)
            if arrow_m:
                lhs, base = arrow_m.group(1), arrow_m.group(2)
                if base in self._aliases:
                    self._aliases[lhs] = self._aliases[base]

        return dict(self._buffers)

    def classify_target(self, target_expr: str) -> str:
        """判定写入目标的缓冲区类型: heap/stack/global/param/unknown。"""
        root = _extract_var(target_expr)
        if root is None:
            return "unknown"
        if root in self._aliases:
            canonical = self._aliases[root]
            if canonical in self._buffers:
                return self._buffers[canonical].kind
        return "unknown"

    def is_heap_write(self, target_expr: str) -> bool:
        """写入目标是否确为堆缓冲区."""
        return self.classify_target(target_expr) == "heap"

    def is_stack_write(self, target_expr: str) -> bool:
        """写入目标是否为栈缓冲区 (应排除堆告警)."""
        return self.classify_target(target_expr) == "stack"


# 辅助

def _match_paren(text: str, open_pos: int) -> str:
    d, i = 1, open_pos + 1
    while i < len(text) and d > 0:
        if text[i] == '(':
            d += 1
        elif text[i] == ')':
            d -= 1
        i += 1
    return text[open_pos + 1:i - 1] if d == 0 else "?"


def _extract_var(expr: str) -> Optional[str]:
    """从表达式中提取变量名."""
    expr = expr.strip().lstrip('&').lstrip('*').strip()
    m = re.match(r'^(\w+)', expr)
    return m.group(1) if m else None


__all__ = ['BufferDisjointness', 'BufferInfo']
