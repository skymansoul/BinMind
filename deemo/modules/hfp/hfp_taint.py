"""
轻量污点传播引擎 — 堆溢出误报抑制的第一阶段。

决策逻辑:
  堆溢出检测的误报主要来自"写大小超过分配大小"的机械比较, 未区分
  size 的来源。若 write_size 与 alloc_size 同源于同一外部输入变量,
  且无缩放差异, 则 memcpy/memset 的"溢出"多为等价复制, 而非漏洞。
  本模块对 size 表达式做单向污点分析: 标记输入源, 沿赋值/算术传播,
  输出每个变量的污点等级与来源表达式, 供三态判定引擎消歧。

不处理: 函数调用间的参数传递 (由 hfp_engine 的调用点展开处理)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

# 污点等级: 越高越可能受外部输入控制
class TaintLevel(IntEnum):
    UNKNOWN = 0      # 未识别
    CONSTANT = 1     # 编译期常量
    INTERNAL = 2     # 内部派生 (循环变量/局部计算)
    EXTERNAL = 3     # 外部输入 (argv/read/recv/scanf/env)
    MIXED = 4        # 混合来源


# 外部输入源函数 — 返回值进入数据流即视为受控
INPUT_SINKS: Tuple[str, ...] = (
    'read', 'recv', 'recvfrom', 'scanf', 'fscanf', 'sscanf',
    'fgets', 'getenv', 'getc', 'fread', 'readlink', 'atoi',
    'strtol', 'strtoul', 'strlen', 'syscall',
)


@dataclass
class TaintFact:
    """单个变量的污点事实."""
    var: str
    level: TaintLevel = TaintLevel.UNKNOWN
    src_expr: str = ""          # 来源表达式 (常量/输入调用)
    const_val: Optional[int] = None  # CONSTANT 时的值
    scale: int = 1              # 相对来源的缩放系数


@dataclass
class TaintState:
    """程序点的污点状态 — 变量 → 事实."""
    facts: Dict[str, TaintFact] = field(default_factory=dict)

    def get(self, var: str) -> Optional[TaintFact]:
        return self.facts.get(var)

    def set(self, fact: TaintFact) -> None:
        self.facts[fact.var] = fact


# 赋值模式: dst = src
_RE_ASSIGN = re.compile(r'\b(\w+)\s*=\s*(\w+)\s*$')
# 算术: dst = a + b / dst = a * b / dst = a + N
_RE_ARITH = re.compile(r'\b(\w+)\s*=\s*(\w+)\s*([+*\-])\s*(\w+|\d+)\s*$')
# 常量赋值
_RE_CONST = re.compile(r'\b(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*$')
# 输入调用: dst = read(fd, buf, n)
_RE_INPUT_CALL = re.compile(r'\b(\w+)\s*=\s*(\w+)\s*\(')
# sizeof 展开: dst = sizeof(T) 或 n * sizeof(T)
_RE_SIZEOF = re.compile(r'sizeof\s*\(\s*(\w+)\s*\)')


def _is_input_call(func: str) -> bool:
    return func in INPUT_SINKS


def classify_line(line: str, state: TaintState) -> List[TaintFact]:
    """对单条 IR 行做污点传播, 返回新增/更新的事实列表."""
    line = line.strip()
    if not line:
        return []

    m = _RE_INPUT_CALL.match(line)
    if m:
        dst, func = m.group(1), m.group(2)
        if _is_input_call(func):
            return [TaintFact(
                var=dst, level=TaintLevel.EXTERNAL, src_expr=func)]
    # 优先级: 常量赋值先于通用赋值 (避免把常量误判为内部变量)
    m = _RE_CONST.search(line)
    if m:
        var, val = m.group(1), m.group(2)
        try:
            cval = int(val, 0)
        except ValueError:
            return []
        return [TaintFact(
            var=var, level=TaintLevel.CONSTANT, const_val=cval,
            src_expr=str(cval))]

    m = _RE_ASSIGN.search(line)
    if m:
        dst, src = m.group(1), m.group(2)
        src_fact = state.get(src)
        if src_fact is not None:
            return [TaintFact(
                var=dst, level=src_fact.level,
                src_expr=src_fact.src_expr, const_val=src_fact.const_val,
                scale=src_fact.scale)]
        return []

    m = _RE_ARITH.search(line)
    if m:
        dst, a, op, b = m.group(1), m.group(2), m.group(3), m.group(4)
        fa = state.get(a)
        if fa is None:
            return []
        b_const = None
        try:
            b_const = int(b, 0)
        except ValueError:
            pass
        if op == '*':
            if b_const is not None:
                return [TaintFact(
                    var=dst, level=fa.level, src_expr=fa.src_expr,
                    const_val=None, scale=fa.scale * b_const)]
            fb = state.get(b)
            if fb is not None and fb.level == TaintLevel.CONSTANT:
                return [TaintFact(
                    var=dst, level=fa.level, src_expr=fa.src_expr,
                    const_val=None, scale=fa.scale * (fb.const_val or 1))]
            return [TaintFact(var=dst, level=TaintLevel.MIXED)]
        # + / - : 常量偏移不改变污点等级
        return [TaintFact(
            var=dst, level=fa.level, src_expr=fa.src_expr,
            const_val=None, scale=fa.scale)]

    return []


def run_taint(ir_lines: List[str]) -> TaintState:
    """对整个 IR 序列执行前向污点传播."""
    state = TaintState()
    for line in ir_lines:
        facts = classify_line(line, state)
        for f in facts:
            state.set(f)
    return state


def taint_of_var(state: TaintState, var: str) -> TaintFact:
    """查询变量污点, 缺省返回 UNKNOWN."""
    fact = state.get(var)
    if fact is not None:
        return fact
    return TaintFact(var=var, level=TaintLevel.UNKNOWN)


def same_source(a: Optional[TaintFact], b: Optional[TaintFact]) -> bool:
    """判断两个变量是否同源 (用于 write_size vs alloc_size 同源检测)."""
    if a is None or b is None:
        return False
    if a.src_expr and b.src_expr and a.src_expr == b.src_expr:
        return True
    return False
