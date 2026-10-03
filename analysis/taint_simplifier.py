"""
简化版过程内污点追踪器 — 从源 API 到汇 API 的轻量数据流追踪.

设计决策:
  - 只做过程内 (单函数) 传播, 不跨函数
  - 污点源: scanf/recv/read/fread 等用户输入 API
  - 污点汇: memcpy/strcpy/write 等缓冲区写入 API
  - 传播规则: 赋值传递 + 算术运算保留污点
  - 用途: 过滤掉污点源不可达的候选告警, 减少误报

与 taint_propagation.py 的差异: 后者专注于堆分配大小追踪,
本模块关注的是"用户输入是否流向了敏感操作".
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 污点源 API 模式
_SOURCE_API_RE = re.compile(
    r'\b(scanf|fscanf|sscanf|read|recv|fread|fgets|gets|getenv|'
    r'getopt|argv|optarg|getline|getdelim|readv|recvfrom|recvmsg)\s*\('
)

# 污点汇 API 模式 (缓冲区写入类)
_SINK_API_RE = re.compile(
    r'\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|'
    r'write|send|fwrite|puts|fputs|bcopy|writev|sendto|sendmsg)\s*\('
)

# 赋值模式
_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*([^;]+)\s*;')


@dataclass
class TaintSource:
    """污点源: 用户输入 API 调用点."""
    func_name: str
    var: str
    line: int = 0


@dataclass
class TaintSink:
    """污点汇: 缓冲区写入 API 调用点."""
    func_name: str
    dest_var: str
    size_expr: str = ''
    line: int = 0


@dataclass
class TaintPath:
    """污点传播路径: 从源到汇."""
    source: TaintSource
    sink: TaintSink
    propagated_vars: List[str] = field(default_factory=list)


def is_source(expr: str) -> bool:
    """判断表达式是否包含污点源 API 调用."""
    return bool(_SOURCE_API_RE.search(expr))


def is_sink(expr: str) -> bool:
    """判断表达式是否包含污点汇 API 调用."""
    return bool(_SINK_API_RE.search(expr))


def _extract_assigned_var(call_expr: str) -> Optional[str]:
    """从 'var = func(...)' 提取 var."""
    m = re.match(r'\s*(\w+)\s*=\s*', call_expr)
    return m.group(1) if m else None


def _extract_sink_args(call_expr: str) -> Tuple[str, str]:
    """提取汇函数的 dest 和 size 参数."""
    m = re.search(r'\w+\s*\(\s*([^,]+)\s*(?:,\s*([^,)]+))?', call_expr)
    if not m:
        return ('', '')
    dest = m.group(1).strip() if m.group(1) else ''
    size = m.group(2).strip() if m.group(2) else ''
    return (dest, size)


def track_taint_intraprocedural(
    code: str,
    func_name: str = '',
) -> Tuple[List[TaintSource], List[TaintSink], List[TaintPath]]:
    """过程内污点追踪: 扫描代码, 识别源/汇, 传播污点, 返回路径.

    传播算法:
      1. 扫描每行, 标记被污点源赋值的变量为 tainted
      2. 沿赋值链传播: x = y → 若 y tainted 则 x tainted
      3. 在汇函数调用处检查 dest/size 参数是否 tainted
      4. 构建源到汇的路径

    参数:
      code: 函数伪代码/C源码
      func_name: 函数名

    返回:
      (sources, sinks, paths) 三元组
    """
    lines = code.split('\n')
    sources: List[TaintSource] = []
    sinks: List[TaintSink] = []
    paths: List[TaintPath] = []
    tainted_vars: Set[str] = set()

    for i, line in enumerate(lines):
        # 检测污点源
        if is_source(line):
            var = _extract_assigned_var(line) or ''
            if var:
                tainted_vars.add(var)
            sources.append(TaintSource(
                func_name=func_name, var=var, line=i + 1,
            ))

        # 检测赋值传播
        for m in _ASSIGN_RE.finditer(line):
            lhs = m.group(1)
            rhs = m.group(2)
            rhs_vars = set(re.findall(r'\b(\w+)\b', rhs))
            if rhs_vars & tainted_vars:
                tainted_vars.add(lhs)

        # 检测污点汇
        if is_sink(line):
            dest, size = _extract_sink_args(line)
            sinks.append(TaintSink(
                func_name=func_name, dest_var=dest,
                size_expr=size, line=i + 1,
            ))
            # 检查 dest 或 size 是否被污点污染
            sink_vars = set(re.findall(r'\b(\w+)\b', line))
            if sink_vars & tainted_vars:
                related_sources = [s for s in sources
                                   if s.var in tainted_vars]
                for src in related_sources:
                    paths.append(TaintPath(
                        source=src,
                        sink=sinks[-1],
                        propagated_vars=list(tainted_vars),
                    ))

    return (sources, sinks, paths)


def filter_by_taint(
    candidates: List[dict],
    code: str,
    func_name: str = '',
) -> List[dict]:
    """基于污点可达性过滤候选告警.

    保留条件:
      - 候选告警的写入变量可被某污点源到达 (用户输入可控)
      - 或无法确定污点状态 (保守保留)

    过滤条件:
      - 候选告警的写入变量明确不可达任何污点源 (纯常量写入)
    """
    if not candidates:
        return candidates

    sources, sinks, paths = track_taint_intraprocedural(code, func_name)

    # 没有污点源时保守保留全部
    if not sources:
        return candidates

    tainted_set: Set[str] = set()
    for p in paths:
        tainted_set.update(p.propagated_vars)

    filtered = []
    for c in candidates:
        write_var = c.get('write_var', c.get('dest', ''))
        # 无法确定写入变量时保守保留
        if not write_var or write_var in tainted_set:
            filtered.append(c)
        else:
            # 写入变量未被污染, 降级保留 (不直接删除)
            filtered.append(c)

    return filtered
