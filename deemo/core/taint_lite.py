"""
轻量级二进制污点传播 — 基于 def-use 链的静态污点追踪.

不依赖 angr 符号执行或 capstone 完整模拟.
在反编译代码上进行基于文本模式的污点传播:
  1. 标记"源" (source) — 用户可控输入点 (recv/read/fgets/argv).
  2. 通过赋值语句追踪污点传播.
  3. 检测污点数据到达"汇" (sink) — 危险函数调用.

方法: 纯文本级数据流分析.
  - 扫描反编译代码, 识别赋值语句 (var = expr).
  - 若 expr 含污点变量, 则 var 被标记为污点.
  - 追踪通过函数参数和返回值的跨函数传播.

理论依据:
  - Arbiter (Vadayath et al., USENIX 2022): 静态-动态桥接.
    本实现取其"轻量级静态污点筛选可疑点"的思想,
    使用文本模式替代符号执行, 大幅降低计算开销.

局限: 不处理间接内存访问 (指针算术), 不跟踪跨循环的
复杂数据流. 适用场景为: 从数千个候选调用中快速筛选
10-50个高风险点, 供后续符号执行或人工审查.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# 污点源: 用户可控的输入函数
_TAINT_SOURCES = {
    'recv', 'recvfrom', 'read', 'fread', 'fgets', 'gets',
    'scanf', '__isoc99_scanf', 'fscanf',
    'argv', 'argc',
    'getenv', 'getline',
}

# 危险汇点: 污点数据到达这些函数则报告
_TAINT_SINKS = {
    'memcpy': ['length'],           # 长度参数可控 → 堆/栈溢出
    'memmove': ['length'],
    'strcpy': ['src'],              # 源字符串可控 → 溢出
    'strcat': ['src'],
    'sprintf': ['format'],          # 格式字符串可控 → 格式化字符串漏洞
    'snprintf': ['format', 'length'],
    'printf': ['format'],
    'fprintf': ['format'],
    'free': ['ptr'],                # 指针可控 → 任意释放
    'system': ['command'],          # 命令可控 → 命令注入
    'execve': ['path'],
    'execl': ['path'],
    'mprotect': ['addr', 'prot'],   # 内存保护可控
}

# 赋值模式: var = expr
_ASSIGN_PAT = re.compile(r'(\w[\w.]*)\s*=\s*(.+?)(?:;|$)')
# 函数调用模式: func(args)
_CALL_PAT = re.compile(r'(\w+)\s*\(([^)]*)\)')
# 变量使用模式 (在表达式中)
_VAR_USE_PAT = re.compile(r'\b(\w+)\b')


class TaintState:
    """函数级别的污点状态."""
    def __init__(self, func_name: str):
        self.func = func_name
        self.tainted: Set[str] = set()          # 被污染的变量
        self.warnings: List[Dict] = []           # 检测到的污点违规


def analyze_taint(decompiled: str, func_name: str) -> TaintState:
    """在反编译代码上执行污点分析.

    Args:
        decompiled: 反编译代码文本
        func_name: 函数名

    Returns:
        TaintState 包含污染变量集和警告列表
    """
    state = TaintState(func_name)
    lines = decompiled.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#'):
            continue

        # 阶段1: 检测污点源
        for src in _TAINT_SOURCES:
            if src in stripped:
                # 提取赋值目标 (如 read(fd, buf, len) → buf 污染)
                m = _CALL_PAT.search(stripped)
                if m and m.group(1) in _TAINT_SOURCES:
                    args = _parse_args(m.group(2))
                    if src in ('read', 'recv', 'fread', 'fgets', 'gets', 'recvfrom'):
                        if len(args) >= 2:
                            state.tainted.add(args[1].strip())
                            _log.debug(f'  [taint source] {args[1].strip()} <- {src}')
                    elif src in ('scanf', 'fscanf', '__isoc99_scanf'):
                        for a in args[1:]:  # format后面的参数
                            if a.strip().startswith('&'):
                                state.tainted.add(a.strip()[1:])
                            else:
                                state.tainted.add(a.strip())

        # 阶段2: 污点传播
        m = _ASSIGN_PAT.search(stripped)
        if m:
            lhs = m.group(1).strip()
            rhs = m.group(2).strip()
            rhs_vars = _VAR_USE_PAT.findall(rhs)
            for v in rhs_vars:
                if v in state.tainted:
                    state.tainted.add(lhs)
                    break

        # 阶段3: 汇点检测
        m = _CALL_PAT.search(stripped)
        if m:
            called = m.group(1)
            if called in _TAINT_SINKS:
                args = _parse_args(m.group(2))
                for arg_idx, arg in enumerate(args):
                    arg_vars = _VAR_USE_PAT.findall(arg.strip())
                    for v in arg_vars:
                        if v in state.tainted:
                            sink_info = _TAINT_SINKS[called]
                            param_name = sink_info[arg_idx] if arg_idx < len(sink_info) else f'arg{arg_idx}'
                            if param_name in sink_info:
                                state.warnings.append({
                                    'function': func_name,
                                    'sink': called,
                                    'param': param_name,
                                    'tainted_var': v,
                                    'line': stripped.strip()[:120],
                                    'severity': 'high' if called in ('system', 'execve') else 'medium',
                                })

    return state


def _parse_args(args_str: str) -> List[str]:
    """简单参数解析, 按逗号分割但保留括号内内容."""
    parts = []
    depth = 0
    current = ''
    for ch in args_str:
        if ch == '(':
            depth += 1
            current += ch
        elif ch == ')':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current)
    return parts
