"""
格式化字符串参数流分析 —— 追踪格式化参数在调用链中的位置映射。

printf 有多个变体 (fprintf/sprintf/snprintf/dprintf/syslog),
每个的格式化参数位置不同:
  printf(fmt, ...)     → fmt 在 arg[0]
  fprintf(fp, fmt, ...)→ fmt 在 arg[1]
  snprintf(buf, n, fmt, ...) → fmt 在 arg[2]
  syslog(prio, fmt, ...) → fmt 在 arg[1]

若调用链中存在位置偏移: wrapper(fmt, ...) → printf(fmt, ...)
则 wrapper 的 arg[0] 应对应 printf 的 arg[0]。
但若 wrapper(const_char, fmt) → printf(fmt), 则 wrapper 的 arg[1]
对应 printf 的 arg[0]。本模块追踪这种跨调用边界的位置映射。

方法: 对每个调用边 (caller → callee), 记录调用方实参位置到
被调方形参位置的映射。沿调用链累积映射。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# 各格式化函数的 fmt 参数位置 (0-indexed)
_FMT_ARG_POS: Dict[str, int] = {
    'printf': 0, 'fprintf': 1, 'dprintf': 1,
    'sprintf': 1, 'snprintf': 2,
    'vprintf': 0, 'vfprintf': 1, 'vsprintf': 1, 'vsnprintf': 2,
    'syslog': 1, 'vsyslog': 1,
    'err': 0, 'errx': 0, 'warn': 0, 'warnx': 0,
    '__printf_chk': 1, '__fprintf_chk': 2,
}


@dataclass
class ArgMapping:
    """一条调用边的参数位置映射。"""
    caller: str
    callee: str
    mapping: Dict[int, int]  # caller_arg_pos → callee_arg_pos
    call_site: str = ""


@dataclass
class FmtArgTrace:
    """格式化参数从顶层调用到实际 printf 的完整追踪。"""
    entry_func: str         # 顶层函数 (通常是用户输入入口)
    fmt_var_name: str       # 格式化参数变量名
    call_chain: List[str]   # [entry, ..., printf_func]
    entry_arg_pos: int      # 在 entry_func 的参数位置
    final_fmt_pos: int      # 在最终 printf 中的参数位置
    confidence: float


class FormatStringArgFlow:
    """
    格式化参数流追踪器。

    维护调用边图, 沿边追踪格式化参数的位置变化。
    """

    def __init__(self):
        self._mappings: List[ArgMapping] = []

    def add_mapping(self, caller: str, callee: str,
                    arg_map: Dict[int, int]) -> None:
        """注册一条调用边的参数位置映射。"""
        self._mappings.append(ArgMapping(caller, callee, arg_map))

    def trace_fmt_arg(
        self, entry_func: str, entry_arg: int, var_name: str = "fmt",
    ) -> List[FmtArgTrace]:
        """
        从 entry_func 的 entry_arg 开始, 沿调用链追踪到 printf。

        使用递归深搜, 最大深度 5。
        """
        traces: List[FmtArgTrace] = []

        def dfs(current_func: str, current_pos: int,
                chain: List[str], depth: int) -> None:
            if depth > 5 or len(chain) > 8:
                return
            chain.append(current_func)

            # 检查当前函数是否为 printf 系函数
            fmt_pos = _FMT_ARG_POS.get(current_func)
            if fmt_pos is not None and fmt_pos == current_pos:
                traces.append(FmtArgTrace(
                    entry_func=entry_func,
                    fmt_var_name=var_name,
                    call_chain=list(chain),
                    entry_arg_pos=entry_arg,
                    final_fmt_pos=fmt_pos,
                    confidence=0.85 - depth * 0.08,
                ))
                chain.pop()
                return

            # 继续沿调用链搜索
            for mapping in self._mappings:
                if mapping.callee == current_func:
                    new_pos = mapping.mapping.get(current_pos)
                    if new_pos is not None:
                        dfs(mapping.caller, new_pos, chain, depth + 1)

            chain.pop()

        dfs(entry_func, entry_arg, [], 0)
        return traces


__all__ = ['ArgMapping', 'FmtArgTrace', 'FormatStringArgFlow']
