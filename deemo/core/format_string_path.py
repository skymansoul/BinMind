# 格式化字符串路径敏感分析 —— 区分"用户可控的buf"与"调用者传入的const char* fmt"。
# 核心误报源: 静态模式匹配将printf(fmt_param)标记为漏洞, 但fmt_param可能来自
# 上层调用者的常数字符串(如log_wrapper("error: %s", msg))。
# 本模块沿调用图反向追踪格式参数来源, 判定是否来自用户输入。
# 方法论: 基于静态污点传播的单变量简化。

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FormatArgTrace:
    func_name: str
    format_func: str
    arg_name: str
    source_type: str     # "constant"/"parameter"/"local_input"/"unknown"
    source_detail: str = ""
    cross_function: bool = False
    confidence: float = 0.0


class FormatStringPathAnalyzer:

    def analyze_call(self, disasm_lines: List[str], call_idx: int,
                      func_name: str = "",
                      caller_disasm: List[str] = None) -> FormatArgTrace:
        if call_idx < 0 or call_idx >= len(disasm_lines):
            return FormatArgTrace(func_name, "", "", "unknown", "", False, 0.0)
        line = disasm_lines[call_idx].strip().lower()
        fmt_func = _extract_fmt(line)
        if not fmt_func:
            return FormatArgTrace(func_name, "", "", "unknown", "", False, 0.0)
        arg_name, st, detail = self._trace(disasm_lines, call_idx)
        cross = False
        if st == "parameter" and caller_disasm:
            cross = True
            arg_name, st, detail = self._trace_caller(caller_disasm, func_name, fmt_func)
        conf = 0.95 if st == "constant" else (0.70 if st == "local_input" else (0.45 if st == "parameter" else 0.20))
        return FormatArgTrace(func_name, fmt_func, arg_name, st, detail, cross, round(conf, 3))

    def _trace(self, lines, idx):
        for i in range(idx - 1, max(-1, idx - 15), -1):
            l = lines[i].strip().lower()
            if not l or l.startswith(';'): continue
            m = re.search(r'mov\s+(?:rdi|edi),\s*(0x[0-9a-fA-F]+|\d+)', l)
            if m: return ("immediate", "constant", f"常量{hex(int(m.group(1),0))}")
            m = re.search(r'lea\s+(?:rdi|edi),\s*\[rip', l)
            if m: return ("global_str", "constant", "全局常量字符串")
            m = re.search(r'mov\s+(?:rdi|edi),\s*(\w+)', l)
            if m:
                r = m.group(1)
                if r in ('rbp','rsp','rsi','rdx'): return (r, "parameter", f"来自{r}(形参)")
                return (r, "local_input", f"来自{r}(局部)")
            m = re.search(r'mov\s+(?:rdi|edi),\s*\[(\w+)\]', l)
            if m: return (f"[{m.group(1)}]", "local_input", f"内存[{m.group(1)}]")
        return ("unknown", "unknown", "无法追溯")

    def _trace_caller(self, caller_lines, callee, fmt_func):
        for i, l in enumerate(caller_lines):
            if callee in l.lower() and 'call' in l.lower():
                for j in range(i-1, max(-1,i-10), -1):
                    p = caller_lines[j].strip().lower()
                    if 'lea' in p and 'rip' in p: return ("arg", "constant", f"调用者全局常量→{callee}→{fmt_func}")
                    m = re.search(r'mov\s+(?:rdi|edi),\s*(0x[0-9a-fA-F]+|\d+)', p)
                    if m: return ("arg", "constant", f"调用者常量→{callee}→{fmt_func}")
                return ("arg", "local_input", f"调用者变量→{callee}→{fmt_func}")
        return ("arg", "parameter", "调用者参数(未定位)")

def _extract_fmt(line):
    for fn in ('printf','fprintf','sprintf','snprintf','dprintf','syslog'):
        if fn in line: return fn
    return None

__all__ = ["FormatArgTrace", "FormatStringPathAnalyzer"]
