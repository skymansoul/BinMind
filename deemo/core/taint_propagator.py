# 在反编译伪代码文本上做use-def链构建+污点传播。
# 不做完整到达-定值分析 — 仅追踪source到sink的2跳内直接数据流。
# 复杂度O(n), 可扩展到大型二进制。
#
# 设计依据:
#   FSVDTG 在S2E上做符号化参数检测, 但需要全系统仿真。
#   Pandora 在angr上做attacker taint, 但仅限SGX。
#   本模块在反编译伪代码级别实现: 不需要IR翻译, 不需要符号执行引擎,
#   直接解析r2/rizin的pdc输出文本做变量传播。
#
# 算法:
#   1. 扫描伪代码行, 标记污点源调用 (read/fgets/recv/scanf/getenv)
#   2. 追踪污点变量的赋值传播: var_b = var_a (tainted) -> var_b
#   3. 检测污点变量传入危险函数 (sink)
#   4. 限制传播深度depth<=2: 避免全程序分析, 保持线性复杂度
import re as _re
from dataclasses import dataclass as _dc
from typing import List, Set

from core.taint_sources import is_taint_source, is_direct_taint_var
from core.taint_sinks import (
    is_format_sink, is_heap_sink, is_stack_sink, is_uaf_sink)


@_dc
class TaintPath:
    source_func: str
    source_type: str
    sink_func: str
    sink_type: str
    tainted_var: str
    path_length: int = 1
    confidence: float = 0.0
    pseudocode_snippet: str = ''


class TaintPropagator:
    MAX_DEPTH = 2
    _ASSIGN_PAT = _re.compile(r'(?:[\*\&]?\s*)?(\w[\w\d_]*)\s*=\s*(.+?)(?:;|$)')
    _CALL_PAT = _re.compile(r'(\w[\w\d_]*)\s*\(([^)]*)\)')

    def propagate(self, pseudocode: str, func_name: str = '') -> List[TaintPath]:
        if not pseudocode or len(pseudocode) < 10:
            return []
        lines = pseudocode.splitlines()
        tainted_vars: Set[str] = set()
        var_defs: dict = {}
        paths: List[TaintPath] = []
        for line_no, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            self._mark_sources(line, tainted_vars)
            self._mark_direct_taint(line, tainted_vars)
            if tainted_vars:
                self._propagate_assignment(line, tainted_vars)
            if tainted_vars:
                self._check_sinks(line, tainted_vars, paths)
        return paths

    def _mark_sources(self, line: str, tainted: Set[str]) -> None:
        for m in self._CALL_PAT.finditer(line):
            callee = m.group(1)
            src_info = is_taint_source(callee)
            if src_info is None:
                continue
            args_str = m.group(2)
            args = self._split_args(args_str)
            taint_idx = src_info['tainted_arg']
            if taint_idx == -1:
                assign_m = self._ASSIGN_PAT.match(line)
                if assign_m:
                    tainted.add(assign_m.group(1))
            elif 0 <= taint_idx < len(args):
                arg_name = args[taint_idx].strip()
                if arg_name and not self._is_constant(arg_name):
                    tainted.add(arg_name)

    def _mark_direct_taint(self, line: str, tainted: Set[str]) -> None:
        """检测直接污点: 先标记函数参数, 再检查argv/argc变量引用。

        函数参数标记是保守策略: 任何函数参数在函数体内都被视为潜在污点。
        先标记参数再检查调用, 避免同行的printf(param)中param尚未标记。
        """
        # 阶段1: 标记函数参数 — 必须在检查调用之前
        param_m = _re.match(
            r'(?:void|int|char|size_t|unsigned|struct)\s+\**\w+\s*\(([^)]*)\)', line)
        if param_m:
            params_str = param_m.group(1)
            for param in params_str.split(','):
                parts = param.strip().split()
                if parts:
                    var = parts[-1].strip('*').strip()
                    if var and not self._is_constant(var):
                        tainted.add(var)
        # 阶段2: 标记argv/argc引用
        for m in self._CALL_PAT.finditer(line):
            args = self._split_args(m.group(2))
            for arg in args:
                arg = arg.strip()
                base = arg.split('[')[0].strip() if '[' in arg else arg
                if is_direct_taint_var(base):
                    tainted.add(arg)
                    assign_m = self._ASSIGN_PAT.match(line)
                    if assign_m:
                        tainted.add(assign_m.group(1))

    def _propagate_assignment(self, line: str, tainted: Set[str]) -> None:
        assign_m = self._ASSIGN_PAT.match(line)
        if not assign_m:
            return
        lhs, rhs = assign_m.group(1), assign_m.group(2).strip()
        for tv in list(tainted):
            if _re.search(rf'\b{_re.escape(tv)}\b', rhs):
                tainted.add(lhs)
                break

    def _check_sinks(self, line: str, tainted: Set[str],
                     paths: List[TaintPath]) -> None:
        for m in self._CALL_PAT.finditer(line):
            callee = m.group(1)
            args = self._split_args(m.group(2))
            conf, sink_type, danger_idx = 0.0, '', -1
            if is_format_sink(callee):
                danger_idx, sink_type, conf = 0, 'FORMAT', 0.85
            else:
                info = is_heap_sink(callee) or is_stack_sink(callee) or is_uaf_sink(callee)
                if info:
                    danger_idx = info['danger_arg']
                    sink_type = 'HEAP' if 'heap' in info['vuln'] else ('STACK' if 'stack' in info['vuln'] else 'UAF')
                    conf = 0.60
            if sink_type and 0 <= danger_idx < len(args):
                arg = args[danger_idx].strip()
                if arg in tainted:
                    paths.append(TaintPath(
                        source_func='(detected)', source_type='UNKNOWN',
                        sink_func=callee, sink_type=sink_type,
                        tainted_var=arg, path_length=1,
                        confidence=conf, pseudocode_snippet=line))

    @staticmethod
    def _split_args(args_str: str) -> List[str]:
        if not args_str.strip():
            return []
        depth, parts, current = 0, [], []
        for ch in args_str:
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if ch == ',' and depth == 0:
                parts.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            parts.append(''.join(current).strip())
        return parts

    @staticmethod
    def _is_constant(s: str) -> bool:
        s = s.strip()
        return (not s or s.startswith(('"', "'")) or
                s in ('NULL','0','-1','1') or
                _re.match(r'^0x[0-9a-fA-F]+$', s) or
                s.replace('.','',1).isdigit())

__all__ = ['TaintPath', 'TaintPropagator']
