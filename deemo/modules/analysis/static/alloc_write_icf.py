"""分配-写关联-ICF: 跨函数调用帧传播.

与原 分配-写关联 的本质区别:
  原 分配-写关联 在 call 指令处终止追踪, size 寄存器来源遇 call 即返回 ROOT_UNKNOWN.
  分配-写关联-ICF 通过 InterprocSummary 构建的跨函数摘要继续追踪参数来源,
  使跨函数的 size 传播可被追踪.
"""
import re
from typing import Dict, List, Optional, Tuple


class InterproceduralCofluenceTracker:
    """跨函数调用帧追踪器, 扩展 分配-写关联 的单函数后向 def-use 到跨函数场景."""

    def __init__(self, summaries: dict = None):
        # summaries: {func_name: {out_reg: (param_idx, const_offset)}}
        self._summaries = summaries or {}
        self._call_depth = 0
        self._max_depth = 3

    def add_summary(self, func_name: str, param_to_size_reg: dict):
        """注册函数摘要: 参数索引 → size 寄存器映射."""
        self._summaries[func_name] = param_to_size_reg

    def trace_across_call(self, call_func: str, call_args: list,
                          size_reg: str) -> Tuple[str, str, int, int, float]:
        """跨函数追踪 size 寄存器来源.

        返回 (root_kind, root_value, coeff, const, confidence).
        root_kind: 'inter_param' / 'inter_ret' / 'unknown'
        """
        if self._call_depth >= self._max_depth:
            return ('unknown', '', 1, 0, 0.0)

        summary = self._summaries.get(call_func)
        if not summary:
            return ('unknown', '', 1, 0, 0.0)

        # 如果 size_reg 在被调函数中来自参数 i
        if size_reg in summary:
            param_idx, const_offset = summary[size_reg]
            if param_idx < len(call_args):
                arg = call_args[param_idx].strip()
                # 实参是常量
                if re.match(r'\d+$', arg) or re.match(r'0x[0-9a-fA-F]+$', arg):
                    val = int(arg, 0)
                    return ('inter_param', str(val), 1, const_offset, 0.85)
                # 实参是变量 — 递归追踪
                self._call_depth += 1
                kind, val, coeff, const, conf = self.trace_across_call(
                    arg, call_args, size_reg)
                self._call_depth -= 1
                if kind != 'unknown':
                    return ('inter_param', val, coeff, const + const_offset, conf * 0.9)
                # 无法继续追踪, 返回参数名
                return ('inter_param', arg, 1, const_offset, 0.70)

        # 检查返回值 (rax) 是否绑定到 alloc
        if 'rax' in summary and summary['rax'].get('alloc_return'):
            param_idx = summary['rax']['alloc_return']
            if param_idx < len(call_args):
                arg = call_args[param_idx].strip()
                return ('inter_ret', arg, 1, 0, 0.75)

        return ('unknown', '', 1, 0, 0.0)

    def analyze_findings(self, pseudocode: str,
                         findings: list) -> list:
        """对已有堆 findings 做跨函数追踪增强."""
        if not pseudocode or not findings:
            return findings

        # 解析伪代码中的函数调用
        calls = []
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*\(([^)]*)\)', line)
            if m:
                dst, func, args_str = m.groups()
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                calls.append((lineno, dst, func, args))
            # 无返回值的调用
            m2 = re.match(r'(\w+)\s*\(([^)]*)\)', line)
            if m2 and not m:
                func, args_str = m2.groups()
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                calls.append((lineno, None, func, args))

        # 为每个 heap finding 尝试跨函数追踪
        for f in findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            desc = f.get('description', '')
            # 检查是否有跨函数调用
            for lineno, dst, func, args in calls:
                if func in self._summaries:
                    # 尝试追踪 size 参数
                    root_kind, root_val, coeff, const, conf = (
                        self.trace_across_call(func, args, 'rdi'))
                    if root_kind != 'unknown':
                        f['cross_func_provenance'] = {
                            'func': func,
                            'root_kind': root_kind,
                            'root_value': root_val,
                            'coeff': coeff,
                            'const': const,
                            'confidence': conf,
                            'call_line': lineno,
                        }
                        break

        return findings
