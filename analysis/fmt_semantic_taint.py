"""
格式说明符语义污点传播 (Format Specifier Semantic Taint Propagation) — 将二进制污点 (tainted/not) 升级为格式说明符语义级别.

格式说明符语义污点传播 (Format Specifier Semantic Taint Propagation) 语义分类 (5级):
  SEM_CLEAN     (0): 常量字符串, 无格式说明符 → 绝对安全
  SEM_CONST_FMT (1): 常量但有格式说明符 → 有意图的格式化, 安全
  SEM_USER_SAFE (2): 用户输入但被清理 (%% 替换等) → 安全
  SEM_USER_READ (3): 用户输入, 可能含 %s/%x/%p → 信息泄露
  SEM_USER_WRITE(4): 用户输入, 可能含 %n/%hn → 代码执行 (最高风险)

Phase 2-5 管线 + 格式调用发现 → 已提取至 analysis.fmt_semantic_phases.
"""


import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple

# Phase 2-5 管线方法 → 已提取
from analysis.fmt_semantic_phases import (
    scan_taint_sources, propagate_taint,
    detect_sanitizers, classify_semantics,
    discover_fmt_calls,
    _INPUT_ARRAYS,
)


class SemClass(IntEnum):
    """格式字符串语义安全等级 (越低越安全)."""
    SEM_CLEAN = 0       # 常量, 无格式说明符
    SEM_CONST_FMT = 1   # 常量, 含格式说明符 (有意为之)
    SEM_USER_SAFE = 2   # 用户输入, 但已被清理
    SEM_USER_READ = 3   # 用户输入, 可能含 %s/%x (信息泄露)
    SEM_USER_WRITE = 4  # 用户输入, 可能含 %n (代码执行)

    def is_vuln(self) -> bool:
        return self >= SemClass.SEM_USER_READ


@dataclass
class FstpVerdict:
    """格式说明符语义污点传播 (Format Specifier Semantic Taint Propagation) 验证结果."""
    call_line: int
    func_name: str
    fmt_arg: str
    sem_class: SemClass = SemClass.SEM_CLEAN
    is_cwe134: bool = False
    confidence: float = 0.0
    reason: str = ""
    has_sanitizer: bool = False
    sanitizer_line: int = -1
    is_cross_func: bool = False
    wrapper_chain: List[str] = field(default_factory=list)


class FmtSemanticTaintPropagator:
    """格式说明符语义感知的污点传播器."""

    def __init__(self):
        self.const_strings: Dict[str, str] = {}       # var → 常量值
        self.tainted_vars: Dict[str, SemClass] = {}   # var → 语义类别
        self.sanitized_vars: Dict[str, int] = {}      # var → 清理行号
        self.wrapper_map: Dict[str, int] = {}         # func → fmt_arg_pos

    def clear(self):
        """清除所有状态 (用于批量分析)."""
        self.const_strings.clear()
        self.tainted_vars.clear()
        self.sanitized_vars.clear()
        self.wrapper_map.clear()

    def analyze(self, pseudocode: str,
                call_sites: Optional[List[Tuple[int, str, str]]] = None,
                ) -> Tuple[List[FstpVerdict], Dict]:
        """分析伪代码中的格式字符串风险."""
        lines = pseudocode.split('\n')
        self._phase0_discover_wrappers(lines)
        self._phase1_scan_constants(lines)

        # Phase 2-5 → 委托给 fmt_semantic_phases
        scan_taint_sources(lines, self.tainted_vars, SemClass.SEM_USER_WRITE)
        propagate_taint(lines, self.tainted_vars)
        detect_sanitizers(lines, self.tainted_vars, self.sanitized_vars,
                          SemClass.SEM_USER_SAFE)
        classify_semantics(lines, self.tainted_vars,
                          SemClass.SEM_USER_WRITE, SemClass.SEM_USER_READ)

        if call_sites is None:
            call_sites = discover_fmt_calls(lines)

        verdicts = []
        for cl, func, arg in call_sites:
            v = self._verify_single(cl, func, arg, lines)
            verdicts.append(v)

        stats = {
            'total_calls': len(call_sites),
            'sem_clean': sum(1 for v in verdicts
                            if v.sem_class == SemClass.SEM_CLEAN),
            'sem_const_fmt': sum(1 for v in verdicts
                                if v.sem_class == SemClass.SEM_CONST_FMT),
            'sem_user_safe': sum(1 for v in verdicts
                                if v.sem_class == SemClass.SEM_USER_SAFE),
            'sem_user_read': sum(1 for v in verdicts
                                if v.sem_class == SemClass.SEM_USER_READ),
            'sem_user_write': sum(1 for v in verdicts
                                if v.sem_class == SemClass.SEM_USER_WRITE),
            'cwe134_confirmed': sum(1 for v in verdicts if v.is_cwe134),
            'sanitized': sum(1 for v in verdicts if v.has_sanitizer),
        }
        return verdicts, stats

    # Phase 0: 发现包装函数

    def _phase0_discover_wrappers(self, lines: List[str]):
        """检测包装函数: my_log(fmt, ...) → printf(fmt, ...)."""
        pass  # 跨函数分析由上层处理

    # Phase 1: 常量字符串扫描

    def _phase1_scan_constants(self, lines: List[str]):
        """扫描编译时常量字符串赋值."""
        for line in lines:
            stripped = line.strip()
            # char *fmt = "..."
            m = re.match(r'(?:const\s+)?char\s*\*\s*(\w+)\s*=\s*"([^"]*)"',
                        stripped)
            if m:
                self.const_strings[m.group(1)] = m.group(2)
                continue
            # fmt = "..."
            m = re.match(r'(\w+)\s*=\s*"([^"]*)"\s*;?', stripped)
            if m:
                self.const_strings[m.group(1)] = m.group(2)

    # 验证单个调用

    def _verify_single(self, line_no: int, func: str, arg: str,
                       lines: List[str]) -> FstpVerdict:
        """验证单个格式字符串调用的语义类别."""
        v = FstpVerdict(call_line=line_no, func_name=func, fmt_arg=arg)

        # 0. 直接输入数组? (argv[i], environ[i])
        for arr in _INPUT_ARRAYS:
            if re.search(rf'\b{arr}\s*\[', arg):
                v.sem_class = SemClass.SEM_USER_WRITE
                v.is_cwe134 = True
                v.confidence = 0.90
                v.reason = f'用户输入数组 {arg} 直接作为格式参数 — CWE-134'
                return v

        # 1. 常量字符串?
        if arg in self.const_strings:
            const_val = self.const_strings[arg]
            if '%' in const_val:
                v.sem_class = SemClass.SEM_CONST_FMT
                v.confidence = 0.98
                v.reason = f'编译时常量格式字符串: "{const_val[:40]}"'
                v.is_cwe134 = False
            else:
                v.sem_class = SemClass.SEM_CLEAN
                v.confidence = 0.99
                v.reason = f'编译时常量纯字符串: "{const_val[:40]}"'
                v.is_cwe134 = False
            return v

        # 2. 被清理?
        if arg in self.sanitized_vars:
            v.sem_class = SemClass.SEM_USER_SAFE
            v.has_sanitizer = True
            v.sanitizer_line = self.sanitized_vars[arg]
            v.confidence = 0.85
            v.reason = f'用户输入已被清理 (行 {v.sanitizer_line})'
            v.is_cwe134 = False
            return v

        # 3. 用户输入?
        if arg in self.tainted_vars:
            sc = self.tainted_vars[arg]
            v.sem_class = sc
            if sc == SemClass.SEM_USER_WRITE:
                v.is_cwe134 = True
                v.confidence = 0.90
                v.reason = '用户输入直接作为格式字符串, 可能含%n — CWE-134'
            elif sc == SemClass.SEM_USER_READ:
                v.is_cwe134 = True
                v.confidence = 0.78
                v.reason = '用户输入作为格式字符串, 可能含%s/%x — 信息泄露'
            else:
                v.is_cwe134 = False
                v.confidence = 0.85
                v.reason = '用户输入但已被分类为安全'
            return v

        # 4. 无法确定
        v.sem_class = SemClass.SEM_CLEAN
        v.confidence = 0.40
        v.reason = '未找到用户输入源 — 可能来自内部变量'
        v.is_cwe134 = False
        return v


__all__ = ['SemClass', 'FstpVerdict', 'FmtSemanticTaintPropagator']
