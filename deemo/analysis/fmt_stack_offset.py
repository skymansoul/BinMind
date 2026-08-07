"""
格式字符串栈偏移推断 — 无DWARF信息下, 通过调用约定+IR模式推断格式化参数栈位置.

方法: 调用约定分析 → IR模式匹配 (call printf前的push/mov) → 常量格式字符串检测.
仅使用反编译输出+调用约定知识, 不依赖源码或调试信息.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class CallingConvention(Enum):
    SYSTEMV_AMD64 = "systemv_amd64"     # rdi, rsi, rdx, rcx, r8, r9 → stack
    SYSTEMV_I386 = "systemv_i386"       # 全栈传参
    ARM64_AAPCS = "arm64_aapcs64"       # x0-x7 → stack
    UNKNOWN = "unknown"

# 每种调用约定下格式参数在各格式化函数中的位置
# (format_arg_index, 可变参数起始索引)
FMT_ARG_POSITIONS: Dict[str, Dict[str, Tuple[int, int]]] = {
    CallingConvention.SYSTEMV_AMD64.value: {
        'printf':  (0, 1),   # rdi=fmt, rsi=arg1
        'fprintf': (1, 2),   # rdi=FILE*, rsi=fmt, rdx=arg1
        'sprintf': (1, 2),   # rdi=buf, rsi=fmt, rdx=arg1
        'snprintf': (2, 3),  # rdi=buf, rsi=n, rdx=fmt, rcx=arg1
        'dprintf': (1, 2),   # rdi=fd, rsi=fmt, rdx=arg1
        'syslog':  (1, 2),   # rdi=priority, rsi=fmt, rdx=arg1
    },
    CallingConvention.SYSTEMV_I386.value: {
        'printf':  (0, 1),
        'fprintf': (1, 2),
        'sprintf': (1, 2),
        'snprintf': (2, 3),
        'dprintf': (1, 2),
        'syslog':  (1, 2),
    },
    CallingConvention.ARM64_AAPCS.value: {
        'printf':  (0, 1),   # x0=fmt, x1=arg1
        'fprintf': (1, 2),   # x0=FILE*, x1=fmt, x2=arg1
        'sprintf': (1, 2),   # x0=buf, x1=fmt, x2=arg1
        'snprintf': (2, 3),
        'dprintf': (1, 2),
        'syslog':  (1, 2),
    },
}

# 默认 (unknown calling convention)
_DEFAULT_POS = (0, 1)

@dataclass
class StackOffsetEstimate:
    """格式参数的栈偏移估计。"""
    func_name: str                  # 格式化函数名
    conv: CallingConvention
    fmt_arg_index: int              # 格式字符串是第几个参数 (0-indexed)
    vararg_start: int               # 可变参数起始索引
    on_stack: bool                  # 格式字符串本身是否在栈上 (>6个参数)
    stack_frame_size: int = 0       # 估计的栈帧大小
    confidence: float = 0.5

@dataclass
class FmtCallSite:
    """单个格式字符串调用点的分析结果。"""
    call_addr: str = ""
    func_name: str = ""
    fmt_arg: str = ""               # 格式参数变量名或常量字符串
    fmt_content: str = ""           # 能静态提取的格式字符串内容
    offset: StackOffsetEstimate = field(default_factory=lambda: StackOffsetEstimate(
        func_name="", conv=CallingConvention.UNKNOWN, fmt_arg_index=0, vararg_start=0,
        on_stack=False))
    is_user_controlled: bool = False
    callers: List[str] = field(default_factory=list)  # 调用者的函数名

class FormatStackOffsetAnalyzer:
    """格式字符串栈偏移推断器。

    在没有调试信息的stripped binary上:
      1. 检测架构/调用约定
      2. 在反编译IR中定位call printf序列
      3. 从寄存器分配反推格式参数位置
      4. 输出 StackOffsetEstimate 供利用性评分使用
    """

    # 格式化函数名模式
    _FMT_FUNCS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
        'vsnprintf', 'syslog', '__printf_chk', '__fprintf_chk',
        '__sprintf_chk', 'wprintf', 'fwprintf', 'swprintf',
    }

    # 在IR中匹配 call 指令的模式
    _CALL_PAT = re.compile(
        r'(?:call|CALL)\s+(\S*?(?:printf|sprintf|fprintf|syslog|dprintf|vprintf)\S*)',
        re.IGNORECASE,
    )
    # 在IR中匹配参数传递的mov
    _MOV_ARG_PAT = re.compile(
        r'(?:mov|MOV|lea|LEA)\s+(?:r\w+|e\w+|x\d+|\[?\w+\]?)\s*,\s*(\S+)',
        re.IGNORECASE,
    )

    _FMT_STRING_PAT = re.compile(r'"((?:[^"\\]|\\.)*)"')

    def __init__(self, arch: str = "x86_64"):
        self._arch = arch
        self._conv = self._infer_convention(arch)

    @staticmethod
    def _infer_convention(arch: str) -> CallingConvention:
        arch_lower = arch.lower().replace('-', '').replace('_', '')
        if arch_lower in ('x8664', 'amd64', 'x8664'):
            return CallingConvention.SYSTEMV_AMD64
        elif arch_lower in ('x86', 'i386', 'i686'):
            return CallingConvention.SYSTEMV_I386
        elif arch_lower in ('arm64', 'aarch64', 'armv8'):
            return CallingConvention.ARM64_AAPCS
        return CallingConvention.UNKNOWN

    def detect_arch_from_ir(self, ir_lines: List[str]) -> CallingConvention:
        """从IR行推断调用约定 (通过寄存器名推断架构)。"""
        ir_text = '\n'.join(ir_lines[:200])  # 只看前200行
        if re.search(r'\br(?:ax|bx|cx|dx|si|di|sp|bp|8|9|1[0-5])\b', ir_text):
            return CallingConvention.SYSTEMV_AMD64
        if re.search(r'\be(?:ax|bx|cx|dx|si|di|sp|bp)\b', ir_text):
            return CallingConvention.SYSTEMV_I386
        if re.search(r'\bx(?:0|[12]?\d|30)\b', ir_text):
            return CallingConvention.ARM64_AAPCS
        return CallingConvention.UNKNOWN

    def find_call_sites(
        self, pseudocode: str, func_name: str = "",
    ) -> List[FmtCallSite]:
        """在伪代码中定位所有格式化函数调用点。"""
        sites = []
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            m = self._CALL_PAT.search(line)
            if not m:
                # 也检查简化形式: 函数名(参数)
                for fmt_func in self._FMT_FUNCS:
                    if fmt_func in line and '(' in line:
                        sites.append(self._analyze_call_site(
                            fmt_func, line, lines, i, func_name))
                        break
                continue

            callee = m.group(1).strip()
            # 提取函数名 (去除 plt/imp 前缀)
            for fmt_func in self._FMT_FUNCS:
                if fmt_func in callee.lower():
                    sites.append(self._analyze_call_site(
                        fmt_func, line, lines, i, func_name))
                    break

        return sites

    def _analyze_call_site(
        self, func_name: str, call_line: str,
        lines: List[str], idx: int, caller: str,
    ) -> FmtCallSite:
        """分析单个调用点: 提取格式参数和内容。"""
        site = FmtCallSite(func_name=func_name, call_addr=f"line_{idx}")

        # 获取格式参数位置
        positions = FMT_ARG_POSITIONS.get(self._conv.value, {})
        fmt_idx, vararg_start = positions.get(func_name, _DEFAULT_POS)

        # 从调用前的mov指令推断格式参数
        context = lines[max(0, idx - 8):idx]

        # 1. 尝试提取常量格式字符串
        fmt_content = self._extract_const_fmt(context, call_line)

        # 2. 尝试提取变量名
        fmt_var = self._extract_fmt_var(context, fmt_idx)

        # 3. 判断用户可控性
        is_ctrl = self._is_user_controlled(fmt_var or "", context, lines)

        # 4. 构建偏移估计
        on_stack = (self._conv == CallingConvention.SYSTEMV_I386
                    or fmt_idx >= 6)  # x86_64: 前6参数在寄存器

        site.fmt_content = fmt_content
        site.fmt_arg = fmt_var or fmt_content or "unknown"
        site.is_user_controlled = is_ctrl
        site.callers = [caller] if caller else []
        site.offset = StackOffsetEstimate(
            func_name=func_name,
            conv=self._conv,
            fmt_arg_index=fmt_idx,
            vararg_start=vararg_start,
            on_stack=on_stack,
            stack_frame_size=self._estimate_frame_size(context),
            confidence=0.85 if fmt_content else 0.50,
        )

        return site

    def _extract_const_fmt(self, context: List[str], call_line: str) -> str:
        """从调用上下文提取常量格式字符串。"""
        for line in reversed(context):
            m = self._FMT_STRING_PAT.search(line)
            if m:
                return m.group(1)
        # 也检查call行本身
        m = re.search(r'"([^"]*%[^"]*)"', call_line)
        if m:
            return m.group(1)
        return ""

    def _extract_fmt_var(self, context: List[str], fmt_idx: int) -> str:
        """根据调用约定和fmt_idx提取格式参数变量名。"""
        # x86_64寄存器名到参数位置的映射
        regs_arg0 = ('rdi', 'edi', 'di', 'dil')
        regs_arg1 = ('rsi', 'esi', 'si', 'sil')
        regs_arg2 = ('rdx', 'edx', 'dx', 'dl')

        target_regs = [regs_arg0, regs_arg1, regs_arg2][fmt_idx] if fmt_idx < 3 else []

        var_pattern = re.compile(
            r'(?:mov|MOV|lea|LEA)\s+' + '|'.join(target_regs) + r'\s*,\s*(\w+)',
            re.IGNORECASE,
        )

        for line in reversed(context):
            # 查找寄存器赋值
            for reg in target_regs:
                m = re.search(
                    rf'(?:mov|MOV|lea|LEA)\s+{reg}\s*,\s*(\w+)',
                    line, re.IGNORECASE,
                )
                if m:
                    return m.group(1)
            # 搜索赋值模式: var = "..."; 在 call printf(fvar) 之前
            m = re.search(r'(\w+)\s*=\s*"([^"]*)"', line)
            if m:
                return m.group(1)

        return ""

    @staticmethod
    def _estimate_frame_size(context: List[str]) -> int:
        """从push/sub rsp估计栈帧大小。"""
        for line in context:
            m = re.search(r'(?:sub|SUB)\s+(?:rsp|esp|sp)\s*,\s*0x?([0-9a-fA-F]+)', line)
            if m:
                return int(m.group(1), 16)
        return 0  # leaf function

    @staticmethod
    def _is_user_controlled(
        fmt_var: str, context: List[str], all_lines: List[str],
    ) -> bool:
        """判断格式变量是否可能来自用户输入。"""
        user_sources = (
            'argv', 'getenv', 'fgets', 'read', 'recv',
            'scanf', 'gets', 'getline', 'getpass',
            'atoi', 'strdup', 'basename',
        )
        if not fmt_var:
            return False
        context_text = '\n'.join(context)
        for src in user_sources:
            if src in context_text:
                return True
        # 追踪定义: 如果fmt_var从未被赋值为常量字符串 → 可能是外部输入
        all_text = '\n'.join(all_lines)
        has_const_init = bool(re.search(
            rf'{re.escape(fmt_var)}\s*=\s*"', all_text))
        has_arg_init = bool(re.search(
            rf'{re.escape(fmt_var)}\s*=\s*(?:argv|getenv|fgets)', all_text))
        if has_arg_init:
            return True
        if not has_const_init and fmt_var not in ('fmt', 'format', 'buf'):
            return True
        return False

def infer_fmt_offset(
    pseudocode: str, func_name: str = "", arch: str = "x86_64",
) -> List[FmtCallSite]:
    """便捷入口: 推断伪代码中所有格式字符串调用的栈偏移。"""
    analyzer = FormatStackOffsetAnalyzer(arch=arch)
    if not pseudocode:
        return []
    return analyzer.find_call_sites(pseudocode, func_name)

__all__ = [
    'CallingConvention', 'StackOffsetEstimate', 'FmtCallSite',
    'FormatStackOffsetAnalyzer', 'infer_fmt_offset',
    'FMT_ARG_POSITIONS',
]
