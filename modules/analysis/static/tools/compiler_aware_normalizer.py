# 初始创建: 编译器感知的函数归一化, 解决GCC内联libc别名问题
# 增加编译器模式识别: 区分GCC -O2消除的安全检查 vs 真正的缺失

"""编译器感知的函数归一化, 处理跨编译器/优化级别的语义等价差异

GCC -O2 会将 malloc 内联为 __libc_malloc, 将 printf 替换为 __printf_chk
若检测器只识别标准名称→跨编译器测试时漏报率急剧升高

本模块做两件事:
  1. 函数名归一化: 编译器内部别名→标准名称
     __libc_malloc → malloc
     __printf_chk → printf
     _Znwm → operator new (C++)
  2. 编译器安全检查模式识别:
     GCC -O2 的 _FORTIFY_SOURCE 会在某些函数后插入 __chk_fail
     → 这些是编译器添加的保护, 不是漏洞

归一化后的函数列表可直接供 format_string_detector 和 heap_overflow_detector 使用

理论依据:
  所有主流编译器 (GCC/Clang/MSVC) 的 libc 内部符号都有文档化的映射关系
  glibc 的 Versions 文件和 GCC 的 builtins.def 提供了完整映射
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


# libc 内部别名 → 标准名称
# 来源: glibc/sysdeps 和 GCC builtins
_LIBC_ALIAS_MAP: Dict[str, str] = {
    # malloc 家族
    '__libc_malloc':    'malloc',
    '__libc_calloc':    'calloc',
    '__libc_realloc':   'realloc',
    '__libc_free':      'free',
    '__GI___libc_malloc': 'malloc',
    '__GI___libc_free': 'free',
    # printf 家族 (FORTIFY_SOURCE)
    '__printf_chk':     'printf',
    '__fprintf_chk':    'fprintf',
    '__sprintf_chk':    'sprintf',
    '__snprintf_chk':   'snprintf',
    '__vfprintf_chk':   'vfprintf',
    '__vsprintf_chk':   'vsprintf',
    '__vsnprintf_chk':  'vsnprintf',
    '__isoc99_printf':  'printf',
    '__isoc99_scanf':   'scanf',
    # memcpy 家族
    '__memcpy_chk':     'memcpy',
    '__memmove_chk':    'memmove',
    '__memset_chk':     'memset',
    '__strcpy_chk':     'strcpy',
    '__strncpy_chk':    'strncpy',
    # C++ operator new
    '_Znwm':            'malloc',     # operator new
    '_Znam':            'malloc',     # operator new[]
    '_ZdlPv':           'free',       # operator delete
    '_ZdaPv':           'free',       # operator delete[]
    # pthread
    '___pthread_mutex_lock':   'pthread_mutex_lock',
    '___pthread_mutex_unlock': 'pthread_mutex_unlock',
}

# FORTIFY_SOURCE 安全检查函数, 这些不是漏洞
_FORTIFY_FUNCTIONS: Set[str] = {
    '__chk_fail', '__stack_chk_fail', '__fortify_fail',
    '__stack_chk_fail_local',
}

# 编译器添加的死代码/填充
_COMPILER_PADDING: Set[str] = {
    'endbr64',         # Intel CET (GCC)
    'nop', 'ud2',      # 填充/不可达 (Clang)
    'int3',            # 调试断点 (MSVC)
    'lfence',          # 屏障
}


class CompilerAwareNormalizer:

    def normalize_function_calls(
        self, asm_lines: List[Tuple[int, str]]
    ) -> List[Tuple[int, str]]:
        result = []
        for addr, text in asm_lines:
            text_lower = text.lower().strip()
            if 'call' in text_lower:
                normalized = self._normalize_call(text)
                result.append((addr, normalized))
            else:
                result.append((addr, text))
        return result

    def normalize_function_name(self, func_name: str) -> str:
        """归一化单个函数名"""
        return _LIBC_ALIAS_MAP.get(func_name, func_name)

    def is_fortify_check(self, func_name: str) -> bool:
        """判断函数是否为 FORTIFY_SOURCE 安全检查 (非漏洞)"""
        return func_name in _FORTIFY_FUNCTIONS

    def is_compiler_padding(self, mnemonic: str) -> bool:
        """判断指令是否为编译器填充 (非语义操作)"""
        return mnemonic.lower() in _COMPILER_PADDING

    def _normalize_call(self, insn_text: str) -> str:
        """归一化单条 call 指令中的函数名"""
        import re
        # 提取call目标
        m = re.search(r'call\s+([\w.@$]+)', insn_text, re.I)
        if not m:
            return insn_text
        callee = m.group(1)
        normalized = _LIBC_ALIAS_MAP.get(callee, callee)
        if normalized != callee:
            return insn_text.replace(callee, normalized)
        return insn_text

    def normalize_insn_list(
        self, asm_lines: List[str]
    ) -> List[str]:
        """归一化纯文本指令列表 (无地址)"""
        result = []
        for text in asm_lines:
            text_lower = text.lower().strip()
            if 'call' in text_lower:
                result.append(self._normalize_call(text))
            else:
                result.append(text)
        return result

    def filter_non_semantic(
        self, asm_lines: List[Tuple[int, str]]
    ) -> List[Tuple[int, str]]:
        """过滤非语义指令 (填充/断点/屏障), 减小后续分析负担"""
        return [
            (addr, text) for addr, text in asm_lines
            if not self.is_compiler_padding(
                text.strip().split()[0] if text.strip() else ''
            )
        ]

    def get_all_aliases(self, standard_name: str) -> List[str]:
        """获取标准函数名的所有编译器别名 (用于检测器扩展规则)"""
        return [
            alias for alias, std in _LIBC_ALIAS_MAP.items()
            if std == standard_name
        ]
