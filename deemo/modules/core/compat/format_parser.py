# -*- coding: utf-8 -*-
"""printf 格式符严格状态机解析器 — 替代子串匹配, 逐字符解析格式说明符.

printf 格式: %[flags][width][.precision][length]conversion
  状态机遍历格式字符串, 在 '%' 后进入格式符解析状态,
  按标志→宽度→精度→长度→转换说明符的顺序推进,
  精确识别 %n / %10$n / %08x / %.2f 等合法格式符.

与简单子串匹配的区别: 子串匹配会在 "var_name" 中匹配到 "%n",
状态机只在遇到 '%' 后才开始解析, 不会误匹配普通字符串中的 '%' 字符.
"""

from typing import List, Tuple, Dict


# printf 转换说明符分类
_WRITE_SPECS = frozenset({'n', 'hn', 'hhn', 'ln', 'lln'})  # 写入类
_LEAK_SPECS = frozenset({'s', 'x', 'lx', 'llx', 'p'})       # 泄露类
_ALL_SPECS = frozenset({'d','i','u','o','x','X','f','F','e','E','g','G','a','A',
                         'c','s','p','n','m','%'})
# 长度修饰符
_LENGTH_MODS = frozenset({'h','hh','l','ll','q','L','j','z','t','w'})


class FormatSpec:
    """解析出的单个格式说明符."""
    __slots__ = ('positional', 'flags', 'width', 'precision',
                 'length', 'conversion', 'is_write', 'is_leak', 'raw')
    def __init__(self):
        self.positional = 0; self.flags = ''; self.width = ''
        self.precision = ''; self.length = ''; self.conversion = ''
        self.is_write = False; self.is_leak = False; self.raw = ''


def parse_format_string(fmt: str) -> List[FormatSpec]:
    """状态机解析 printf 格式字符串, 返回所有格式说明符列表.

    状态转换: NORMAL → (遇到%) → FLAGS → WIDTH → PRECISION → LENGTH → CONVERSION → NORMAL
    若遇到非法字符(不属于任何状态的合法字符集), 回退到 NORMAL 状态.
    """
    specs = []
    i = 0; n = len(fmt)
    while i < n:
        if fmt[i] != '%':
            i += 1; continue
        # 进入格式符解析
        start = i; i += 1
        if i >= n: break
        if fmt[i] == '%': i += 1; continue  # %% → 转义

        spec = FormatSpec()
        spec.raw = fmt[start:]

        # 1. 位置参数: %10$ 形式, 在标志之前
        pos_str = ''
        while i < n and fmt[i].isdigit():
            pos_str += fmt[i]; i += 1
        if i < n and fmt[i] == '$':
            spec.positional = int(pos_str) if pos_str else 0
            i += 1
        else:
            # 不是位置参数, 回退: 刚才读的数字可能是宽度
            i -= len(pos_str)

        # 2. 标志: -+ #0 等
        while i < n and fmt[i] in '-+#0 ':
            spec.flags += fmt[i]; i += 1

        # 3. 宽度: 数字(非位置参数)或 *
        if i < n and fmt[i] == '*':
            spec.width = '*'; i += 1
        else:
            w = ''
            while i < n and fmt[i].isdigit():
                w += fmt[i]; i += 1
            if w: spec.width = w

        # 4. 精度: . 后跟数字或 *
        if i < n and fmt[i] == '.':
            i += 1
            if i < n and fmt[i] == '*':
                spec.precision = '*'; i += 1
            else:
                p = ''
                while i < n and fmt[i].isdigit():
                    p += fmt[i]; i += 1
                if p: spec.precision = p

        # 5. 长度修饰符: hh/h/l/ll/L/q/j/z/t 等
        if i < n and fmt[i] == 'h':
            if i+1 < n and fmt[i+1] == 'h':
                spec.length = 'hh'; i += 2
            else:
                spec.length = 'h'; i += 1
        elif i < n and fmt[i] == 'l':
            if i+1 < n and fmt[i+1] == 'l':
                spec.length = 'll'; i += 2
            else:
                spec.length = 'l'; i += 1
        elif i < n and fmt[i] in 'Lqjztw':
            spec.length = fmt[i]; i += 1

        # 6. 转换说明符
        if i < n:
            c = fmt[i]
            # 处理多字符说明符 (如 'lln' 中 'n' 是转换符, 'll' 已作为长度处理)
            if c in _ALL_SPECS:
                spec.conversion = c
                # 若之前未检测到长度修饰符, 但转换符前的字母可能是长度
                i += 1
            elif i+1 < n and fmt[i:i+2] in ('hn','ln'):
                spec.conversion = fmt[i:i+2]; i += 2
            elif i+2 < n and fmt[i:i+3] in ('hhn','lln'):
                spec.conversion = fmt[i:i+3]; i += 3
            else:
                i += 1  # 无效转换符, 跳过

        if spec.conversion:
            conv_key = spec.conversion
            if spec.length:
                conv_key_full = spec.length + spec.conversion
                if conv_key_full in _WRITE_SPECS:
                    spec.is_write = True
                if conv_key_full in _LEAK_SPECS:
                    spec.is_leak = True
            if spec.conversion in _WRITE_SPECS or spec.conversion in ('hn','hhn','ln','lln'):
                spec.is_write = True
            if spec.conversion in _LEAK_SPECS:
                spec.is_leak = True
            spec.raw = fmt[start:i]
            specs.append(spec)

    return specs


def classify_format_risk(specs: List[FormatSpec]) -> Dict:
    """对解析出的格式符列表做风险分类."""
    writes = [s for s in specs if s.is_write]
    leaks = [s for s in specs if s.is_leak]
    positional = [s for s in specs if s.positional > 0]
    return {
        'total_specs': len(specs),
        'write_specs': len(writes),
        'leak_specs': len(leaks),
        'positional_specs': len(positional),
        'max_write_danger': 'CRITICAL' if any(
            s.conversion in ('n','hn','hhn') for s in writes
        ) else ('HIGH' if writes else 'NONE'),
        'fortify_bypass': len(positional) > 0 and len(writes) > 0,
        'details': [{'conv': s.conversion, 'pos': s.positional,
                     'write': s.is_write, 'leak': s.is_leak,
                     'raw': s.raw} for s in specs],
    }
