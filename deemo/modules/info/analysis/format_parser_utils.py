# analysis/format_parser_utils.py — 格式字符串解析共享工具
# 被 format_string_v3.py 和 format_string_deep.py 共用。
#
# 功能:
#   _parse_format_specifiers: 解析 %[pos$][flags][width][.prec][len]spec
# split_args: 括号/引号感知的参数分割
# is_string_variable: 判断参数是字符串变量还是字面量

import re
from typing import Dict, List

def parse_format_specifiers(fmt_str: str) -> List[Dict]:
    """解析格式字符串, 提取每个格式说明符的类型和位置。
    返回: [{type, position (n$), width, precision, is_dynamic_width}]
    """
    specifiers = []
    pattern = re.compile(r"""
        %(?:
            (\d+)\$                    # 位置参数 n$
        )?
        (?:[#0\- +']*)?              # flags
        (?:\*)?                       # 动态宽度
        (?:\d+)?                      # 宽度
        (?:\.\*)?                     # 动态精度
        (?:\.\d+)?                    # 精度
        (?:hh|h|l|ll|j|z|t|L|q)?    # 长度修饰符
        ([diouxXeEfFgGaAcspn%])      # 转换说明符
    """, re.VERBOSE)

    for m in pattern.finditer(fmt_str):
        pos = m.group(1)
        conv = m.group(2)
        if conv == '%':
            continue
        specifiers.append({
            "position": int(pos) if pos else None,
            "conversion": conv,
            "is_dynamic_width": '*' in m.group(0) and '.*' not in m.group(0),
            "full_match": m.group(0),
        })
    return specifiers

def split_args(args_str: str) -> List[str]:
    """分割函数参数 — 正确处理嵌套括号和引号字符串。"""
    args = []
    current = []
    depth = 0
    in_string = False
    string_char = None

    for ch in args_str:
        if in_string:
            current.append(ch)
            if ch == string_char and (len(current) < 2 or current[-2] != '\\'):
                in_string = False
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            current.append(ch)
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)

    if current:
        args.append(''.join(current).strip())
    return args

def is_string_variable(arg: str) -> bool:
    """判断参数是字符串变量 (非字面量) → 无法静态分析格式串。"""
    arg = arg.strip()
    if arg.startswith('"') or arg.startswith("'"):
        return False
    if re.match(r'^[a-zA-Z_]\w*$', arg):
        return True
    if '+' in arg or '[' in arg:
        return True
    return False
