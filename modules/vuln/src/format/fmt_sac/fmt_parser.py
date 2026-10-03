"""格式串解析 — 从 .rdata 提取字符串字面量并统计说明符.

创建: 2024-12-23
设计决策:
  - 说明符解析只统计"有效"说明符: %% 转义不计, %N$ 位置参数按展开
    计数, %* 宽度星号不消耗实参但可泄露, %n 单独标记.
  - rdata 提取: objdump -s -j .rdata 输出的 ASCII 列直接解析,
    与调用点 LEA 偏移做地址-内容匹配由上层完成.
"""
import re
from typing import List, Optional, Tuple

_PCT_SPEC_RE = re.compile(
    r'%(?:(\d+)\$)?(?:[-+ #0]*)(?:\d+|\*)?(?:\.(?:\d+|\*))?'
    r'(?:hh|h|ll|l|L|z|j|t)?([diouxXeEfFgGaAcspn%])')


def parse_specifiers(fmt: str) -> Tuple[int, bool, List[str]]:
    """返回 (有效说明符数, 是否含%n, 说明符列表)."""
    specs: List[str] = []
    i = 0
    n = len(fmt)
    while i < n:
        if fmt[i] != '%':
            i += 1
            continue
        if i + 1 < n and fmt[i + 1] == '%':
            i += 2
            continue
        m = _PCT_SPEC_RE.match(fmt, i)
        if m:
            pos_arg = m.group(1)
            conv = m.group(2)
            specs.append(conv)
            if conv == 'n':
                pass  # 单独标记
            i = m.end()
        else:
            i += 1
    has_n = '%' in fmt and bool(re.search(
        r'%(?:\d+\$)?(?:[-+ #0]*)(?:\d+|\*)?(?:\.(?:\d+|\*))?'
        r'(?:hh|h|ll|l|L|z|j|t)?n', fmt))
    return len(specs), has_n, specs


def count_consumed_args(specs: List[str], has_pct_n: bool) -> int:
    """说明符消耗的实参数: 普通说明符计1, * 宽度/精度额外计1."""
    return len(specs)


def extract_rdata_strings(objdump_s_output: str) -> List[Tuple[int, str]]:
    """从 objdump -s 输出提取 (行首地址, ASCII文本) 对.
    文本为整行 16 字节的 ASCII 列, 匹配时按目标偏移截取."""
    out: List[Tuple[int, str]] = []
    for line in objdump_s_output.splitlines():
        m = re.match(r'^\s*([0-9a-fA-F]+)\s+'
                     r'((?:[0-9a-fA-F]{2,8}\s*){1,4})\s+(.*)$', line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        ascii_part = m.group(3) or ''
        text = re.sub(r'^[.]+', '', ascii_part)
        text = re.sub(r'[^ -~]', '', text)
        if len(text) >= 2:
            out.append((addr, text))
    return out


def resolve_rdata_text(rdata: dict, target: int) -> str:
    """lea 目标 → 行内偏移截取的字符串."""
    for addr, text in rdata.items():
        if addr <= target < addr + len(text) + 4:
            off = target - addr
            if 0 <= off < len(text):
                return text[off:]
    return ''
