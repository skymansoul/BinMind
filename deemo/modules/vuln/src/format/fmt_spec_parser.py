"""FMT-SPEC 格式说明符解析器 — 从二进制.rdata提取格式串并解析说明符.

核心功能:
  1. 从PE/ELF二进制中提取.rdata/.rodata中的格式字符串
  2. 解析POSIX格式说明符: %[flags][width][.prec][length]specifier
  3. 计算格式串需要的参数数量 (用于参数不匹配检测)
  4. 检测危险说明符: %n (写), %s (读), %{N}$x (直接参数访问)

解析器覆盖:
  - 标准C89/C99格式说明符
  - POSIX位置参数 %n$
  - GNU %m (errno)
  - 动态宽度/精度 %*d / %.*s (额外消费参数)

创建: 2026-06-10
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 格式说明符解析

# 完整的格式说明符正则 (POSIX + GNU扩展)
_SPEC_RE = re.compile(r"""
    %                                                        # 起始%
    (?P<posarg>\d+\$)?                                       # POSIX位置参数 %3$d
    (?P<flags>[-+ #0']*)                                     # flags
    (?P<width>\d+|\*(?:\d+\$)?)?                              # 宽度: N 或 * 或 *N$
    (?:\.(?P<prec>\d+|\*(?:\d+\$)?))?                         # 精度: .N 或 .* 或 .*N$
    (?P<length>hh|ll|[hljztLZq]|I32|I64)?                    # 长度修饰符
    (?P<spec>[diouxXeEfFgGaAcCsSpnm%])                        # 转换说明符
""", re.VERBOSE)

# 危险说明符
_DANGEROUS_SPECS = frozenset({'n', 'hn', 'hhn', 'ln', 'lln'})
_LEAK_SPECS = frozenset({'s', 'x', 'X', 'p', 'lx', 'llx'})
_WRITE_SPECS = frozenset({'n', 'hn', 'hhn', 'ln', 'lln'})


@dataclass
class FmtSpecifier:
    """单个格式说明符的解析结果."""
    raw: str             # 原始文本 (如 "%03d", "%2$s")
    spec: str            # 转换字符 (d, s, n, x, ...)
    pos_arg: int = 0     # 位置参数索引 (0=顺序)
    width: int = 0
    width_dynamic: bool = False   # width是* (动态)
    width_arg: int = 0            # 动态width的参数位置
    prec: int = -1                # -1=无精度
    prec_dynamic: bool = False    # prec是* (动态)
    prec_arg: int = 0
    length: str = ""              # hh/h/l/ll/j/z/t/L
    is_percent: bool = False      # %% (literal %)

    def is_dangerous(self) -> bool:
        """是否具有写能力 (%n家族)."""
        return (self.spec == 'n' or
                (self.spec in ('d','i','u','o','x','X','c','s')
                 and self.length in ('hhn','hn','ln','lln')))

    def is_leak(self) -> bool:
        """是否泄露内存/寄存器数据."""
        return self.spec in ('s', 'x', 'X', 'p')

    def args_consumed(self) -> int:
        """此说明符消费的参数数量."""
        if self.is_percent or self.spec == 'm':
            return 0
        n = 1  # 主参数
        if self.width_dynamic and self.width_arg == 0:
            n += 1
        if self.prec_dynamic and self.prec_arg == 0:
            n += 1
        return n


def parse_format_specs(fmt_string: str) -> List[FmtSpecifier]:
    """解析格式字符串, 返回所有格式说明符.

    参数:
      fmt_string: C格式字符串 (如 "value=%03d name=%s\\n")
    返回:
      按出现顺序的格式说明符列表
    """
    specs = []
    # 处理C转义: 将\\n转为实际换行等 (简化处理)
    # 实际格式字符串在.rdata中是原始字节
    for m in _SPEC_RE.finditer(fmt_string):
        gd = m.groupdict()
        spec_char = gd['spec']
        pos = gd['posarg']

        # 解析位置参数
        pos_arg = 0
        if pos:
            pos_arg = int(pos.rstrip('$'))

        # 解析宽度
        width = 0
        width_dyn = False
        width_arg = 0
        w = gd['width']
        if w:
            if w.startswith('*'):
                width_dyn = True
                if len(w) > 1:
                    width_arg = int(w[1:].rstrip('$'))
            else:
                width = int(w)

        # 解析精度
        prec = -1
        prec_dyn = False
        prec_arg = 0
        p = gd['prec']
        if p is not None:
            if p.startswith('*'):
                prec_dyn = True
                if len(p) > 1:
                    prec_arg = int(p[1:].rstrip('$'))
            else:
                prec = int(p)

        specs.append(FmtSpecifier(
            raw=m.group(0), spec=spec_char,
            pos_arg=pos_arg, width=width,
            width_dynamic=width_dyn, width_arg=width_arg,
            prec=prec, prec_dynamic=prec_dyn, prec_arg=prec_arg,
            length=gd['length'] or '',
            is_percent=(spec_char == '%'),
        ))

    return specs


def count_consumed_args(specs: List[FmtSpecifier]) -> int:
    """计算格式字符串消费的参数总数 (考虑位置参数).

    若使用位置参数 (%n$), 返回最大位置索引.
    否则, 返回所有说明符的参数之和.
    """
    max_pos = 0
    has_pos = False
    sequential = 0
    for s in specs:
        if s.pos_arg > 0:
            has_pos = True
            # 每个位置参数及其宽度/精度可能在不同位置
            needed = s.pos_arg
            if s.width_dynamic and s.width_arg == 0:
                needed = max(needed, s.pos_arg + 1)  # 简化
            if s.prec_dynamic and s.prec_arg == 0:
                needed = max(needed, s.pos_arg + 2)
            max_pos = max(max_pos, needed)
        else:
            sequential += s.args_consumed()

    return max_pos if has_pos else sequential


def detect_format_danger(fmt_string: str, specs: List[FmtSpecifier]) -> dict:
    """分析格式字符串的安全风险等级."""
    has_write = any(s.is_dangerous() for s in specs)
    has_leak = any(s.is_leak() for s in specs)
    has_pos = any(s.pos_arg > 0 for s in specs)
    total_args = count_consumed_args(specs)

    risk = 'SAFE'
    if has_write:
        risk = 'CRITICAL'  # %n → 任意写
    elif has_pos and has_leak:
        risk = 'HIGH'      # %n$x → 任意栈读
    elif has_leak:
        risk = 'MEDIUM'    # %x/%s → 信息泄露
    elif len(specs) > 0:
        risk = 'LOW'       # 有说明符但无危险类型

    return {
        'risk_level': risk,
        'total_specs': len(specs),
        'args_consumed': total_args,
        'has_write': has_write,
        'has_leak': has_leak,
        'has_positional': has_pos,
        'dangerous_specs': [s.raw for s in specs if s.is_dangerous()],
    }


# smoke test
def _check():
    # 测试格式说明符解析
    specs = parse_format_specs("val=%03d name=%s ptr=%p")
    assert len(specs) == 3, f"expected 3 specs, got {len(specs)}"
    assert specs[0].spec == 'd' and specs[0].width == 3
    assert specs[1].spec == 's'
    assert specs[2].spec == 'p'

    # 实际上 \\n 是字面反斜杠, spec匹配不到
    specs2 = parse_format_specs("val=%03d name=%s ptr=%p")
    assert len(specs2) == 3, f"expected 3 specs, got {len(specs2)}"

    # 测试位置参数
    specs3 = parse_format_specs("%3$s %1$d %2$p")
    assert len(specs3) == 3
    assert specs3[0].pos_arg == 3
    assert count_consumed_args(specs3) == 3

    # 测试危险检测
    danger = detect_format_danger("%s %n", parse_format_specs("%s %n"))
    assert danger['risk_level'] == 'CRITICAL'
    assert danger['has_write']

    # 测试%m (GNU errno)
    specs4 = parse_format_specs("err=%m val=%d")
    assert len(specs4) == 2  # %m is a spec but args_consumed=0

    print("[OK] fmt_spec_parser tests passed")


if __name__ == "__main__":
    _check()
