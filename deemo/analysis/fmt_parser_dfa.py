"""
格式字符串AST解析器 — 将printf格式字符串解析为结构化表示。

核心方法:
  使用确定性有限状态机 (DFA) 解析格式字符串, 状态包括:
    LITERAL → PERCENT → FLAGS → WIDTH → PRECISION → LENGTH → SPECIFIER

解析结果用于:
  1. 判断格式字符串是否包含 %n (写操作)
  2. 计算格式字符串消耗的参数数量 (用于栈偏移推断)
  3. 检测位置参数 %m$n 的使用
  4. 分类格式说明符的危险等级 (INFO / LEAK / WRITE / CODE_EXEC)

与现有F-SCORE六阶段的关系:
  - Stage F (Format): 使用本解析器判断格式字符串是否可控+是否含危险说明符
  - Stage S (Source): 使用栈偏移推断结果
  - Stage O (Offset): 使用参数计数验证

局限:
  - 不处理编译器的格式字符串扩展 (如%m, %v)
  - 不模拟printf内部状态机 (仅解析格式字符串本身)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Tuple


class FmtDanger(Enum):
    """格式说明符的危险等级."""
    INFO = auto()       # %s, %d — 仅读取
    LEAK = auto()       # %p, %x — 可能泄露地址
    WRITE = auto()      # %n — 写入已输出字节数
    CODE_EXEC = auto()  # %n + 位置参数 — 精确控制写入地址


@dataclass
class FmtSpec:
    """单个格式说明符."""
    raw: str = ""                     # 原始文本, 如 "%03d" 或 "%7$n"
    width: int = 0                    # 宽度, 0=未指定
    precision: int = -1               # 精度, -1=未指定
    positional_arg: int = 0           # 位置参数索引, 0=未使用位置参数
    length_mod: str = ""              # 长度修饰符: h/hh/l/ll/z/t
    spec_char: str = ""               # 说明符字符: d/s/n/p/x 等
    danger: FmtDanger = FmtDanger.INFO

    @property
    def is_write(self) -> bool:
        return self.danger in (FmtDanger.WRITE, FmtDanger.CODE_EXEC)

    @property
    def is_leak(self) -> bool:
        return self.danger == FmtDanger.LEAK


@dataclass
class ParsedFmtString:
    """解析后的格式字符串."""
    original: str
    specs: List[FmtSpec] = field(default_factory=list)
    literal_parts: List[str] = field(default_factory=list)
    total_args_consumed: int = 0
    has_positional: bool = False
    has_write_spec: bool = False
    max_danger: FmtDanger = FmtDanger.INFO


class FmtStringParser:
    """格式字符串确定性有限状态机解析器.

    状态转移:
      LITERAL ─'%'→ PERCENT ─[0-9]→ WIDTH ─'.'→ PRECISION
      PERCENT ─[1-9]$→ POSITIONAL
      WIDTH ─[hlLzjt]→ LENGTH ─SPEC→ LITERAL
      PERCENT ─[hlLzjt]→ LENGTH ─SPEC→ LITERAL
      PERCENT ─SPEC→ LITERAL
      PERCENT ─'%'→ LITERAL (转义%%)
    """

    # 说明符字符 → 危险等级映射
    SPEC_DANGER = {
        'd': FmtDanger.INFO, 'i': FmtDanger.INFO,
        'u': FmtDanger.INFO, 'o': FmtDanger.INFO,
        'c': FmtDanger.INFO, 'f': FmtDanger.INFO,
        'e': FmtDanger.INFO, 'g': FmtDanger.INFO,
        'a': FmtDanger.INFO, 'F': FmtDanger.INFO,
        'E': FmtDanger.INFO, 'G': FmtDanger.INFO,
        'A': FmtDanger.INFO,
        's': FmtDanger.INFO, 'S': FmtDanger.INFO,
        'p': FmtDanger.LEAK,
        'x': FmtDanger.LEAK, 'X': FmtDanger.LEAK,
        'n': FmtDanger.WRITE,
        'h': FmtDanger.WRITE,  # %hn (short write)
    }

    def parse(self, fmt_str: str) -> ParsedFmtString:
        """解析完整格式字符串."""
        result = ParsedFmtString(original=fmt_str)
        if not fmt_str:
            return result

        i = 0
        literal_buf = []
        n = len(fmt_str)

        while i < n:
            if fmt_str[i] == '%':
                if literal_buf:
                    result.literal_parts.append(''.join(literal_buf))
                    literal_buf.clear()
                i, spec = self._parse_specifier(fmt_str, i + 1)
                if spec:
                    result.specs.append(spec)
                    if spec.positional_arg > 0:
                        result.has_positional = True
                    if spec.is_write:
                        result.has_write_spec = True
                    if spec.danger.value > result.max_danger.value:
                        result.max_danger = spec.danger
                    result.total_args_consumed += 1
            else:
                literal_buf.append(fmt_str[i])
                i += 1

        if literal_buf:
            result.literal_parts.append(''.join(literal_buf))

        return result

    def _parse_specifier(self, s: str, start: int) -> Tuple[int, Optional[FmtSpec]]:
        """从%之后开始解析单个格式说明符。返回 (next_index, FmtSpec|None)."""
        i = start
        n = len(s)
        if i >= n:
            return i, None

        spec = FmtSpec()

        # %%
        if s[i] == '%':
            return i + 1, None

        raw_start = start - 1

        # 位置参数: %m$
        pos_val = 0
        j = i
        while j < n and s[j].isdigit():
            pos_val = pos_val * 10 + int(s[j])
            j += 1
        if j < n and s[j] == '$' and pos_val > 0:
            spec.positional_arg = pos_val
            i = j + 1
        else:
            j = i  # reset, 不是位置参数

        # 标志: -+ #0
        while i < n and s[i] in '-+ #0':
            i += 1

        # 宽度
        width_val = 0
        while i < n and s[i].isdigit():
            width_val = width_val * 10 + int(s[i])
            i += 1
        spec.width = width_val

        # 精度
        if i < n and s[i] == '.':
            i += 1
            prec_val = 0
            while i < n and s[i].isdigit():
                prec_val = prec_val * 10 + int(s[i])
                i += 1
            spec.precision = prec_val

        # 长度修饰符
        if i < n and s[i] in 'hlLzjt':
            if s[i] == 'h' and i + 1 < n and s[i + 1] == 'h':
                spec.length_mod = 'hh'
                i += 2
            elif s[i] == 'l' and i + 1 < n and s[i + 1] == 'l':
                spec.length_mod = 'll'
                i += 2
            else:
                spec.length_mod = s[i]
                i += 1

        # 说明符字符
        if i < n and s[i] in self.SPEC_DANGER:
            spec.spec_char = s[i]
            spec.danger = self.SPEC_DANGER[s[i]]
            i += 1
        elif i < n:
            spec.spec_char = s[i]
            i += 1  # 未知说明符, 默认为INFO

        spec.raw = s[raw_start:i]
        return i, spec


def classify_fmt_danger(fmt_str: str) -> Tuple[FmtDanger, bool]:
    """快速分类格式字符串的危险等级.

    Returns:
        (danger_level, has_user_controlled_fmt_hint)
    """
    parser = FmtStringParser()
    parsed = parser.parse(fmt_str)
    return parsed.max_danger, parsed.has_write_spec
