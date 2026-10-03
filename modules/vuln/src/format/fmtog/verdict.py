"""Fmt-OG 三态判决 — 常量串/参数契约/输入源/包装透传证据合成.

SUPPRESS 证据:
  - 常量串安全: fmt 为 .rodata 常量且无 %n, 无论参数来源
  - 参数充足: 常量串说明符数 ≤ 实参数, 无越界读
  - 包装透传: vprintf 族 fmt 常量, 或 caller 实参为常量
CONFIRM 证据:
  - 输入源: fmt 身份源自输入 API (RETURN/ARG 链) 或含 %n 且可控
  - 参数不足: 说明符数 > 实参数 (越界读)
UNCHANGED: 证据不足, 保留.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


class FmtVerdictKind(Enum):
    SUPPRESS = auto()
    CONFIRM = auto()
    UNCHANGED = auto()


@dataclass
class FmtVerdict:
    kind: FmtVerdictKind
    reason: str = ''
    evidence: List[str] = field(default_factory=list)


class FmtSynthesizer:
    """综合证据输出判决."""

    def const_safe(self, fmt_text: str, n_count: int) -> FmtVerdict:
        if n_count == 0:
            return FmtVerdict(
                FmtVerdictKind.SUPPRESS,
                f'常量格式串 "{fmt_text[:32]}" 无 %n, 与参数来源无关',
                ['const_fmt_no_n'])
        return FmtVerdict(
            FmtVerdictKind.CONFIRM,
            f'常量格式串含 {n_count} 个 %n, 存在写内存面',
            ['const_fmt_with_n'])

    def args_match(self, fmt_text: str, required: int,
                   available: int) -> FmtVerdict:
        if required <= available:
            return FmtVerdict(
                FmtVerdictKind.SUPPRESS,
                f'说明符 {required} ≤ 实参 {available}, 无越界读',
                ['args_sufficient'])
        return FmtVerdict(
            FmtVerdictKind.CONFIRM,
            f'说明符 {required} > 实参 {available}, 越界读',
            ['args_insufficient'])

    def input_sink(self, identity: str) -> FmtVerdict:
        return FmtVerdict(
            FmtVerdictKind.CONFIRM,
            f'格式串身份 {identity} 源自输入 API, 用户可控',
            ['fmt_from_input'])

    def user_fmt(self) -> FmtVerdict:
        return FmtVerdict(
            FmtVerdictKind.CONFIRM,
            '格式串非常量且身份不可判定, 按用户可控处理',
            ['fmt_non_const'])

    def unchanged(self, reason: str = '证据不足, 保留') -> FmtVerdict:
        return FmtVerdict(FmtVerdictKind.UNCHANGED, reason)
