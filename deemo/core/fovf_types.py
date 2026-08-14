"""FOVF 类型定义 — FOVF (Format-String re-verification with Value-Flow) 对格式化字符串
检测误报做复核: 沿值流把格式参数分类为常量/用户可控/未知, 产出 CONFIRMED/FILTERED/UNCERTAIN 三值裁决。"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class FmtVerdict(Enum):
    CONFIRMED = 'CONFIRMED'
    FILTERED = 'FILTERED'
    UNCERTAIN = 'UNCERTAIN'


class ArgCategory(Enum):
    """格式参数值流分类.

    LITERAL      字符串字面量
    CONST_BUFFER 仅常量填充且已终止的栈缓冲
    USER         直接或传递来自用户输入源
    TEMPLATE     由常量模板 + 用户实参生成的缓冲 (间接可控)
    UNKNOWN      无法确定
    """
    LITERAL = 'LITERAL'
    CONST_BUFFER = 'CONST_BUFFER'
    USER = 'USER'
    TEMPLATE = 'TEMPLATE'
    UNKNOWN = 'UNKNOWN'


@dataclass
class FmtCallSite:
    """危险格式化调用点."""
    pc: int
    func: str
    fmt_arg: str          # 格式参数原文 (变量名或字面量)
    fmt_pos: int = 0
    line: str = ''


@dataclass
class FmtEvidence:
    """单调用点复核证据."""
    verdict: FmtVerdict
    site: FmtCallSite
    category: ArgCategory = ArgCategory.UNKNOWN
    reasons: List[str] = field(default_factory=list)
    confidence: float = 0.0
    has_danger_spec: bool = False

    def to_dict(self) -> dict:
        return {
            'pc': self.site.pc,
            'func': self.site.func,
            'fmt_arg': self.site.fmt_arg,
            'category': self.category.value,
            'verdict': self.verdict.value,
            'reasons': self.reasons,
            'confidence': round(self.confidence, 3),
        }


@dataclass
class FovfStats:
    """FOVF 阶段统计."""
    call_sites: int = 0
    confirmed: int = 0
    filtered: int = 0
    uncertain: int = 0
    fp_reduction_ratio: float = 0.0
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            'call_sites': self.call_sites,
            'confirmed': self.confirmed,
            'filtered': self.filtered,
            'uncertain': self.uncertain,
            'fp_reduction_ratio': round(self.fp_reduction_ratio, 4),
            'elapsed_ms': round(self.elapsed_ms, 1),
        }
