"""不变性分析的数据类型定义.

从 invariant_spectrum_analyzer.py 分离, 减少单文件体积。
"""

from dataclasses import dataclass, field
from typing import List


class InvariantType:
    RANGE = "range"
    CONSTANT = "constant"
    RELATION = "relation"
    NON_ZERO = "non_zero"


@dataclass
class Invariant:
    """推断出的可能不变式."""
    program_point: str
    inv_type: str
    confidence: float = 1.0
    obs_count: int = 1
    range_lo: float = 0.0
    range_hi: float = 0.0
    const_val: float = 0.0
    rel_var: str = ""
    rel_op: str = ""
    last_violated_by: str = ""
    violation_count: int = 0


@dataclass
class InputSpectrum:
    """一个输入的不变性谱向量."""
    input_id: str
    spectrum: List[float] = field(default_factory=list)
    outlier_score: float = 0.0
    is_outlier: bool = False
    invariant_violations: List[str] = field(default_factory=list)
