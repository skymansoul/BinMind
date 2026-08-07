# 拆分自 integer_overflow_detector.py — 数据结构定义.
# 独立模块: IntOverflowSite作为公共数据契约, 检测器与便捷函数共享.
from dataclasses import dataclass, field
from typing import List


@dataclass
class IntOverflowSite:
    """整数溢出候选点 — 含模式分类和置信度."""
    func_name: str = ''
    pattern: str = ''       # mul_assign | add_assign | calloc | direct_mul | loop_accum
    operands: List[str] = field(default_factory=list)
    result_var: str = ''
    alloc_var: str = ''     # 最终流入的alloc变量
    alloc_line: int = 0
    narrow_type: bool = False  # 操作数是否为窄类型(unsigned short等)
    wide_type: bool = False    # 操作数是否为宽类型(size_t等)
    has_guard: bool = False    # 是否有溢出守卫
    confidence: float = 0.0
    line_text: str = ''
