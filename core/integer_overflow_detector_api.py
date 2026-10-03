# 拆分自 integer_overflow_detector.py — 便捷函数层.
# 独立模块: 将检测器输出转换为兼容现有API的findings字典列表.
from typing import List

from core.integer_overflow_detector_core import IntegerOverflowDetector


def detect_integer_overflows(pseudocode: str, func_name: str = '') -> List[dict]:
    """运行整数溢出检测, 返回兼容现有API的findings列表."""
    detector = IntegerOverflowDetector()
    sites = detector.detect(pseudocode)
    findings = []
    for s in sites:
        findings.append({
            'function': func_name or s.func_name,
            'pattern': s.pattern,
            'expression': f'{s.operands[0]}*{s.operands[1]}' if 'mul' in s.pattern
                          else f'{s.operands[0]}+{s.operands[1]}' if 'add' in s.pattern
                          else str(s.operands),
            'result_var': s.result_var,
            'confidence': s.confidence,
            'narrow_type': s.narrow_type,
            'wide_type': s.wide_type,
            'has_guard': s.has_guard,
            'exploitable': s.confidence >= 0.55,
            'description': (
                f'整数溢出风险: {s.pattern} '
                f'({", ".join(s.operands)})'
                f'{" [窄类型]" if s.narrow_type else ""}'
                f'{" [宽类型]" if s.wide_type else ""}'
                f'{" [有守卫]" if s.has_guard else ""}'
                f' conf={s.confidence:.2f}'
            ),
        })
    return sorted(findings, key=lambda f: -f['confidence'])
