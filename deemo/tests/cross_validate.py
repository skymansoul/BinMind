# 跨检测器交叉验证 - 同一二进制用四个检测器独立扫描, 统计一致性。
# 若堆溢出和整数溢出在同一函数都触发→高置信度(整数溢出常是堆溢出前导)。
# 若UAF和堆溢出在同一指针上触发→时间线矛盾(堆溢出要求alloc后use, UAF要求free后use)。

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CrossValidationResult:
    """交叉验证结果"""
    func_name: str
    heap_findings: int
    uaf_findings: int
    fmt_findings: int
    int_findings: int
    edge_findings: int
    # 交叉信号
    heap_int_correlated: bool    # 堆溢出+整数溢出同函数, 高置信度
    uaf_heap_conflict: bool      # UAF+堆溢出同指针, 时间线矛盾
    consensus_score: float       # 0-1, 多检测器一致性得分


def cross_validate(
    heap_results: List[Dict] = None,
    uaf_results: List[Dict] = None,
    fmt_results: List[Dict] = None,
    int_results: List[Dict] = None,
    edge_results: List[Dict] = None,
) -> List[CrossValidationResult]:
    """多检测器结果交叉验证。

    输入各检测器的原始输出, 按函数名聚合, 计算交叉信号。
    输出含consensus_score: 多检测器一致, 高分; 矛盾, 低分。
    """
    heap = heap_results or []
    uaf = uaf_results or []
    fmt = fmt_results or []
    iov = int_results or []
    edge = edge_results or []

    # 按func_name聚合
    funcs: Dict[str, Dict] = {}
    for name, findings, key in [
        ('heap', heap, 'heap'), ('uaf', uaf, 'uaf'),
        ('fmt', fmt, 'fmt'), ('int', iov, 'int'),
        ('edge', edge, 'edge'),
    ]:
        for f in findings:
            fn = f.get('function', f.get('func_name', 'unknown'))
            if fn not in funcs:
                funcs[fn] = {'heap': 0, 'uaf': 0, 'fmt': 0, 'int': 0, 'edge': 0}
            funcs[fn][key] += 1

    results = []
    for fn, counts in funcs.items():
        heap_int = counts['heap'] > 0 and counts['int'] > 0
        uaf_heap = counts['uaf'] > 0 and counts['heap'] > 0
        total_types = sum(1 for c in counts.values() if c > 0)
        consensus = total_types / 5.0  # 5个检测器
        if heap_int:
            consensus += 0.2  # 堆溢出+整数溢出, 加分
        if uaf_heap:
            consensus -= 0.1  # 可能矛盾, 减分

        results.append(CrossValidationResult(
            func_name=fn,
            heap_findings=counts['heap'],
            uaf_findings=counts['uaf'],
            fmt_findings=counts['fmt'],
            int_findings=counts['int'],
            edge_findings=counts['edge'],
            heap_int_correlated=heap_int,
            uaf_heap_conflict=uaf_heap,
            consensus_score=round(min(1.0, max(0.0, consensus)), 3),
        ))

    results.sort(key=lambda r: -r.consensus_score)
    return results


if __name__ == "__main__":
    # Demo: 模拟多检测器输出
    demo_heap = [{"function": "process_packet", "confidence": 0.85}]
    demo_uaf = [{"function": "process_packet", "confidence": 0.70}]
    demo_int = [{"function": "process_packet", "confidence": 0.60}]
    results = cross_validate(demo_heap, demo_uaf, None, demo_int)
    for r in results:
        print(f"{r.func_name}: consensus={r.consensus_score:.2f} "
              f"(heap={r.heap_findings} uaf={r.uaf_findings} int={r.int_findings} "
              f"corr={r.heap_int_correlated} conflict={r.uaf_heap_conflict})")
