"""误报收敛 — 把耦合验证的原始判定映射到报告集合并计数。

UNCERTAIN 一律不进入报告(误报主来源); 记录过滤理由
供论文的"各级过滤贡献"统计使用。
"""


from typing import List, Tuple

from heapov import verdict as V
from heapov.model import Finding


def finalize(findings: List[Finding], threshold: float = V.CONF_REPORT_MIN,
             ) -> Tuple[List[Finding], dict]:
    """收敛报告集。返回 (reportable, stats)。

    stats 含: total, filtered, by_reason, reported, per_verdict。
    """
    reportable: List[Finding] = []
    stats = {'total': len(findings), 'filtered': 0, 'reported': 0,
             'by_reason': {}, 'per_verdict': {}}
    for f in findings:
        stats['per_verdict'][f.verdict] = stats['per_verdict'].get(f.verdict, 0) + 1
        if f.verdict not in (V.OVERFLOW, V.LIKELY):
            stats['filtered'] += 1
            reason = '|'.join(f.fp_reasons) if f.fp_reasons else f.verdict
            stats['by_reason'][reason] = stats['by_reason'].get(reason, 0) + 1
            continue
        if f.confidence < threshold:
            stats['filtered'] += 1
            stats['by_reason']['low-confidence'] = \
                stats['by_reason'].get('low-confidence', 0) + 1
            continue
        reportable.append(f)
        stats['reported'] += 1
    reportable.sort(key=lambda f: -f.confidence)
    return reportable, stats
