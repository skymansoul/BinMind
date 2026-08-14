"""
三层区间误报抑制 — 按写入超出量分三级分类。
CONFIRMED: 写入明确超出分配 → CRITICAL; PARTIAL: 部分超出(<16B) → WARNING 置信度×0.6;
SUPPRESSED: 安全(写入<=分配) → 排除。
"""


from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class Tier(Enum):
    CONFIRMED = "confirmed"
    PARTIAL = "partial"
    SUPPRESSED = "suppressed"


@dataclass
class FilterResult:
    alloc_var: str; alloc_size: int
    write_var: str; write_size: int
    tier: Tier; overflow: int; desc: str


def classify(alloc_sz: int, write_sz: int,
             avar: str = "?", wvar: str = "?") -> FilterResult:
    if alloc_sz <= 0 or write_sz <= 0:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.SUPPRESSED, 0, "size unknown")
    ovf = write_sz - alloc_sz
    if ovf <= 0:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.SUPPRESSED, 0, f"safe: {write_sz}<={alloc_sz}")
    if ovf <= 16:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.PARTIAL, ovf, f"partial: +{ovf}B")
    return FilterResult(avar, alloc_sz, wvar, write_sz,
                        Tier.CONFIRMED, ovf, f"confirmed: +{ovf}B")


def apply_filter(findings: List[dict],
                 results: List[FilterResult]) -> tuple[List[dict], int]:
    filtered = []; suppressed = 0
    for f in findings:
        desc = f.get('description', '')
        matched = next((r for r in results
                        if r.alloc_var in desc or r.write_var in desc), None)
        if matched is None:
            filtered.append(f)
        elif matched.tier == Tier.CONFIRMED:
            f['tier'] = 'confirmed'; f['overflow'] = matched.overflow
            filtered.append(f)
        elif matched.tier == Tier.PARTIAL:
            f['severity'] = 'Medium'; f['tier'] = 'partial'
            f['overflow'] = matched.overflow; filtered.append(f)
        else:
            suppressed += 1
    return filtered, suppressed


def filter_stats(results: List[FilterResult]) -> Dict[str, int]:
    return {"confirmed": sum(1 for r in results if r.tier == Tier.CONFIRMED),
            "partial": sum(1 for r in results if r.tier == Tier.PARTIAL),
            "suppressed": sum(1 for r in results if r.tier == Tier.SUPPRESSED),
            "total": len(results)}
