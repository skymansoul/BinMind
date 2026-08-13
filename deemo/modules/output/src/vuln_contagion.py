"""
跨二进制漏洞传染风险图 — 导入面重叠 + 加固差分传播模型。

问题定义:
  共享库中发现漏洞时需要快速评估生态中哪些二进制可能受波及。
  现有 CVE 扫描器仅匹配包名/版本号，无法处理静态链接或不同调用路径。

  本模块提供轻量级传染风险评估—无需完整反汇编，仅依赖导入表、
  checksec 加固状态和 CVSS 基础评分。

与现有工作的区别:
  - MIRAGE: 攻击图建模—需运行时交互信息
  - Binarly US 12,287,885: 跨二进制 ICFG—需完整反汇编
  - VPSS: Java/Maven 生态—不适用于原生二进制

传染评分: contagion = sigmoid(w1×overlap + w2×(1-hw_ratio) + w3×cvss_norm + w4×proximity)

  MIRAGE, Binarly US 12,287,885, VPSS

修改记录:
  创建 2024-10-11 — 传染图核心 (assess_contagion, build_contagion_graph, contagion_summary)
  2024-10-11 — 度量函数拆分至 contagion_metrics.py
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from modules.output.src.contagion_metrics import (
    DEFAULT_WEIGHTS, compute_import_overlap, compute_symbol_proximity,
    compute_hardening_ratio, _family_set, _normalize_import_name,
)

@dataclass
class ContagionEdge:
    source: str
    target: str
    import_overlap: float
    symbol_proximity: float
    source_cvss: float
    target_hardening_ratio: float
    contagion_score: float
    risk_factors: Dict[str, float] = field(default_factory=dict)

    def risk_level(self) -> str:
        if self.contagion_score >= 0.8: return 'critical'
        if self.contagion_score >= 0.5: return 'high'
        if self.contagion_score >= 0.3: return 'medium'
        return 'low'

def assess_contagion(
    source_imports: List[str], source_cvss_score: float,
    target_imports: List[str], target_checksec: Dict[str, Any],
    target_name: str = "", source_name: str = "",
    weights: Tuple[float, float, float, float] = DEFAULT_WEIGHTS,
) -> ContagionEdge:
    w_io, w_hp, w_cs, w_sp = weights
    io_score = compute_import_overlap(source_imports, target_imports)
    sp_score = compute_symbol_proximity(source_imports, target_imports)
    hr = compute_hardening_ratio(target_checksec)
    cvss_norm = min(source_cvss_score / 10.0, 1.0)
    hardening_penalty = 1.0 - hr

    raw = w_io*io_score + w_hp*hardening_penalty + w_cs*cvss_norm + w_sp*sp_score
    contagion = 1.0 / (1.0 + math.exp(-7.0 * (raw - 0.35)))

    return ContagionEdge(
        source=source_name or 'source', target=target_name or 'target',
        import_overlap=round(io_score, 4),
        symbol_proximity=round(sp_score, 4),
        source_cvss=round(source_cvss_score, 1),
        target_hardening_ratio=round(hr, 2),
        contagion_score=round(contagion, 4),
        risk_factors={
            'import_overlap': round(io_score, 4),
            'hardening_penalty': round(hardening_penalty, 4),
            'cvss_norm': round(cvss_norm, 4),
            'symbol_proximity': round(sp_score, 4),
        })

def build_contagion_graph(
    source_binary: Dict[str, Any],
    candidate_binaries: List[Dict[str, Any]],
    source_cvss_score: float, min_score: float = 0.15,
) -> List[ContagionEdge]:
    source_imports = source_binary.get('imports', [])
    source_name = source_binary.get('name', 'source')
    edges: List[ContagionEdge] = []
    for candidate in candidate_binaries:
        if candidate.get('name') == source_name: continue
        edge = assess_contagion(
            source_imports=source_imports, source_cvss_score=source_cvss_score,
            target_imports=candidate.get('imports', []),
            target_checksec=candidate.get('checksec', {}),
            target_name=candidate.get('name', 'unknown'),
            source_name=source_name)
        if edge.contagion_score >= min_score:
            edges.append(edge)
    edges.sort(key=lambda e: e.contagion_score, reverse=True)
    return edges

def contagion_summary(edges: List[ContagionEdge]) -> Dict[str, Any]:
    if not edges:
        return {'total_assessed': 0, 'critical': 0, 'high': 0, 'medium': 0,
                'low': 0, 'max_score': 0.0, 'mean_score': 0.0}
    levels = defaultdict(int)
    for e in edges: levels[e.risk_level()] += 1
    scores = [e.contagion_score for e in edges]
    return {
        'total_assessed': len(edges),
        'critical': levels.get('critical', 0), 'high': levels.get('high', 0),
        'medium': levels.get('medium', 0), 'low': levels.get('low', 0),
        'max_score': round(max(scores), 4),
        'mean_score': round(sum(scores)/len(scores), 4),
        'top_targets': [{'name': e.target, 'score': e.contagion_score,
                         'level': e.risk_level()} for e in edges[:5]],
    }
