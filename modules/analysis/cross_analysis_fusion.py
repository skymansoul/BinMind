"""
跨分析结果融合 (Cross-Analysis Result Fusion, CARF)
-----------------------------------------------------
融合静态分析/动态执行/符号执行/反编译的结果为统一发现.

设计依据:
  不同分析方法产出不同格式的结果——静态分析给出可疑代码位置,
  动态 trace 提供运行时行为, 符号执行输出路径约束.
  安全分析师需手动关联这些分散发现——耗时且易遗漏.
  CARF 按 (地址, 数据类型) 对齐各分析源的结果, 输出统一视图.

算法:
  1. 地址对齐: 将各源的结果按虚拟地址/函数名归一化
  2. 证据聚合: 同一地址的多源证据加权合并
  3. 冲突检测: 若两源对同一地址给出矛盾判断, 标记为需人工审查
"""
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AnalysisItem:
    """单个分析源的发现."""
    source: str          # 'static' | 'dynamic' | 'symbolic' | 'decompile'
    address: str         # 虚拟地址或函数名
    finding_type: str    # 发现类型
    severity: str = "INFO"
    confidence: float = 0.5
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusedFinding:
    """融合后的统一发现."""
    address: str
    sources: List[str] = field(default_factory=list)
    findings: List[AnalysisItem] = field(default_factory=list)
    consensus_severity: str = "INFO"
    consensus_type: str = ""
    aggregate_confidence: float = 0.0
    source_agreement: float = 0.0  # 0=完全冲突, 1=完全一致
    has_conflict: bool = False


class CrossAnalysisFusion:
    """跨分析结果融合器.

    按地址对齐多源发现, 加权合并置信度与严重性, 冲突标记人工审查.
    """

    def __init__(self):
        self._items: Dict[str, List[AnalysisItem]] = defaultdict(list)
        self._source_weights = {
            'static': 0.7, 'dynamic': 0.85,
            'symbolic': 0.9, 'decompile': 0.6,
        }

    def add_findings(self, source: str, items: List[AnalysisItem]):
        for item in items:
            item.source = source
            self._items[item.address].append(item)

    def fuse(self) -> List[FusedFinding]:
        """融合所有源的结果."""
        results = []
        for addr, items in self._items.items():
            sources = list(set(i.source for i in items))
            types = [i.finding_type for i in items]
            severities = [i.severity for i in items]

            # 共识类型: 多数投票
            type_votes = defaultdict(int)
            sev_ranks = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            for t, s in zip(types, severities):
                type_votes[t] += 1

            consensus_type = max(type_votes, key=type_votes.get)
            # 共识严重性: 加权平均
            weighted_sev = sum(
                sev_ranks.get(i.severity, 0) * self._source_weights.get(i.source, 0.5)
                for i in items
            ) / max(0.01, sum(self._source_weights.get(i.source, 0.5) for i in items))
            sev_levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            consensus_sev = sev_levels[min(4, max(0, round(weighted_sev)))]

            # 聚合置信度
            confidences = [i.confidence * self._source_weights.get(i.source, 0.5)
                          for i in items]
            agg_conf = sum(confidences) / len(confidences) if confidences else 0.0

            # 源一致性: 所有源是否给出一致判断
            unique_types = set(types)
            agreement = 1.0 / len(unique_types) if unique_types else 0.0

            results.append(FusedFinding(
                address=addr, sources=sources, findings=items,
                consensus_severity=consensus_sev, consensus_type=consensus_type,
                aggregate_confidence=round(min(1.0, agg_conf), 3),
                source_agreement=round(agreement, 3),
                has_conflict=len(unique_types) > 1,
            ))

        results.sort(key=lambda r: r.aggregate_confidence, reverse=True)
        return results

    def conflict_report(self, fused: List[FusedFinding]) -> List[Dict[str, Any]]:
        """生成冲突报告——不同源对同一地址的矛盾判断."""
        conflicts = []
        for f in fused:
            if not f.has_conflict:
                continue
            by_source = defaultdict(list)
            for item in f.findings:
                by_source[item.source].append(item.finding_type)
            conflicts.append({
                'address': f.address,
                'disagreement': dict(by_source),
                'recommendation': '建议人工审查——各分析源判断不一致',
            })
        return conflicts
