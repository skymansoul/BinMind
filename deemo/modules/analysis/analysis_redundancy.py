"""
分析冗余检测器 (Analysis Redundancy Detector, ARD)
---------------------------------------------------
检测多个分析方法是否产出相同结论——冗余=高置信验证,
而非资源浪费. 同时检测矛盾=需要进一步调查.

设计依据:
  多种分析方法 (静态+动态+符号) 同时确认同一漏洞→高置信.
  某一方法单独报告而其他方法未发现→可能是误报或该方法独有的盲点.
  ARD 量化分析间的冗余度, 为每发现计算 "独立验证计数".

算法:
  1. 对每发现计算多源 Jaccard 相似度
  2. 冗余得分 = 确认该发现的分析源数 / 总活跃源数
  3. 低于阈值的发现标记为 "单源" (可能需额外验证)
"""
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


class AnalysisRedundancyDetector:
    """分析冗余检测器.

    用法:
      ard = AnalysisRedundancyDetector()
      ard.record('static', '0x401000', 'buffer_overflow')
      ard.record('dynamic', '0x401000', 'buffer_overflow')
      ard.record('symbolic', '0x401000', 'buffer_overflow')
      score = ard.redundancy_score('0x401000')
      # score = 1.0 (三个源一致确认)
    """

    def __init__(self, min_agreement_sources: int = 2):
        self._findings: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )  # address → source → {finding_types}
        self._active_sources: Set[str] = set()
        self._min_agreement = min_agreement_sources

    def record(self, source: str, address: str, finding_type: str):
        """记录一个分析源的发现."""
        self._active_sources.add(source)
        self._findings[address][source].add(finding_type)

    def redundancy_score(self, address: str) -> float:
        """计算某地址的冗余得分 (0-1)."""
        if address not in self._findings:
            return 0.0
        sources = self._findings[address]
        n_sources = len(sources)
        n_active = len(self._active_sources)
        if n_active == 0:
            return 0.0

        # 基础分: 确认源比例
        base = n_sources / n_active
        # 类型一致性奖励
        all_types: Set[str] = set()
        for types in sources.values():
            all_types |= types
        # 若所有源报告同一类型→奖励
        agreement_bonus = 0.0
        if all(len(types & all_types) > 0 for types in sources.values()):
            agreement_bonus = 0.2
        return min(1.0, base + agreement_bonus)

    def is_independently_verified(self, address: str) -> bool:
        """该发现是否被至少 min_agreement_sources 个源独立验证."""
        return len(self._findings.get(address, {})) >= self._min_agreement

    def single_source_findings(self) -> List[str]:
        """返回仅被单一源报告的发现——可能是误报候选."""
        return [
            addr for addr, sources in self._findings.items()
            if len(sources) == 1
        ]

    def high_confidence_findings(self) -> List[Tuple[str, float]]:
        """返回高冗余得分 (>0.7) 的发现."""
        scored = [(addr, self.redundancy_score(addr))
                  for addr in self._findings]
        return [(a, s) for a, s in scored if s > 0.7]

    def contradiction_report(self) -> List[Dict[str, Any]]:
        """检测矛盾: 同一地址不同源报告不同类型."""
        contradictions = []
        for addr, sources in self._findings.items():
            all_types = set()
            for types in sources.values():
                all_types |= types
            if len(all_types) > 1:
                contradictions.append({
                    'address': addr,
                    'conflicting_sources': {
                        src: list(types) for src, types in sources.items()
                    },
                    'distinct_types': sorted(all_types),
                })
        return contradictions

    def summary(self) -> Dict[str, Any]:
        total = len(self._findings)
        verified = sum(1 for a in self._findings if self.is_independently_verified(a))
        single = len(self.single_source_findings())
        return {
            'total_findings': total,
            'independently_verified': verified,
            'single_source': single,
            'verification_rate': round(verified / max(1, total), 3),
            'active_sources': sorted(self._active_sources),
        }
