"""ACFPC-CMS: 冲突感知多源融合.

与原 ACFPC 的本质区别:
  原 ACFPC 用固定权重五模态融合 (static 0.28, dynamic 0.10, llm 0.27, fuzzing 0.15, symbex 0.20).
  ACFPC-CMS 加入 D-S 证据理论冲突检测, 当证据冲突时动态调权,
  避免冲突证据互相抵消导致漏报.
"""
from typing import Dict, List, Optional, Tuple


class ConflictAwareMultiSourceFuser:
    """冲突感知多源融合器, 基于 D-S 证据理论检测证据冲突并动态调权."""

    # 原 ACFPC 固定权重
    DEFAULT_WEIGHTS = {
        'static': 0.28,
        'dynamic': 0.10,
        'llm': 0.27,
        'fuzzing': 0.15,
        'symbex': 0.20,
    }
    # 高冲突阈值
    CONFLICT_THRESHOLD = 0.65
    # 中冲突阈值
    MODERATE_CONFLICT = 0.35

    def __init__(self, base_weights: dict = None):
        self._base_weights = base_weights or dict(self.DEFAULT_WEIGHTS)
        self._stats = {'total': 0, 'conflicts': 0, 'high_conflicts': 0}

    def fuse(self, evidences: list) -> dict:
        """融合多源证据.

        evidences: [{'source': str, 'score': float, 'weight': float (optional)}]
        返回: {final_score, confidence, conflict_factor, severity, weights_used}
        """
        self._stats['total'] += 1
        if not evidences:
            return {
                'final_score': 0.0,
                'confidence': 0.0,
                'conflict_factor': 0.0,
                'severity': 'unknown',
                'weights_used': {},
            }

        # 构建 mass 函数
        masses = []
        sources = []
        for ev in evidences:
            source = ev.get('source', 'unknown')
            score = max(0.0, min(1.0, ev.get('score', 0.5)))
            weight = ev.get('weight', self._base_weights.get(source, 0.1))
            # mass(A) = score * weight, m(¬A) = (1-score) * weight, m(Θ) = 1 - weight
            m_a = score * weight
            m_not_a = (1.0 - score) * weight
            m_theta = 1.0 - weight
            masses.append({'A': m_a, 'not_A': m_not_a, 'theta': m_theta})
            sources.append(source)

        # 检测冲突
        conflict_factor = self._detect_conflict(evidences)
        if conflict_factor > self.CONFLICT_THRESHOLD:
            self._stats['high_conflicts'] += 1
        if conflict_factor > 0:
            self._stats['conflicts'] += 1

        # 动态调权
        adjusted_weights = self._adjust_weights(
            self._base_weights, conflict_factor, evidences)

        # D-S 组合
        combined = masses[0]
        total_K = 0.0
        for i in range(1, len(masses)):
            combined, K = self._dempster_combine(combined, masses[i])
            total_K = max(total_K, K)

        final_score = combined.get('A', 0.0)
        confidence = 1.0 - combined.get('theta', 1.0)
        severity = self._classify_severity(final_score)

        return {
            'final_score': final_score,
            'confidence': confidence,
            'conflict_factor': conflict_factor,
            'severity': severity,
            'weights_used': adjusted_weights,
            'ds_combined_mass': combined,
            'sources': sources,
        }

    def _detect_conflict(self, evidences: list) -> float:
        """D-S 冲突因子 K = sum(m1(¬A)*m2(A))."""
        if len(evidences) < 2:
            return 0.0

        # 计算所有证据对的冲突
        max_K = 0.0
        for i in range(len(evidences)):
            for j in range(i + 1, len(evidences)):
                s1 = evidences[i].get('score', 0.5)
                s2 = evidences[j].get('score', 0.5)
                w1 = evidences[i].get('weight',
                                       self._base_weights.get(
                                           evidences[i].get('source', ''), 0.1))
                w2 = evidences[j].get('weight',
                                       self._base_weights.get(
                                           evidences[j].get('source', ''), 0.1))
                m1_a = s1 * w1
                m1_not_a = (1.0 - s1) * w1
                m2_a = s2 * w2
                m2_not_a = (1.0 - s2) * w2
                # 冲突 = m1(A)*m2(¬A) + m1(¬A)*m2(A)
                K = m1_a * m2_not_a + m1_not_a * m2_a
                max_K = max(max_K, K)
        return max_K

    def _adjust_weights(self, base_weights: dict,
                        conflict_factor: float,
                        evidences: list) -> dict:
        """根据冲突因子动态调整权重."""
        adjusted = dict(base_weights)

        if conflict_factor > self.CONFLICT_THRESHOLD:
            # 高冲突: 找出冲突最严重的源, 降低其权重
            scores = {ev.get('source', ''): ev.get('score', 0.5)
                       for ev in evidences}
            if scores:
                # 计算每个源与其他源的分歧度
                disagreements = {}
                for s1, sc1 in scores.items():
                    total_disagree = 0.0
                    for s2, sc2 in scores.items():
                        if s1 != s2:
                            total_disagree += abs(sc1 - sc2)
                    disagreements[s1] = total_disagree
                # 降低分歧最大的源权重, 提高一致性源权重
                max_disagree = max(disagreements.values()) if disagreements else 0
                if max_disagree > 0:
                    for source in adjusted:
                        if source in disagreements:
                            ratio = 1.0 - (disagreements[source] / max_disagree) * 0.5
                            adjusted[source] = base_weights.get(source, 0.1) * ratio
        elif conflict_factor > self.MODERATE_CONFLICT:
            # 中等冲突: 轻微调整
            for source in adjusted:
                adjusted[source] = base_weights.get(source, 0.1) * 0.9

        # 归一化
        total = sum(adjusted.values())
        if total > 0:
            for k in adjusted:
                adjusted[k] /= total
        return adjusted

    def _dempster_combine(self, m1: dict, m2: dict) -> Tuple[dict, float]:
        """D-S 组合规则, 返回 (combined_mass, conflict_K)."""
        # 冲突因子
        K = m1.get('A', 0) * m2.get('not_A', 0) + \
            m1.get('not_A', 0) * m2.get('A', 0)

        if K >= 1.0:
            # 完全冲突, 返回均匀分布
            return ({'A': 0.5, 'not_A': 0.0, 'theta': 0.5}, 1.0)

        norm = 1.0 - K
        if norm <= 0:
            norm = 1e-10

        # 组合
        combined_A = (m1.get('A', 0) * m2.get('A', 0) +
                      m1.get('A', 0) * m2.get('theta', 0) +
                      m1.get('theta', 0) * m2.get('A', 0)) / norm
        combined_not_A = (m1.get('not_A', 0) * m2.get('not_A', 0) +
                          m1.get('not_A', 0) * m2.get('theta', 0) +
                          m1.get('theta', 0) * m2.get('not_A', 0)) / norm
        combined_theta = m1.get('theta', 0) * m2.get('theta', 0) / norm

        return ({'A': combined_A, 'not_A': combined_not_A,
                 'theta': combined_theta}, K)

    def _classify_severity(self, score: float) -> str:
        """根据评分分类严重程度."""
        if score >= 0.75:
            return 'critical'
        if score >= 0.50:
            return 'high'
        if score >= 0.25:
            return 'medium'
        return 'low'

    def enhance_findings(self, findings: list) -> list:
        """对已有 findings 做冲突感知融合增强."""
        for f in findings:
            evidences = f.get('evidences', [])
            if not evidences:
                # 从 finding 字段构建证据
                evidences = []
                if f.get('static_score') is not None:
                    evidences.append({
                        'source': 'static',
                        'score': f['static_score'],
                    })
                if f.get('dynamic_score') is not None:
                    evidences.append({
                        'source': 'dynamic',
                        'score': f['dynamic_score'],
                    })
                if f.get('llm_score') is not None:
                    evidences.append({
                        'source': 'llm',
                        'score': f['llm_score'],
                    })
                if f.get('fuzzing_score') is not None:
                    evidences.append({
                        'source': 'fuzzing',
                        'score': f['fuzzing_score'],
                    })
                if f.get('symbex_score') is not None:
                    evidences.append({
                        'source': 'symbex',
                        'score': f['symbex_score'],
                    })

            if evidences:
                result = self.fuse(evidences)
                f['cms_fusion'] = result
                # 用融合结果更新 finding 的 severity
                if result['severity'] != 'unknown':
                    f['cms_severity'] = result['severity']
                if result['conflict_factor'] > self.CONFLICT_THRESHOLD:
                    f['cms_high_conflict'] = True

        return findings

    @property
    def stats(self) -> dict:
        return dict(self._stats)
