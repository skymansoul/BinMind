# 数据质量评估器 — 检测和修复ML训练数据中的常见质量问题
# 核心: 缺失值/异常值/类别不平衡/标签噪声/特征冗余检测
# 设计: 不对现有pipeline做假设, 作为独立的质量审计层使用

from __future__ import annotations
import math
import random
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class QualityIssue:
    """数据质量问题"""
    kind: str                    # missing_value, 离群点, class_imbalance, label_noise, feature_redundancy, duplicate
    severity: str                # low, medium, high, critical
    description: str
    affected_indices: List[int] = field(default_factory=list)
    affected_features: List[str] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class QualityReport:
    """数据质量报告"""
    dataset_name: str
    n_samples: int
    n_features: int
    n_classes: int
    issues: List[QualityIssue] = field(default_factory=list)
    completeness_score: float = 1.0     # 完整性: 非缺失值比例
    balance_score: float = 1.0          # 平衡性: 类别分布的均匀度
    consistency_score: float = 1.0      # 一致性: 重复/冲突的比例
    reliability_score: float = 1.0      # 可靠性: 标签噪声估计
    overall_score: float = 0.0          # 综合质量分数 [0, 1]

    def to_dict(self) -> dict:
        return {
            'dataset_name': self.dataset_name,
            'n_samples': self.n_samples, 'n_features': self.n_features,
            'n_classes': self.n_classes,
            'issues': [{'kind': i.kind, 'severity': i.severity,
                        'description': i.description,
                        'n_affected': len(i.affected_indices),
                        'suggestion': i.suggestion} for i in self.issues],
            'scores': {
                'completeness': self.completeness_score,
                'balance': self.balance_score,
                'consistency': self.consistency_score,
                'reliability': self.reliability_score,
                'overall': self.overall_score,
            },
        }


# ---------------------------------------------------------------------------
# 质量评估器
# ---------------------------------------------------------------------------

class DataQualityAssessor:
    """数据质量评估器

    四个评估维度:
      1. 完整性 (Completeness): 缺失值检测
      2. 平衡性 (Balance): 类别分布 + 特征分布
      3. 一致性 (Consistency): 重复样本 + 冲突标签
      4. 可靠性 (Reliability): 标签噪声估计 (通过置信度分析)

    每个维度产生 QualityIssue 列表和 0-1 分数
    """

    def __init__(self, missing_threshold: float = 0.3,
                 outlier_std: float = 3.0,
                 imbalance_ratio: float = 0.1,
                 duplication_threshold: float = 0.99,
                 noise_confidence: float = 0.4):
        self.miss_thresh = missing_threshold
        self.outlier_std = outlier_std
        self.imbalance_ratio = imbalance_ratio
        self.dup_thresh = duplication_threshold
        self.noise_conf = noise_confidence

    def assess(self, X: List[List[float]], y: Optional[List[int]] = None,
               feature_names: Optional[List[str]] = None,
               sample_ids: Optional[List[str]] = None,
               dataset_name: str = "unnamed",
               prediction_confidences: Optional[List[float]] = None) -> QualityReport:
        """全维度质量评估

        Args:
            X: 特征矩阵 [N, D]
            y: 标签列表 (可选)
            feature_names: 特征名称 (可选)
            sample_ids: 样本标识 (可选, 用于去重)
            dataset_name: 数据集名称
            prediction_confidences: 模型预测置信度 (可选, 用于标签噪声估计)
        """
        N = len(X)
        D = len(X[0]) if X else 0
        n_classes = len(set(y)) if y else 1

        report = QualityReport(
            dataset_name=dataset_name,
            n_samples=N, n_features=D, n_classes=n_classes,
        )

        if N == 0:
            report.issues.append(QualityIssue(
                kind='empty_dataset', severity='critical',
                description='数据集为空',
                suggestion='检查数据加载逻辑'))
            report.overall_score = 0.0
            return report

        # 1. 完整性检查
        comp_issues = self._check_completeness(X, feature_names)
        report.issues.extend(comp_issues)
        report.completeness_score = self._calc_completeness(X, comp_issues)

        # 2. 平衡性检查
        if y is not None:
            bal_issues = self._check_balance(y, X, feature_names)
            report.issues.extend(bal_issues)
            report.balance_score = self._calc_balance(y)

        # 3. 一致性检查
        cons_issues = self._check_consistency(X, y, sample_ids)
        report.issues.extend(cons_issues)
        report.consistency_score = self._calc_consistency(X, cons_issues, sample_ids)

        # 4. 可靠性检查
        if prediction_confidences is not None and y is not None:
            rel_issues = self._check_reliability(y, prediction_confidences)
            report.issues.extend(rel_issues)
            report.reliability_score = self._calc_reliability(y, prediction_confidences)
        else:
            report.reliability_score = 1.0

        # 综合分数
        report.overall_score = (
            report.completeness_score * 0.30 +
            report.balance_score * 0.25 +
            report.consistency_score * 0.25 +
            report.reliability_score * 0.20
        )

        return report

    def _check_completeness(self, X, feature_names) -> List[QualityIssue]:
        issues = []
        N = len(X)
        D = len(X[0]) if X else 0

        # 检测包含NaN/Inf的特征
        nan_cols = []
        for j in range(D):
            nan_count = 0
            for i in range(N):
                val = X[i][j]
                if math.isnan(val) if isinstance(val, float) else False:
                    nan_count += 1
                elif math.isinf(val) if isinstance(val, float) else False:
                    nan_count += 1
            if nan_count > 0:
                nan_cols.append((j, nan_count))

        for j, count in nan_cols:
            ratio = count / N
            feat_name = feature_names[j] if feature_names and j < len(feature_names) else f"feat_{j}"
            severity = 'critical' if ratio > 0.5 else ('high' if ratio > 0.2 else 'medium')
            issues.append(QualityIssue(
                kind='missing_value',
                severity=severity,
                description=f'特征 "{feat_name}" 包含 {count}/{N} ({ratio:.1%}) 无效值',
                affected_features=[feat_name],
                suggestion=f'考虑填充均值/中位数或丢弃该特征' if ratio < 0.3
                           else f'该特征缺失率过高({ratio:.1%}), 建议丢弃',
            ))

        # 检测常数列
        for j in range(D):
            vals = set()
            for i in range(min(N, 1000)):  # 采样检查
                vals.add(X[i][j])
            if len(vals) <= 1:
                feat_name = feature_names[j] if feature_names and j < len(feature_names) else f"feat_{j}"
                issues.append(QualityIssue(
                    kind='constant_feature',
                    severity='low',
                    description=f'特征 "{feat_name}" 为常数, 无信息量',
                    affected_features=[feat_name],
                    suggestion='移除该特征或检查数据来源',
                ))

        return issues

    def _check_balance(self, y, X, feature_names) -> List[QualityIssue]:
        issues = []
        N = len(y)
        counter = Counter(y)
        if not counter:
            return issues

        max_count = max(counter.values())
        min_count = min(counter.values())

        if min_count / max(max_count, 1) < self.imbalance_ratio:
            most_common = counter.most_common(2)
            issues.append(QualityIssue(
                kind='class_imbalance',
                severity='high',
                description=f'类别严重不平衡: {most_common[0][0]}={most_common[0][1]} vs {most_common[1][0]}={most_common[1][1]}',
                suggestion='考虑过采样(SMOTE)、欠采样或类别加权损失',
            ))

        # 异常值检测 (基于Z-score)
        D = len(X[0]) if X else 0
        outlier_cols = []
        for j in range(D):
            col_vals = [X[i][j] for i in range(N)]
            mu = sum(col_vals) / N
            std = math.sqrt(sum((v - mu) ** 2 for v in col_vals) / max(N - 1, 1))
            if std < 1e-8:
                continue

            n_outliers = sum(1 for v in col_vals
                            if abs(v - mu) > self.outlier_std * std)
            if n_outliers > N * 0.05:
                feat_name = feature_names[j] if feature_names and j < len(feature_names) else f"feat_{j}"
                outlier_cols.append((feat_name, n_outliers))

        for feat_name, count in outlier_cols[:3]:  # 最多报告3个
            issues.append(QualityIssue(
                kind='outliers',
                severity='medium',
                description=f'特征 "{feat_name}" 含 {count} 个异常值 (> {self.outlier_std}σ)',
                affected_features=[feat_name],
                suggestion='考虑Winsorization截尾或使用鲁棒缩放',
            ))

        return issues

    def _check_consistency(self, X, y, sample_ids) -> List[QualityIssue]:
        issues = []
        N = len(X)

        # 重复样本检测
        dup_groups = self._find_duplicates(X, sample_ids)
        if dup_groups:
            total_dup = sum(len(g) - 1 for g in dup_groups)
            issues.append(QualityIssue(
                kind='duplicate_samples',
                severity='medium',
                description=f'发现 {len(dup_groups)} 组重复样本, 共 {total_dup} 个冗余',
                affected_indices=[idx for g in dup_groups for idx in g[1:]],
                suggestion='去重以避免数据泄露和过拟合',
            ))

            # 冲突标签检测
            if y is not None:
                conflicts = []
                for group in dup_groups:
                    labels = [y[i] for i in group]
                    if len(set(labels)) > 1:
                        conflicts.append(group)
                if conflicts:
                    issues.append(QualityIssue(
                        kind='label_conflict',
                        severity='high',
                        description=f'{len(conflicts)} 组重复样本有冲突标签 (相同特征不同类别)',
                        affected_indices=[idx for g in conflicts for idx in g],
                        suggestion='检查数据标注质量, 移除冲突样本或人工重新标注',
                    ))

        return issues

    def _find_duplicates(self, X, sample_ids) -> List[List[int]]:
        """基于特征哈希的重复检测"""
        N = len(X)
        if N < 2:
            return []

        # 使用哈希桶加速
        buckets: Dict[str, List[int]] = defaultdict(list)
        for i in range(N):
            # 特征值哈希 (基于前几个维度和统计量)
            feat = X[i]
            key_parts = []
            for j in range(min(8, len(feat))):
                key_parts.append(f"{feat[j]:.4f}")
            # 加上均值和标准差做二次校验
            mu = sum(feat) / len(feat)
            key_parts.append(f"{mu:.4f}")
            key = hashlib.md5('|'.join(key_parts).encode()).hexdigest()[:16]
            buckets[key].append(i)

        dup_groups = []
        for indices in buckets.values():
            if len(indices) < 2:
                continue
            # 精确比较
            for a_idx in range(len(indices)):
                for b_idx in range(a_idx + 1, len(indices)):
                    a, b = indices[a_idx], indices[b_idx]
                    # 余弦相似度
                    dot = sum(X[a][j] * X[b][j] for j in range(len(X[a])))
                    na = math.sqrt(sum(v * v for v in X[a]))
                    nb = math.sqrt(sum(v * v for v in X[b]))
                    sim = dot / max(na * nb, 1e-12)
                    if sim >= self.dup_thresh:
                        dup_groups.append([a, b])

        # 合并传递重复组
        merged = self._merge_dup_groups(dup_groups)
        return [g for g in merged if len(g) >= 2]

    def _merge_dup_groups(self, pairs: List[List[int]]) -> List[List[int]]:
        """合并重叠的重复组 (并查集)"""
        if not pairs:
            return []

        parent = {}
        def find(x):
            if x not in parent:
                parent[x] = x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for a, b in pairs:
            union(a, b)

        groups: Dict[int, List[int]] = defaultdict(list)
        for node in parent:
            groups[find(node)].append(node)

        return list(groups.values())

    def _check_reliability(self, y, confidences) -> List[QualityIssue]:
        """标签噪声估计 — 低置信度正确预测可能指示噪声"""
        issues = []
        low_conf_correct = []
        low_conf_incorrect = []

        for i, (label, conf) in enumerate(zip(y, confidences)):
            pred_label = 1 if conf >= 0.5 else 0
            if conf < self.noise_conf * 2:
                if pred_label == label:
                    low_conf_correct.append(i)
                else:
                    low_conf_incorrect.append(i)

        if low_conf_incorrect:
            issues.append(QualityIssue(
                kind='possible_label_noise',
                severity='medium',
                description=f'{len(low_conf_incorrect)} 样本模型低置信度且预测错误, 可能是标签噪声',
                affected_indices=low_conf_incorrect[:50],
                suggestion='人工检查这些样本的标注正确性',
            ))

        # 置信度校准检查
        if confidences:
            avg_conf = sum(confidences) / len(confidences)
            if avg_conf < 0.5:
                issues.append(QualityIssue(
                    kind='low_model_confidence',
                    severity='low',
                    description=f'模型平均置信度仅 {avg_conf:.3f}, 可能表示数据质量或模型容量不足',
                    suggestion='检查特征质量或增加模型容量',
                ))

        return issues

    # ---- 分数计算 ----
    def _calc_completeness(self, X, issues) -> float:
        nan_issues = [i for i in issues if i.kind == 'missing_value']
        if not nan_issues:
            return 1.0
        worst_ratio = max(
            (len(i.affected_indices) / max(len(X), 1) if i.affected_indices else 0.5)
            for i in nan_issues
        ) if nan_issues else 0.0
        return 1.0 - worst_ratio * 0.5

    def _calc_balance(self, y) -> float:
        counter = Counter(y)
        if len(counter) < 2:
            return 0.5
        counts = list(counter.values())
        # 归一化熵
        total = sum(counts)
        probs = [c / total for c in counts]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        max_entropy = math.log2(len(counts))
        return entropy / max(max_entropy, 1e-8)

    def _calc_consistency(self, X, issues, sample_ids) -> float:
        dup_issues = [i for i in issues if i.kind == 'duplicate_samples']
        if not dup_issues:
            return 1.0
        dup_ratio = len(dup_issues[0].affected_indices) / max(len(X), 1)
        return 1.0 - min(dup_ratio * 2.0, 1.0)

    def _calc_reliability(self, y, confidences) -> float:
        if not confidences:
            return 1.0
        avg_conf = sum(confidences) / len(confidences)
        return min(1.0, avg_conf * 2.0)


# ---------------------------------------------------------------------------
# 工厂
# ---------------------------------------------------------------------------

def create_quality_assessor(missing_threshold: float = 0.3,
                            outlier_std: float = 3.0) -> DataQualityAssessor:
    return DataQualityAssessor(missing_threshold=missing_threshold,
                               outlier_std=outlier_std)


def assess_data_quality(X, y=None, feature_names=None, **kwargs):
    """一次性质量评估"""
    assessor = create_quality_assessor(**kwargs)
    return assessor.assess(X, y, feature_names=feature_names)
