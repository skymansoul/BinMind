# 特征重要性分析器 — 多种归因方法的统一接口
# 方法: 置换重要性 / SHAP近似 (Kernel SHAP简化) / 消融分析 / Sobol指数采样
# 设计: 独立于模型类型, 只需要 predict(X) 接口

from __future__ import annotations
import math
import random
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FeatureScore:
    name: str
    index: int
    score: float          # 归一化重要性 [0, 1]
    score_std: float = 0.0  # bootstrap标准差
    method: str = ''
    rank: int = 0

@dataclass
class ImportanceReport:
    features: List[FeatureScore]
    method: str
    n_samples: int
    n_features: int
    top_features: List[FeatureScore] = field(default_factory=list)
    # 冗余特征 (高相关组)
    redundant_groups: List[Tuple[str, str, float]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'method': self.method,
            'n_features': self.n_features,
            'features': [{'name': f.name, 'index': f.index, 'score': f.score,
                          'std': f.score_std, 'rank': f.rank}
                         for f in sorted(self.features, key=lambda x: x.score, reverse=True)],
            'redundant_groups': [{'feat_a': g[0], 'feat_b': g[1], 'correlation': g[2]}
                                 for g in self.redundant_groups],
        }


class FeatureImportanceAnalyzer:
    """多方法特征重要性分析器

    支持的方法:
      - permutation: 置换特征后观察性能下降 (模型无关, 标准方法)
      - ablation: 逐一移除特征
      - shapley_sample: 简化SHAP值估计 (基于Kernel SHAP的采样近似)
      - sobol: 基于Sobol序列的全局敏感性分析 (方差分解)
      - correlation: 特征-标签相关性 (线性)

    计算复杂度 (N=样本数, D=特征数, M=置换次数):
      permutation: O(D * M * N * pred_cost)
      shapley:     O(2^D) 精确解; 采样近似 O(K * N * pred_cost)
    """

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feat_names = feature_names or []

    def analyze(self, X: List[List[float]],
                predict_fn: Callable[[List[List[float]]], List[float]],
                y: Optional[List[float]] = None,
                baseline_pred: Optional[List[float]] = None,
                method: str = 'permutation',
                n_permutations: int = 10,
                n_shapley_samples: int = 200,
                top_k: int = 20) -> ImportanceReport:
        """统一分析入口"""
        N = len(X)
        D = len(X[0]) if X else 0

        if self.feat_names and len(self.feat_names) < D:
            self.feat_names.extend([f"feat_{i}" for i in range(len(self.feat_names), D)])
        elif not self.feat_names:
            self.feat_names = [f"feat_{i}" for i in range(D)]

        if baseline_pred is None:
            baseline_pred = predict_fn(X)

        if method == 'permutation':
            scores = self._permutation_importance(
                X, predict_fn, baseline_pred, n_permutations)
        elif method == 'ablation':
            scores = self._ablation_importance(X, predict_fn, baseline_pred)
        elif method == 'shapley':
            scores = self._shapley_importance(
                X, predict_fn, baseline_pred, n_shapley_samples)
        elif method == 'sobol':
            scores = self._sobol_importance(X, predict_fn)
        elif method == 'correlation':
            if y is None:
                raise ValueError("correlation方法需要提供y标签")
            scores = self._correlation_importance(X, y)
        else:
            raise ValueError(f"未知方法: {method}")

        # 归一化和排名
        max_score = max(scores) if scores else 1.0
        if max_score > 0:
            scores = [s / max_score for s in scores]

        features = []
        for i, score in enumerate(scores):
            features.append(FeatureScore(
                name=self.feat_names[i] if i < len(self.feat_names) else f"f{i}",
                index=i, score=score, method=method,
            ))
        features.sort(key=lambda f: f.score, reverse=True)
        for rank, f in enumerate(features):
            f.rank = rank + 1

        # 冗余特征组检测
        redundant = self._find_redundant_groups(X, features[:min(30, D)])

        report = ImportanceReport(
            features=features, method=method,
            n_samples=N, n_features=D,
            top_features=features[:top_k],
            redundant_groups=redundant,
        )
        return report

    # ---------- Permutation ----------
    def _permutation_importance(self, X, predict_fn, baseline, n_perm):
        N = len(X)
        D = len(X[0]) if X else 0
        base_perf = self._pred_perf(baseline)

        scores = [0.0] * D
        for j in range(D):
            perf_drops = []
            for _ in range(n_perm):
                # 置换特征j
                X_perm = [row[:] for row in X]
                col = [X[i][j] for i in range(N)]
                random.shuffle(col)
                for i in range(N):
                    X_perm[i][j] = col[i]

                pred_perm = predict_fn(X_perm)
                perf = self._pred_perf(pred_perm)
                perf_drops.append(max(0.0, base_perf - perf))

            scores[j] = sum(perf_drops) / len(perf_drops)

        return scores

    # ---------- Ablation ----------
    def _ablation_importance(self, X, predict_fn, baseline):
        N = len(X)
        D = len(X[0]) if X else 0
        base_perf = self._pred_perf(baseline)

        scores = [0.0] * D
        for j in range(D):
            X_ablated = [row[:] for row in X]
            for i in range(N):
                X_ablated[i][j] = 0.0  # 零填充消融

            pred_abl = predict_fn(X_ablated)
            perf = self._pred_perf(pred_abl)
            scores[j] = max(0.0, base_perf - perf)

        return scores

    # ---------- Shapley采样 ----------
    def _shapley_importance(self, X, predict_fn, baseline, n_samples):
        """简化Kernel SHAP: 随机采样特征子集计算边际贡献"""
        N = len(X)
        D = len(X[0]) if X else 0
        base_perf = self._pred_perf(baseline)

        shap_scores = [0.0] * D
        shap_counts = [0] * D

        for _ in range(n_samples):
            # 随机排序
            order = list(range(D))
            random.shuffle(order)

            current_features = [row[:] for row in X]
            # 初始: 所有特征归零
            for i in range(N):
                for j in range(D):
                    current_features[i][j] = 0.0

            prev_perf = base_perf

            for feat_idx in order:
                # 将特征feat_idx恢复为真实值
                new_features = [row[:] for row in current_features]
                for i in range(N):
                    new_features[i][feat_idx] = X[i][feat_idx]

                pred = predict_fn(new_features)
                perf = self._pred_perf(pred)
                marginal = max(0.0, perf - prev_perf)

                shap_scores[feat_idx] += marginal
                shap_counts[feat_idx] += 1

                current_features = new_features
                prev_perf = perf

        return [shap_scores[j] / max(shap_counts[j], 1) for j in range(D)]

    # ---------- Sobol ----------
    def _sobol_importance(self, X, predict_fn):
        """基于Sobol序列的方差分解 (一阶敏感度指数近似)"""
        N = len(X)
        D = len(X[0]) if X else 0
        if N < 2:
            return [0.0] * D

        # 简化: 对每个特征, 固定其他特征不变, 观察输出方差
        baseline = predict_fn(X)
        total_var = sum((v - sum(baseline) / N) ** 2 for v in baseline) / max(N - 1, 1)
        if total_var < 1e-10:
            return [0.0] * D

        scores = []
        for j in range(D):
            # 保持其他特征在均值, 只变化特征j
            X_vary = []
            col_vals = [X[i][j] for i in range(N)]
            mean_other = []
            for k in range(D):
                if k == j:
                    continue
                col = [X[i][k] for i in range(N)]
                mean_other.append(sum(col) / N)

            for i in range(N):
                row = []
                other_idx = 0
                for k in range(D):
                    if k == j:
                        row.append(col_vals[i])
                    else:
                        row.append(mean_other[other_idx])
                        other_idx += 1
                X_vary.append(row)

            pred_vary = predict_fn(X_vary)
            vary_var = sum((v - sum(pred_vary) / N) ** 2 for v in pred_vary) / max(N - 1, 1)
            scores.append(min(vary_var / total_var, 1.0))

        return scores

    # ---------- Correlation ----------
    def _correlation_importance(self, X, y):
        N = len(X)
        D = len(X[0]) if X else 0
        scores = []
        for j in range(D):
            xj = [X[i][j] for i in range(N)]
            scores.append(abs(self._pearson_r(xj, y)))
        return scores

    # ---------- 冗余检测 ----------
    def _find_redundant_groups(self, X, top_features) -> List[Tuple[str, str, float]]:
        """检测高度相关的特征对"""
        redundant = []
        top_indices = [f.index for f in top_features[:min(20, len(top_features))]]
        D = len(X[0]) if X else 0
        N = len(X)

        for a_i in range(len(top_indices)):
            for b_i in range(a_i + 1, len(top_indices)):
                ai = top_indices[a_i]
                bi = top_indices[b_i]
                xa = [X[i][ai] for i in range(N)]
                xb = [X[i][bi] for i in range(N)]
                r = self._pearson_r(xa, xb)
                if abs(r) > 0.85:
                    a_name = self.feat_names[ai] if ai < len(self.feat_names) else f"f{ai}"
                    b_name = self.feat_names[bi] if bi < len(self.feat_names) else f"f{bi}"
                    redundant.append((a_name, b_name, r))

        return redundant

    # ---------- 辅助 ----------
    def _pred_perf(self, preds: List[float]) -> float:
        """预测性能度量 (方差=信息量指标, 方差越大说明模型越敏感)"""
        if not preds:
            return 0.0
        mu = sum(preds) / len(preds)
        return sum((p - mu) ** 2 for p in preds) / len(preds)

    def _pearson_r(self, x, y) -> float:
        n = len(x)
        if n < 2:
            return 0.0
        mx = sum(x) / n
        my = sum(y) / n
        sx = math.sqrt(sum((xi - mx) ** 2 for xi in x) / (n - 1))
        sy = math.sqrt(sum((yi - my) ** 2 for yi in y) / (n - 1))
        if sx < 1e-12 or sy < 1e-12:
            return 0.0
        cov = sum((x[i] - mx) * (y[i] - my) for i in range(n)) / (n - 1)
        return max(-1.0, min(1.0, cov / (sx * sy)))


def create_importance_analyzer(feature_names=None) -> FeatureImportanceAnalyzer:
    return FeatureImportanceAnalyzer(feature_names)


def analyze_permutation_importance(X, predict_fn, feature_names=None,
                                    n_perm=10) -> ImportanceReport:
    fi = FeatureImportanceAnalyzer(feature_names)
    return fi.analyze(X, predict_fn, method='permutation', n_permutations=n_perm)
