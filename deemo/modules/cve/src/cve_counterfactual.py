# 反事实解释CVE风险评分
# 反事实解释 - CVE风险评分的可操作归因
#
# 问题: SHAP/LIME给出特征贡献排名, 但不告诉防御者"怎么做才能改变评分".
# 2025-2026年研究 证实:
# SHAP归因在模型重训时高度不稳定 (不同seed导致特征排序完全翻转)
#   - 预测鲁棒性 ≠ 解释稳定性 (XGBoost RI≈0.98 但 ESI≈0.06)
# 特征重要性不能区分因果与相关
# 结论: SHAP对安全运维不可操作 - 知道"EPSS贡献了30%"无助于决策.
#
# 解决方案: 反事实解释 (Counterfactual Explanations).
# 基于Wachter et al. 的框架, 适配到CVE风险评分:
#   给定: CVE的特征向量 x, 评分模型 f, 目标类别 y'.
#   求解: x' = argmin_{x'} λ·|f(x') - y'|² + d(x, x')
#   其中 d(x, x') 为特征空间距离 (加权L1/L2混合).
#
# 反事实类型:
#   Type 1 - 最小扰动: 使评分跨过决策边界的最近邻点.
#     回答: "最少需要改变什么?"
#   Type 2 - 稀疏反事实: 限制最多k个特征可变.
#     回答: "只改一个特征能做到吗?"
#   Type 3 - 可行反事实: 仅允许某些方向的变化 (如"EPSS只能升不能降").
#     回答: "在现实约束下, 什么变化是可能的?"
#
# 本实现的三阶段管线:
#   1. 生成候选: 对每个特征独立搜索, 找到使f(x')跨界的单特征变化.
#   2. 优化: 对多特征候选, 使用坐标下降最小化 λL_pred + L_dist.
#   3. 排序: 按稀疏度、可行性、距离的综合评分排序.
#
# 设计说明:
#   1. 可行性约束: 不同于通用反事实 (Wachter/DiCE), 本实现嵌入CVE领域约束.
#      EPSS可升不可降 (一旦公开高EPSS即持久), CVSS不可变 (静态评分),
#      KEV只能0→1 (一旦收录不撤销). 这使反事实在物理上可达.
#   2. 稀疏性优先级: 安全运维偏好"改一个配置"而非"改5个参数".
#      本实现按L0伪范数 (非零变化特征数) 排序, 优先展示单/双特征方案.
#   3. 与ConformalExploitScorer集成: 反事实目标值使用共形区间边界而非点估计.
#
#
# Counterfactual Explanations without Opening the Black Box
# DiCE: Diverse Counterfactual Explanations (FAccT)
# Explainability Stability Index for Cybersecurity
# SHAP vs Counterfactual Stability in Security Applications

import math
from typing import Dict, List, Optional, Set, Tuple, Any


# 领域约束
# 每个CVE特征的可行性规则: (可降低, 可升高, 步长, 下界, 上界)
_FEATURE_CONSTRAINTS = {
    "cvss_score":       (False, False, 0.1, 0.0, 1.0),   # CVSS发布后不变
    "epss_score":       (True,  True,  0.01, 0.0, 1.0),   # EPSS可升可降 (30天滑动窗口)
    "epss_percentile":  (False, True,  0.01, 0.0, 1.0),   # 同上
    "cisa_kev":         (False, True,  1.0,  0.0, 1.0),   # 只能0→1
    "exploit_maturity": (False, True,  0.25, 0.0, 1.0),   # 只能升级
    "days_since_pub":   (True,  False, 1.0,  0.0, 1.0),   # 时间流逝自然衰减
    "cwe_rarity":       (False, False, 0.0,  0.0, 1.0),   # CWE类型不可变
    "has_fix":          (False, True,  1.0,  0.0, 1.0),   # 只能0→1 (发布补丁)
    "ref_count":        (False, True,  0.1,  0.0, 1.0),   # 可增加引用
    "cpe_count":        (False, True,  0.0,  0.0, 1.0),   # CPE范围不可缩减
}


class CounterfactualExplainer:
    """CVE风险评分的反事实解释器.

    生成"最小可行变化"使评分从当前类别跨越到目标类别.

    使用模式:
      explainer = CounterfactualExplainer(scoring_fn, feature_names)
      cfs = explainer.explain(features, target_class='LOW')
      # cfs = [{features, distance, sparsity, changes}, ...]
    """

    def __init__(self, scoring_fn, feature_names: List[str],
                 decision_thresholds: Optional[Dict[str, float]] = None):
        """
        scoring_fn: f(features) -> float in [0,1].
        feature_names: 特征名列表 (顺序与features参数一致).
        decision_thresholds: 类别阈值, 默认 {CRITICAL:0.75, HIGH:0.5, MEDIUM:0.25, LOW:0}.
        """
        self._scoring_fn = scoring_fn
        self._feature_names = list(feature_names)
        self._thresholds = decision_thresholds or {
            "CRITICAL": 0.75, "HIGH": 0.50, "MEDIUM": 0.25, "LOW": 0.0,
        }
        self._F = len(feature_names)

    def explain(self, features: List[float],
                target_class: str = "LOW",
                max_features_to_change: int = 3,
                n_counterfactuals: int = 5,
                lambda_pred: float = 10.0,
                lambda_dist: float = 1.0,
                lambda_sparse: float = 2.0) -> List[Dict[str, Any]]:
        """生成反事实解释。

        features 为当前特征向量 (需与 feature_names 顺序一致),
        target_class 为目标风险类别, max_features_to_change 为
        最多改变的特征数 (稀疏性约束), n_counterfactuals 为最多
        返回个数, lambda_pred/lambda_dist/lambda_sparse 为损失
        权重; 返回按综合评分排序的反事实列表。
        """
        current_score = self._scoring_fn(features)
        target_bound = self._threshold_to_bound(target_class)

        # 检查是否已在目标类别中
        current_class = self._score_to_class(current_score)
        if current_class == target_class:
            return [{"message": f"already in {target_class}",
                     "current_score": round(current_score, 4)}]

        candidates = []

        # 阶段1: 单特征候选 (最简单, 优先)
        for feat_idx in range(self._F):
            feat_name = self._feature_names[feat_idx]
            constraints = _FEATURE_CONSTRAINTS.get(feat_name, (True, True, 0.1, 0.0, 1.0))
            can_decrease, can_increase, step, lo, hi = constraints

            # 确定搜索方向
            if target_class in ("LOW", "MEDIUM"):
                # 需要降低分数 → 降低特征值 (如果可以)
                if can_decrease:
                    cf = self._line_search(features, feat_idx, -step, lo,
                                           target_bound, max_steps=200)
                    if cf:
                        candidates.append(cf)
            else:
                # 需要升高分数 → 升高特征值
                if can_increase:
                    cf = self._line_search(features, feat_idx, +step, hi,
                                           target_bound, max_steps=200)
                    if cf:
                        candidates.append(cf)

        # 阶段2: 双特征候选 (组合搜索)
        if max_features_to_change >= 2:
            # 对高影响力特征组合进行坐标下降
            for i in range(self._F):
                for j in range(i + 1, self._F):
                    if len(candidates) >= n_counterfactuals * 2:
                        break
                    cf = self._coordinate_descent_2d(
                        features, i, j, target_bound, lambda_pred, lambda_dist
                    )
                    if cf:
                        candidates.append(cf)

        # 阶段3: 排序与筛选
        scored = []
        for cf in candidates:
            modified_features = cf["features"]
            # 特征距离 (L2归一化)
            dist = math.sqrt(sum(
                (modified_features[k] - features[k]) ** 2
                for k in range(self._F)
            )) / math.sqrt(self._F)
            # 稀疏度 (变化特征数)
            sparsity = sum(
                1 for k in range(self._F)
                if abs(modified_features[k] - features[k]) > 1e-6
            )
            # 可行性惩罚
            feasibility = self._feasibility_score(features, modified_features)
            # 综合分数
            composite = lambda_dist * dist + lambda_sparse * sparsity - feasibility

            scored.append({
                "features": [round(v, 4) for v in modified_features],
                "changes": {
                    self._feature_names[k]: round(modified_features[k] - features[k], 4)
                    for k in range(self._F)
                    if abs(modified_features[k] - features[k]) > 1e-6
                },
                "original_score": round(current_score, 4),
                "counterfactual_score": round(self._scoring_fn(modified_features), 4),
                "distance": round(dist, 4),
                "sparsity": sparsity,
                "feasibility": round(feasibility, 4),
                "composite_score": round(composite, 4),
                "target_class": target_class,
            })

        scored.sort(key=lambda x: (x["sparsity"], x["composite_score"]))
        return scored[:n_counterfactuals]

    def _line_search(self, features: List[float], feat_idx: int,
                     direction: float, bound: float,
                     target_bound: float, max_steps: int = 200
                     ) -> Optional[Dict[str, Any]]:
        """沿单个特征方向线性搜索, 找到使评分跨界的最近点."""
        modified = list(features)
        step = abs(direction)
        sign = 1 if direction > 0 else -1
        current_score = self._scoring_fn(features)
        # 下降方向: 需要评分低于上界; 上升方向: 需要评分高于下界
        need_lower = target_bound < current_score

        for s in range(1, max_steps + 1):
            new_val = features[feat_idx] + sign * step * s
            if sign > 0 and new_val > bound:
                break
            if sign < 0 and new_val < bound:
                break
            modified[feat_idx] = new_val
            score = self._scoring_fn(modified)
            if need_lower and score <= target_bound:
                return {"features": list(modified), "n_changes": 1}
            if not need_lower and score >= target_bound:
                return {"features": list(modified), "n_changes": 1}
        return None

    def _coordinate_descent_2d(self, features: List[float],
                                i: int, j: int,
                                target_bound: float,
                                lambda_pred: float,
                                lambda_dist: float,
                                max_iter: int = 100,
                                lr: float = 0.01) -> Optional[Dict[str, Any]]:
        """坐标下降法优化双特征反事实."""
        modified = list(features)
        ci = _FEATURE_CONSTRAINTS.get(self._feature_names[i],
                                       (True, True, 0.1, 0.0, 1.0))
        cj = _FEATURE_CONSTRAINTS.get(self._feature_names[j],
                                       (True, True, 0.1, 0.0, 1.0))

        for _ in range(max_iter):
            # 坐标i
            best_i = modified[i]
            best_loss = float('inf')
            for delta in [0, -ci[2], +ci[2], -2*ci[2], +2*ci[2]]:
                trial = modified[i] + delta
                if trial < ci[3] or trial > ci[4]:
                    continue
                if delta < 0 and not ci[0]:
                    continue
                if delta > 0 and not ci[1]:
                    continue
                orig_val = modified[i]
                modified[i] = trial
                pred = self._scoring_fn(modified)
                dist = math.sqrt(
                    (modified[i] - features[i]) ** 2 +
                    (modified[j] - features[j]) ** 2
                )
                loss = lambda_pred * (pred - target_bound) ** 2 + lambda_dist * dist
                modified[i] = orig_val
                if loss < best_loss:
                    best_loss = loss
                    best_i = trial
            modified[i] = best_i

            # 坐标j
            best_j = modified[j]
            best_loss = float('inf')
            for delta in [0, -cj[2], +cj[2], -2*cj[2], +2*cj[2]]:
                trial = modified[j] + delta
                if trial < cj[3] or trial > cj[4]:
                    continue
                if delta < 0 and not cj[0]:
                    continue
                if delta > 0 and not cj[1]:
                    continue
                orig_val = modified[j]
                modified[j] = trial
                pred = self._scoring_fn(modified)
                dist = math.sqrt(
                    (modified[i] - features[i]) ** 2 +
                    (modified[j] - features[j]) ** 2
                )
                loss = lambda_pred * (pred - target_bound) ** 2 + lambda_dist * dist
                modified[j] = orig_val
                if loss < best_loss:
                    best_loss = loss
                    best_j = trial
            modified[j] = best_j

            # 收敛: 检查是否达成目标
            pred = self._scoring_fn(modified)
            current_score = self._scoring_fn(features)
            need_lower = target_bound < current_score
            crossed = (need_lower and pred <= target_bound) or \
                      (not need_lower and pred >= target_bound)
            if crossed and abs(pred - target_bound) < abs(current_score - target_bound):
                return {"features": list(modified), "n_changes": 2}

        return None  # 未找到可行解

    def _feasibility_score(self, original: List[float],
                           modified: List[float]) -> float:
        """计算反事实的可行性评分 (越高越好).

        惩罚不可行特征变化: CVSS改变=严重惩罚, KEV 1→0=最大惩罚.
        """
        penalty = 0.0
        for k in range(self._F):
            delta = modified[k] - original[k]
            if abs(delta) < 1e-6:
                continue
            name = self._feature_names[k]
            constraints = _FEATURE_CONSTRAINTS.get(name)
            if constraints is None:
                continue
            can_dec, can_inc, _, _, _ = constraints
            if delta < 0 and not can_dec:
                penalty += 2.0  # 不可逆方向
            if delta > 0 and not can_inc:
                penalty += 2.0
        return -penalty

    def _score_to_class(self, score: float) -> str:
        for cls_name in ["CRITICAL", "HIGH", "MEDIUM"]:
            if score >= self._thresholds[cls_name]:
                return cls_name
        return "LOW"

    def _threshold_to_bound(self, target_class: str) -> float:
        """目标类别的边界值."""
        if target_class == "LOW":
            return self._thresholds["MEDIUM"] - 0.01
        elif target_class == "MEDIUM":
            return self._thresholds["HIGH"] - 0.01
        elif target_class == "HIGH":
            return self._thresholds["CRITICAL"] - 0.01
        else:
            return self._thresholds["CRITICAL"] + 0.01


# 便捷接口

def explain_cve_risk(scoring_fn, features: List[float],
                     feature_names: Optional[List[str]] = None,
                     target_class: str = "LOW") -> List[Dict[str, Any]]:
    """一站式反事实解释."""
    if feature_names is None:
        feature_names = [
            "cvss_score", "epss_score", "epss_percentile", "cisa_kev",
            "exploit_maturity", "days_since_pub", "cwe_rarity",
            "has_fix", "ref_count", "cpe_count",
        ][:len(features)]
    explainer = CounterfactualExplainer(scoring_fn, feature_names)
    return explainer.explain(features, target_class=target_class)


def build_scoring_fn_from_weights(weights: Dict[str, float],
                                  feature_names: List[str]) -> callable:
    """从特征权重构建评分函数 - 用于测试/demo."""
    w = [weights.get(n, 0.0) for n in feature_names]

    def scoring_fn(features: List[float]) -> float:
        return min(1.0, max(0.0, sum(
            features[i] * w[i] for i in range(len(features))
        )))
    return scoring_fn
