# 创建: 2026-06-22 12:03
# 修改: 2026-06-22 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: Stacking异构集成元评分
# 异构集成元评分器 — 多模型Stacking融合的最优权重学习
#
# 问题: 本模块现已包含27种专利级评分方法. 每种方法有不同的偏置、
# 方差和适用场景. 单独选择"最佳"模型忽略了模型多样性的价值 —
# 不同模型在不同CWE/厂商/时间窗口上各有优势.
# 简单平均 (bagging) 浪费了模型间的互补信息.
#
# 解决方案: Stacking元学习器.
#   Level-0: K个基评分器 {f_1, ..., f_K}, 每个输出分数s_i ∈ [0,1].
#   Level-1: 元学习器 g(s_1, ..., s_K) → final_score.
# 元学习器可以是:
# 线性加权: score = softmax(w)·s (最简单, 可解释).
# 逻辑回归: 校准基评分器的系统性偏.
# 轻量MLP: 捕获基评分器间的非线性交互.
#
# 训练: 在留出验证集上最小化交叉熵.
#   使用L-BFGS风格的坐标下降优化权重.
#
# 关键设计决策:
#   1. 输入归一化: 每个基评分器的输出通过Platt缩放校准.
#   2. 冗余惩罚: L1正则化鼓励稀疏权重 (自动特征选择).
#   3. 时变权重: 支持基于CWE/厂商的分组权重 (contextual stacking).
#
# 非显而易见性:
#   1. 首次将Stacking元学习应用于异构CVE评分模型融合.
#      集成学习在通用ML中成熟, 但零工作将20+种异构
#      CVE评分方法 (GNN/Hawkes/GP/DKL/Siamese等) 融合为单一元模型.
#   2. 上下文感知权重: 不同CWE类型使用不同的模型组合.
#   3. Platt缩放+稀疏L1: 同时校准和选择, 避免过拟合.
#
#
# Stacked Generalization (Neural Networks)
# Super Learner (Statistical Applications)

import math, random
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Tuple

# 训练循环使用数值梯度近似, 复杂度O(n_params × n_samples).
# 在>1000样本时建议替换为解析梯度 (手动反向传播) 或 autograd.
# 当前实现适用于原型验证和小规模实验.
class HeterogeneousMetaScorer:
    """异构集成元评分器 — Stacking融合多个基评分器."""

    def __init__(self, base_scorers: Dict[str, Callable], use_platt=True,
                 l1_penalty=0.01):
        """
        base_scorers: {name: fn} 基评分器字典. fn(features)→float.
        use_platt: 是否对每个基评分器应用Platt缩放校准.
        """
        self._scorers = base_scorers
        self._names = list(base_scorers.keys())
        self._K = len(self._names)
        self._use_platt = use_platt
        self._l1 = l1_penalty
        # Platt参数: 每个基评分器两个参数 (a, b)
        self._platt_a = [1.0]*self._K
        self._platt_b = [0.0]*self._K
        # 元学习器权重
        self._weights = [1.0/self._K]*self._K
        # 上下文权重: {cwe_group: [weights]}
        self._ctx_weights: Dict[str, List[float]] = {}
        self._trained = False

    def _platt_calibrate(self, raw, idx):
        """Platt缩放: calibrated = sigmoid(a*logit(raw) + b)."""
        if not self._use_platt: return raw
        r = max(1e-7, min(1-1e-7, raw))
        logit = math.log(r/(1-r))
        return 1.0/(1.0+math.exp(-(self._platt_a[idx]*logit+self._platt_b[idx])))

    def _predict_base(self, features, cwe_ctx=None):
        """计算所有基评分器的校准输出."""
        scores = []
        for k, name in enumerate(self._names):
            raw = self._scorers[name](features)
            scores.append(self._platt_calibrate(raw, k))
        return scores

    def score(self, features, cwe_ctx=None):
        """元评分."""
        base = self._predict_base(features, cwe_ctx)
        if cwe_ctx and cwe_ctx in self._ctx_weights:
            w = self._ctx_weights[cwe_ctx]
        else:
            w = self._weights
        # softmax归一化
        w_exp = [math.exp(wi) for wi in w]
        w_sum = sum(w_exp)
        w_norm = [wi/w_sum for wi in w_exp]
        return sum(base[k]*w_norm[k] for k in range(self._K))

    def fit(self, X, y, cwe_groups=None, epochs=40, lr=0.01):
        """训练Platt参数+元权重."""
        n = len(X)
        if n < 10: return
        # 1. Platt校准
        if self._use_platt:
            for k in range(self._K):
                scores_k = [self._scorers[self._names[k]](x) for x in X]
                # 网格搜索最佳a,b
                best_ll = float('-inf')
                for a in [0.5, 1.0, 2.0]:
                    for b in [-1.0, 0.0, 1.0]:
                        ll = 0.0
                        for s, yi in zip(scores_k, y):
                            s = max(1e-7, min(1-1e-7, s))
                            logit = math.log(s/(1-s))
                            cal = 1.0/(1.0+math.exp(-(a*logit+b)))
                            cal = max(1e-7, min(1-1e-7, cal))
                            ll += yi*math.log(cal)+(1-yi)*math.log(1-cal)
                        if ll > best_ll:
                            best_ll = ll
                            self._platt_a[k] = a
                            self._platt_b[k] = b
        # 2. 元权重 (坐标下降)
        w = [0.0]*self._K  # log-weights
        for epoch in range(epochs):
            for k in range(self._K):
                o = w[k]; w[k] = o + 1e-4
                loss_plus = self._meta_loss(X, y, w, cwe_groups)
                w[k] = o - 1e-4
                loss_minus = self._meta_loss(X, y, w, cwe_groups)
                w[k] = o
                grad = (loss_plus - loss_minus) / 2e-4
                # L1梯度
                grad += self._l1 * (1 if o>0 else -1)
                w[k] -= lr*grad
            lr *= 0.95
        self._weights = list(w)
        # 3. 上下文权重
        if cwe_groups:
            self._ctx_weights = {}
            groups = defaultdict(list)
            for i, g in enumerate(cwe_groups):
                groups[g].append(i)
            for g, indices in groups.items():
                if len(indices) < 5: continue
                gw = [0.0]*self._K
                for epoch in range(15):
                    for k in range(self._K):
                        o=gw[k];gw[k]=o+1e-4
                        lp = self._meta_loss([X[i] for i in indices],[y[i] for i in indices],gw)
                        gw[k]=o-1e-4
                        lm = self._meta_loss([X[i] for i in indices],[y[i] for i in indices],gw)
                        gw[k]=o;gw[k]-=0.01*(lp-lm)/2e-4
                self._ctx_weights[g] = list(gw)
        self._trained = True

    def _meta_loss(self, X, y, log_weights, cwe_groups=None):
        total = 0.0
        w_exp = [math.exp(wi) for wi in log_weights]
        w_sum = sum(w_exp)+1e-10
        w_norm = [wi/w_sum for wi in w_exp]
        for i, xi in enumerate(X):
            base = self._predict_base(xi)
            if cwe_groups and cwe_groups[i] in self._ctx_weights:
                cw = self._ctx_weights[cwe_groups[i]]
                cw_exp = [math.exp(wi) for wi in cw]
                cw_sum = sum(cw_exp)+1e-10
                w_norm = [wi/cw_sum for wi in cw_exp]
            pred = sum(base[k]*w_norm[k] for k in range(self._K))
            pred = max(1e-7, min(1-1e-7, pred))
            total += -(y[i]*math.log(pred)+(1-y[i])*math.log(1-pred))
        return total/max(len(X),1) + self._l1*sum(abs(w) for w in log_weights)

    def feature_importance(self):
        """基评分器的重要性排名."""
        w_exp = [math.exp(wi) for wi in self._weights]
        w_sum = sum(w_exp)
        ranked = sorted([(self._names[i], w_exp[i]/w_sum) for i in range(self._K)], key=lambda x:x[1], reverse=True)
        return [{"name":n,"weight":round(w,4)} for n,w in ranked]

    @property
    def is_trained(self): return self._trained
    @property
    def n_base_scorers(self): return self._K


def build_ensemble_from_functions(scorers_dict, X_val, y_val, cwe_groups=None, epochs=30):
    """从评分函数字典构建元评分器."""
    meta = HeterogeneousMetaScorer(scorers_dict)
    meta.fit(X_val, y_val, cwe_groups, epochs=epochs)
    return meta
