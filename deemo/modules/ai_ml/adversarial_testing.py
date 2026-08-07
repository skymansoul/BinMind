# 对抗鲁棒性测试 : 对抗扰动→测量性能退化
# 依据: GraphRAG Under Fire
# GragPoison三策略: 关系注入/增强/叙述构造
# 对抗样本→敏感性测量→鲁棒性报告

from __future__ import annotations
import math
import random
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AttackMethod(Enum):
    FGSM = 'fgsm'                    # 快速梯度符号法(FGSM)
    PGD = 'pgd'                      # 投影梯度下降(PGD)(PGD)(PGD)(PGD)
    EDGE_FLIP = 'edge_flip'          # 图结构扰动: 随机边翻转
    FEATURE_NOISE = 'feature_noise'   # 特征加噪
    GRAGPOISON_INJECT = 'gragpoison'  # GragPoison关系注入
    LABEL_FLIP = 'label_flip'        # 标签翻转
    NODE_INJECTION = 'node_injection' # 虚假节点注入


@dataclass
class AdversarialSample:
    original_idx: int
    perturbed_features: Optional[List[float]] = None
    perturbed_adj: Optional[List[List[int]]] = None
    original_pred: float = 0.0
    perturbed_pred: float = 0.0
    prediction_change: float = 0.0
    attack_method: str = ''
    was_successful: bool = False


@dataclass
class RobustnessReport:
    method: str
    n_samples_tested: int
    n_successful_attacks: int
    success_rate: float
    avg_prediction_change: float
    max_prediction_change: float
    samples: List[AdversarialSample] = field(default_factory=list)
    robustness_score: float = 0.0  # 0=脆弱, 1=鲁棒

    def to_dict(self) -> dict:
        return {
            'method': self.method,
            'n_tested': self.n_samples_tested,
            'n_successful': self.n_successful_attacks,
            'success_rate': self.success_rate,
            'avg_change': self.avg_prediction_change,
            'max_change': self.max_prediction_change,
            'robustness_score': self.robustness_score,
        }


# 辅助

def _at_clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def _at_vec_diff(a: List[float], b: List[float]) -> float:
    return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(len(a))))


# 对抗攻击

class AdversarialTester:
    """对抗鲁棒性测试器

    支持多种攻击方法, 每种方法针对不同的脆弱性维度:
      - 特征空间对抗 (FGSM/PGD)
      - 图结构对抗 (Edge Flip / GragPoison)
      - 数据投毒 (Label Flip)
    """

    def __init__(self, epsilon: float = 0.1, pgd_steps: int = 5,
                 pgd_step_size: float = 0.02):
        self.eps = epsilon
        self.pgd_steps = pgd_steps
        self.pgd_alpha = pgd_step_size

    def attack(self, X: List[List[float]],
               predict_fn: Callable[[List[List[float]]], List[float]],
               adjacency: Optional[List[List[int]]] = None,
               method: AttackMethod = AttackMethod.FGSM,
               n_samples: int = 50,
               target_class: int = 1) -> List[AdversarialSample]:
        """执行对抗攻击"""
        N = len(X)
        test_indices = random.sample(range(N), min(n_samples, N))

        dispatcher = {
            AttackMethod.FGSM: self._attack_fgsm,
            AttackMethod.PGD: self._attack_pgd,
            AttackMethod.FEATURE_NOISE: self._attack_feature_noise,
            AttackMethod.EDGE_FLIP: self._attack_edge_flip,
            AttackMethod.GRAGPOISON_INJECT: self._attack_gragpoison,
        }
        attack_fn = dispatcher.get(method, self._attack_fgsm)

        results = []
        for idx in test_indices:
            result = attack_fn(idx, X, predict_fn, adjacency, target_class)
            results.append(result)

        return results

    def _attack_fgsm(self, idx, X, predict_fn, adjacency, target):
        """FGSM: x_adv = x - ε * sign(∇_x L)

        使用数值梯度近似 (前后差分)
        """
        x = X[idx][:]
        if not x:
            return AdversarialSample(original_idx=idx)

        D = len(x)
        orig_pred = predict_fn([x])[0]

        # 数值梯度估计: 对每个维度计算 ∂L/∂x_j
        delta = 1e-4
        grad = []
        for j in range(D):
            x_plus = x[:]
            x_plus[j] += delta
            pred_plus = predict_fn([x_plus])[0]

            x_minus = x[:]
            x_minus[j] -= delta
            pred_minus = predict_fn([x_minus])[0]

            grad_j = (pred_plus - pred_minus) / (2.0 * delta)
            grad.append(grad_j)

        # 应用FGSM扰动
        x_adv = [x[j] - self.eps * (1.0 if grad[j] > 0 else -1.0) for j in range(D)]

        adv_pred = predict_fn([x_adv])[0]
        change = abs(adv_pred - orig_pred)

        return AdversarialSample(
            original_idx=idx,
            perturbed_features=x_adv,
            original_pred=orig_pred,
            perturbed_pred=adv_pred,
            prediction_change=change,
            attack_method='fgsm',
            was_successful=change > 0.1,
        )

    def _attack_pgd(self, idx, X, predict_fn, adjacency, target):
        """PGD: 多步FGSM, 每步投影到ε球内"""
        x_orig = X[idx][:]
        if not x_orig:
            return AdversarialSample(original_idx=idx)

        D = len(x_orig)
        x_adv = x_orig[:]
        # 添加小随机扰动开始
        for j in range(D):
            x_adv[j] += random.uniform(-self.pgd_alpha, self.pgd_alpha)
            x_adv[j] = _at_clip(x_adv[j], x_orig[j] - self.eps, x_orig[j] + self.eps)

        for step in range(self.pgd_steps):
            # 数值梯度
            delta = 1e-4
            grad = []
            for j in range(D):
                x_plus = x_adv[:]
                x_plus[j] += delta
                p_plus = predict_fn([x_plus])[0]
                x_minus = x_adv[:]
                x_minus[j] -= delta
                p_minus = predict_fn([x_minus])[0]
                grad.append((p_plus - p_minus) / (2.0 * delta))

            # 更新
            for j in range(D):
                x_adv[j] = x_adv[j] - self.pgd_alpha * (1.0 if grad[j] > 0 else -1.0)
                # 投影到ε球
                x_adv[j] = _at_clip(x_adv[j], x_orig[j] - self.eps, x_orig[j] + self.eps)

        orig_pred = predict_fn([x_orig])[0]
        adv_pred = predict_fn([x_adv])[0]
        change = abs(adv_pred - orig_pred)

        return AdversarialSample(
            original_idx=idx,
            perturbed_features=x_adv,
            original_pred=orig_pred,
            perturbed_pred=adv_pred,
            prediction_change=change,
            attack_method='pgd',
            was_successful=change > 0.1,
        )

    def _attack_feature_noise(self, idx, X, predict_fn, adjacency, target):
        """加高斯噪声"""
        x = X[idx][:]
        orig_pred = predict_fn([x])[0]
        D = len(x)

        x_noisy = x[:]
        for j in range(D):
            x_noisy[j] += random.gauss(0, self.eps)
            x_noisy[j] = max(0.0, min(1.0, x_noisy[j]))

        adv_pred = predict_fn([x_noisy])[0]
        change = abs(adv_pred - orig_pred)

        return AdversarialSample(
            original_idx=idx,
            perturbed_features=x_noisy,
            original_pred=orig_pred,
            perturbed_pred=adv_pred,
            prediction_change=change,
            attack_method='feature_noise',
            was_successful=change > 0.1,
        )

    def _attack_edge_flip(self, idx, X, predict_fn, adjacency, target):
        """图结构攻击: 翻转边"""
        if adjacency is None:
            return self._attack_feature_noise(idx, X, predict_fn, adjacency, target)

        N = len(X)
        x = X[idx][:]
        orig_adj = adjacency

        # 翻转少量边
        new_adj = [list(nb) for nb in orig_adj]
        n_flips = max(1, int(N * 0.05))

        for _ in range(n_flips):
            i = random.randint(0, N - 1)
            j = random.randint(0, N - 1)
            if i != j:
                if j in new_adj[i]:
                    new_adj[i].remove(j)
                else:
                    new_adj[i].append(j)

        # 重新嵌入时需要考虑邻接表变化 — 这里简化为特征级评估
        # (完整的图对抗需要图预测接口)

        orig_pred = predict_fn([x])[0]

        # 应用邻接扰动到特征: 聚合邻居特征来近似
        x_adv = x[:]
        neighbors = new_adj[idx] if idx < len(new_adj) else []
        if neighbors:
            for j in range(len(x)):
                total = 0.0
                count = 0
                for nb in neighbors:
                    if nb < N:
                        total += X[nb][j]
                        count += 1
                if count > 0:
                    # 掺入邻居信息的扰动
                    x_adv[j] = x_adv[j] * 0.9 + (total / count) * 0.1

        adv_pred = predict_fn([x_adv])[0]
        change = abs(adv_pred - orig_pred)

        return AdversarialSample(
            original_idx=idx,
            perturbed_features=x_adv,
            original_pred=orig_pred,
            perturbed_pred=adv_pred,
            prediction_change=change,
            attack_method='edge_flip',
            was_successful=change > 0.1,
        )

    def _attack_gragpoison(self, idx, X, predict_fn, adjacency, target):
        """GragPoison 关系注入攻击近似

        原始GragPoison攻击GraphRAG的三策略:
          1. relation_injection: 注入虚假关系
          2. relation_enhancement: 增强已有关系的权重
          3. narrative_generation: 生成误导性文本

        本实现近似relation_injection: 注入虚假邻域特征
        """
        x = X[idx][:]
        orig_pred = predict_fn([x])[0]
        D = len(x)

        # 关系注入: 虚假实体特征混入节点
        # 虚假特征=目标类对抗版本
        x_poisoned = x[:]
        for j in range(D):
            # 注入偏移模拟虚假邻域
            poison_signal = self.eps * (1.0 if random.random() > 0.5 else -1.0)
            x_poisoned[j] = _at_clip(x_poisoned[j] + poison_signal, 0.0, 1.0)

        adv_pred = predict_fn([x_poisoned])[0]
        change = abs(adv_pred - orig_pred)

        return AdversarialSample(
            original_idx=idx,
            perturbed_features=x_poisoned,
            original_pred=orig_pred,
            perturbed_pred=adv_pred,
            prediction_change=change,
            attack_method='gragpoison',
            was_successful=change > 0.1,
        )

# 报告

    def test_robustness(self, X, predict_fn,
                        adjacency=None,
                        methods=None,
                        n_samples=50) -> List[RobustnessReport]:
        """全维度鲁棒性测试"""
        if methods is None:
            methods = [AttackMethod.FGSM, AttackMethod.FEATURE_NOISE,
                       AttackMethod.EDGE_FLIP]

        reports = []
        for m in methods:
            samples = self.attack(X, predict_fn, adjacency, method=m,
                                  n_samples=n_samples)
            n_success = sum(1 for s in samples if s.was_successful)
            n_tested = len(samples)

            if n_tested == 0:
                continue

            success_rate = n_success / n_tested
            avg_change = sum(s.prediction_change for s in samples) / n_tested
            max_change = max((s.prediction_change for s in samples), default=0.0)

            # 鲁棒性: 1-攻击成功率
            robustness = 1.0 - success_rate

            reports.append(RobustnessReport(
                method=m.value,
                n_samples_tested=n_tested,
                n_successful_attacks=n_success,
                success_rate=success_rate,
                avg_prediction_change=avg_change,
                max_prediction_change=max_change,
                samples=samples,
                robustness_score=robustness,
            ))

        return reports


def create_adversarial_tester(epsilon=0.1) -> AdversarialTester:
    return AdversarialTester(epsilon=epsilon)


def test_model_robustness(X, predict_fn, adjacency=None, n_samples=50):
    tester = AdversarialTester()
    return tester.test_robustness(X, predict_fn, adjacency, n_samples=n_samples)
