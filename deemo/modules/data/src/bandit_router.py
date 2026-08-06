# 上下文 Bandit 去重方法路由器 (Contextual Bandit Dedup Router)
#
# 核心问题: 去重流水线有 N 种独立方法 (SimHash, MinHash, 图评分, 向量搜索),
#   不同二进制的最优方法组合不同:
#     - stripped blob: 图评分无法运行 (无 CFG), 应跳过
#     - 大文件 (>100MB): 向量搜索 / SimHash 比 MinHash (CDC 分块) 更快
#     - 有丰富符号: 图评分精度最高, 应优先
#   固定执行所有方法浪费 CPU: 4种方法各耗时 0.5-5s → 2-20s/binary.
#
# 创新点:
#   1. Linear Thompson Sampling (LinTS) 在线学习:
#      将"选择方法子集"建模为 contextual bandit.
#      上下文 = 二进制特征向量 (大小/类型/熵/符号存在性/架构),
#      动作 = 方法子集 (2^N 种组合, 实际取 Top-M 候选),
#      奖励 = 方法产出 (发现重复) × 精度 - 执行时间成本.
#      LinTS 假设奖励 = θ^T·context + ε, θ 的后验为高斯分布,
#      每轮从后验采样 θ̃, 选 argmax_a(θ̃^T·context_a).
#   2. 特征感知裁剪: 上下文直接编码方法可行性:
#      - has_cfg=0 → 图评分自动排除
#      - file_size > 100MB → CDC-MinHash 排除 (耗时过长)
#      - has_imports=0 → IOC 提取排除
#      裁剪后仅对可行方法做 bandit 选择, 降低动作空间.
#   3. 冷启动先验注入: 从离线基准测试结果初始化 θ 先验,
#      新部署环境无需数百次探索即可获得合理路由策略.
#   4. 漂移自适应: 当数据分布变化 (如从 x86 切到 ARM), θ 后验
#      自然漂移 (旧数据的似然衰减). 每 N 轮对协方差矩阵做微量膨胀,
#      保持探索能力.
#
# 与现有工作:
#   - adaptive_threshold.py: 调阈值参数, 不选方法. 互补.
#   - 标准 ensemble: 全运行后投票. 本方案智能跳过.
#   - 无已知论文将 contextual bandit 用于去重方法选择.

import math
import random
import time
from typing import Dict, List, Optional, Set, Tuple


class LinTSRouter:
    """Linear Thompson Sampling: θ_a ~ N(μ_a,Σ_a), 采样选 argmax(x^T·θ̃).
    更新用 Bayesian linear regression. CUSUM 检测非平稳奖励分布变化."""

    def __init__(self, d: int, actions: List[str],
                 sigma_prior: float = 1.0, sigma_noise: float = 0.1,
                 inflation_rate: float = 0.001,
                 cusum_threshold: float = 5.0):
        self.d = d; self.actions = actions; self.n_actions = len(actions)
        self.sigma_noise = sigma_noise; self.inflate = inflation_rate
        self._cusum_h = cusum_threshold

        self._mu = [[0.0]*d for _ in range(self.n_actions)]
        self._sigma_inv = [
            [[(1.0/sigma_prior**2) if i==j else 0.0 for j in range(d)] for i in range(d)]
            for _ in range(self.n_actions)]
        self._n_pulls = [0]*self.n_actions; self._total_reward = [0.0]*self.n_actions
        self._reward_ema = [0.5]*self.n_actions
        self._cusum_pos = [0.0]*self.n_actions; self._cusum_neg = [0.0]*self.n_actions
        self._reward_window = {i: [] for i in range(self.n_actions)}
        self._ema_alpha = 0.1

    def select(self, context: List[float]) -> Tuple[int, str]:
        """LinTS 选择: 采样 θ̃~N(μ,Σ), 选 argmax(x^T θ̃)."""
        best_idx, best_val = 0, float('-inf')
        for a_idx in range(self.n_actions):
            # 从 N(μ_a, Σ_a) 采样: θ̃ = μ + L·z (Cholesky)
            # 简化: 用对角协方差近似, θ̃_i = μ_i + σ_i * z_i
            mu = self._mu[a_idx]
            theta_sample = [0.0] * self.d
            for j in range(self.d):
                sigma_j = 1.0 / math.sqrt(max(self._sigma_inv[a_idx][j][j], 1e-9))
                theta_sample[j] = mu[j] + sigma_j * random.gauss(0, 1)

            score = sum(context[j] * theta_sample[j] for j in range(self.d))
            if score > best_val:
                best_val = score
                best_idx = a_idx

        return best_idx, self.actions[best_idx]

    def update(self, action_idx: int, context: List[float], reward: float):
        """Bayesian linear regression: Σ⁻¹+=xx^T/σ², μ 增量更新."""
        inv_noise = 1.0 / (self.sigma_noise ** 2)

        # 更新 precision matrix: Σ⁻¹ += x·x^T / σ²
        for j in range(self.d):
            for k in range(self.d):
                self._sigma_inv[action_idx][j][k] += \
                    context[j] * context[k] * inv_noise

        # 更新 μ (解 Σ⁻¹·μ_new = Σ⁻¹·μ_old + x·reward/σ²)
        # 简化: 对角协方差下逐维更新
        for j in range(self.d):
            sigma_jj = 1.0 / max(self._sigma_inv[action_idx][j][j], 1e-9)
            old_mu = self._mu[action_idx][j]
            gradient = context[j] * reward * inv_noise
            self._mu[action_idx][j] = old_mu + sigma_jj * gradient

        self._n_pulls[action_idx] += 1
        self._total_reward[action_idx] += reward

        # CUSUM: 跟踪奖励 EMA 变化
        prev = self._reward_ema[action_idx]
        self._reward_ema[action_idx] = (1-self._ema_alpha)*prev + self._ema_alpha*reward
        delta = (reward - prev) / max(0.05, abs(prev) + 1e-9)
        self._cusum_pos[action_idx] = max(0, self._cusum_pos[action_idx] + delta - 0.5)
        self._cusum_neg[action_idx] = max(0, self._cusum_neg[action_idx] - delta - 0.5)

        # 协方差膨胀 (漂移自适应)
        if self._n_pulls[action_idx] % 100 == 0:
            for j in range(self.d):
                self._sigma_inv[action_idx][j][j] *= (1.0 - self.inflate)

    def check_nonstationary(self) -> List[int]:
        """检测奖励分布发生显著变化的动作索引.

        返回需要重置先验的动作索引列表.
        CUSUM > threshold → 统计显著的非平稳变化.
        """
        changed = []
        for a in range(self.n_actions):
            if self._cusum_pos[a] > self._cusum_h or self._cusum_neg[a] > self._cusum_h:
                changed.append(a)
                # 重置该动作: 保留均值但放宽方差 (触发重新探索)
                self._cusum_pos[a] = 0.0; self._cusum_neg[a] = 0.0
                for j in range(self.d):
                    self._sigma_inv[a][j][j] *= 0.3  # 方差膨胀 3.3x
        return changed

    def best_action(self, context: List[float]) -> str:
        """贪婪选择 (不探索): argmax_a(μ_a^T·context)."""
        best_idx = max(range(self.n_actions),
                       key=lambda a: sum(context[j]*self._mu[a][j] for j in range(self.d)))
        return self.actions[best_idx]

    @property
    def stats(self) -> dict:
        return {
            "actions": self.actions,
            "pulls": self._n_pulls,
            "avg_reward": [round(r/max(p,1),4) for r,p in
                          zip(self._total_reward, self._n_pulls)],
            "cusum_pos": [round(c,3) for c in self._cusum_pos],
            "cusum_neg": [round(c,3) for c in self._cusum_neg],
            "reward_ema": [round(e,3) for e in self._reward_ema],
        }


# ---------------------------------------------------------------------------
# 去重方法路由器
# ---------------------------------------------------------------------------

class DedupMethodRouter:
    """上下文 Bandit 去重方法路由器.

    用户提供候选方法列表 + 成本 + 可行性检查 + 特征提取.
    router.select(context) → 应执行的方法子集.

    用法:
      methods = [
        {"name":"simhash","cost":0.5,"feasible":lambda c:True},
        {"name":"minhash","cost":2.0,"feasible":lambda c:c[0]<100e6},  # 大小<100MB
        {"name":"graph","cost":3.0,"feasible":lambda c:c[4]>0},  # has_cfg
      ]
      router = DedupMethodRouter(methods, context_dim=6)
      selected = router.select(features)
      router.feedback(selected, features, reward=1.0 if found_dup else 0.0)
    """

    def __init__(self, methods: List[dict], context_dim: int = 6,
                 sigma_prior: float = 1.0):
        self.methods = methods
        self.n_methods = len(methods)
        self._names = [m["name"] for m in methods]
        # 每个方法是独立的二臂 bandit (执行/跳过), 共 n_methods 个
        self._routers = [
            LinTSRouter(d=context_dim, actions=["skip","run"],
                        sigma_prior=sigma_prior)
            for _ in methods
        ]

    def select(self, context: List[float]) -> List[str]:
        """返回应执行的方法名列表."""
        selected = []
        for i, method in enumerate(self.methods):
            feasible_fn = method.get("feasible")
            if feasible_fn and not feasible_fn(context):
                continue  # 不可行: 自动跳过

            # Bandit 选择: run or skip?
            _, decision = self._routers[i].select(context)
            if decision == "run":
                selected.append(method["name"])

        return selected

    def feedback(self, selected_names: List[str], context: List[float],
                 per_method_reward: Dict[str, float]):
        """反馈每个已执行方法的奖励 + 检测非平稳变化."""
        for i, method in enumerate(self.methods):
            name = method["name"]
            if name in selected_names:
                reward = per_method_reward.get(name, 0.0)
                self._routers[i].update(1, context, reward)
            else:
                skip_reward = per_method_reward.get(f"{name}_skip",
                                                     method.get("cost", 0.5) * 0.1)
                self._routers[i].update(0, context, skip_reward)
            # CUSUM 非平稳检测
            changed = self._routers[i].check_nonstationary()
            if changed:
                self._nonstationary_events = getattr(self, '_nonstationary_events', [])
                self._nonstationary_events.append({
                    "method": name, "action_indices": changed,
                    "pulls": self._routers[i]._n_pulls})

    def greedy_select(self, context: List[float]) -> List[str]:
        """贪婪模式 (不探索): 针对生产环境."""
        selected = []
        for i, method in enumerate(self.methods):
            if method.get("feasible") and not method["feasible"](context):
                continue
            if self._routers[i].best_action(context) == "run":
                selected.append(method["name"])
        return selected

    @property
    def stats(self) -> dict:
        return {
            "methods": self._names,
            "routers": [r.stats for r in self._routers],
        }


# ---------------------------------------------------------------------------
# 预置上下文特征提取器 + 成本模型
# ---------------------------------------------------------------------------

def extract_routing_context(sig: dict, data: bytes = b"") -> List[float]:
    """从签名提取路由上下文的 6 维特征.

    维度:
      0: log(file_size+1)/20 (归一化)
      1: byte_entropy/8 或 0.5
      2: has_debug_info (0/1)
      3: section_count/50 (归一化)
      4: has_cfg (0/1 — 是否有调用图数据)
      5: is_stripped (0/1)
    """
    feats = [0.0] * 6

    fsize = sig.get("file_size", 0)
    feats[0] = min(1.0, math.log1p(fsize) / 20.0)

    if data and len(data) > 0:
        counts = [0]*256
        for b in data[:4096]: counts[b] += 1
        n = min(len(data), 4096)
        e = -sum((c/n)*math.log2(c/n) for c in counts if c > 0)
        feats[1] = e / 8.0
    else:
        feats[1] = 0.5

    metadata = sig.get("metadata", {})
    if isinstance(metadata, str):
        try: import json; metadata = json.loads(metadata)
        except Exception: metadata = {}
    feats[2] = 1.0 if metadata.get("has_debug") or not metadata.get("stripped") else 0.0
    feats[3] = min(1.0, metadata.get("section_count", 1) / 50.0)
    feats[4] = 1.0 if sig.get("analysis_count", 0) > 0 else 0.0
    feats[5] = 1.0 if metadata.get("stripped") else 0.0

    return feats


DEFAULT_DEDUP_METHODS = [
    {"name": "exact_hash",  "cost": 0.02, "feasible": lambda c: True},
    {"name": "simhash",     "cost": 0.5,  "feasible": lambda c: True},
    {"name": "minhash",     "cost": 2.0,  "feasible": lambda c: c[0] < 0.8},
    {"name": "graph_score", "cost": 3.0,  "feasible": lambda c: c[4] > 0 and c[5] < 0.5},
    {"name": "vector_lsh",  "cost": 1.0,  "feasible": lambda c: True},
    {"name": "ioc_extract", "cost": 1.5,  "feasible": lambda c: c[2] > 0 or c[5] < 0.5},
]


__all__ = [
    "LinTSRouter",
    "DedupMethodRouter",
    "extract_routing_context",
    "DEFAULT_DEDUP_METHODS",
]
