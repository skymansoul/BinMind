"""
跨战役策略迁移 (Cross-Campaign Strategy Transfer, CCST)
----------------------------------------------------------
从已完成的模糊测试战役中提取策略指纹, 为新战役提供暖启动参数.

注: 本模块实现的是基于案例检索的策略迁移, 不是元学习 (MAML/Reptile).
命名采用 CCST 以准确描述其机制.

设计依据:
  现有模糊测试框架每次新战役从零调参——即使目标二进制与历史战役高度相似.
  通过 k-NN 检索最相似的历史战役并按相似度加权融合策略参数,
  可显著降低冷启动开销.
  LLAMAFUZZ  的LLM语料感知和ISC4DGF
  的LLM种子生成均限于单次战役, 不涉及跨战役知识复用.

算法:
  1. CampaignFingerprint: 编码二进制特征+最优策略+变异权重+性能指标
  2. k-NN检索: 余弦相似度匹配最相似的k个历史战役
  3. 加权融合: 按相似度融合能量策略得分和变异算子权重
  4. 闭环更新: 战役结束后将结果反馈到案例库
"""
import math
import time
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class CampaignFingerprint:
    """单次模糊测试战役的策略指纹."""
    campaign_id: str
    binary_features: Dict[str, float] = field(default_factory=dict)
    # 最优策略
    best_energy_policy: str = "coe"
    energy_policy_scores: Dict[str, float] = field(default_factory=dict)
    # 变异算子权重 (算子名 → 归一化权重)
    mutation_weights: Dict[str, float] = field(default_factory=dict)
    # 性能指标
    total_cycles: int = 0
    total_coverage_edges: int = 0
    total_crashes: int = 0
    convergence_cycles: int = 0      # 覆盖率收敛所需周期数
    avg_coverage_growth_rate: float = 0.0  # 每条边/周期的平均增长率
    campaign_duration_s: float = 0.0
    # 元数据
    created_at: float = 0.0
    arch: str = ""
    binary_size_bytes: int = 0

    def feature_vector(self) -> List[float]:
        """将二进制特征编码为归一化向量, 用于相似度检索."""
        bf = self.binary_features
        size = bf.get('size', 0) or self.binary_size_bytes
        return [
            min(1.0, math.log1p(size) / 25.0),
            bf.get('has_aslr', 1.0),
            bf.get('has_nx', 1.0),
            bf.get('has_pie', 0.0),
            min(1.0, bf.get('section_count', 5) / 20.0),
            bf.get('text_entropy', 5.0) / 8.0,
            min(1.0, bf.get('import_dangerous', 0) / 50.0),
            bf.get('is_cpp', 0.0),
        ]

class CrossCampaignMetaLearner:
    """跨战役元学习器 — k-NN 检索 + 策略加权融合.

    用法:
      ml = CrossCampaignMetaLearner()
      ml.record_campaign(fingerprint)
      warm_start = ml.query(binary_features)
      # 将 warm_start 注入新战役的调度器和能量策略
    """

    def __init__(self, k: int = 5, similarity_min: float = 0.3):
        self._campaigns: List[CampaignFingerprint] = []
        self._k = k
        self._sim_min = similarity_min
        self._arch_counter: Dict[str, int] = defaultdict(int)

    def record_campaign(self, fp: CampaignFingerprint):
        """记录一次完成的战役."""
        fp.created_at = fp.created_at or time.time()
        self._campaigns.append(fp)
        self._arch_counter[fp.arch] += 1

    def query(self, binary_features: Dict[str, float]) -> Dict[str, Any]:
        """查询与新二进制最相似的历史战役, 返回融合后的暖启动策略.
        binary_features: {'size': 2048576, 'arch': 'x86_64', 'has_aslr': 1, ...}
        """
        if not self._campaigns:
            return self._default_warm_start()

        query_vec = CampaignFingerprint(
            campaign_id='__query__', binary_features=binary_features
        ).feature_vector()

        scored = []
        for fp in self._campaigns:
            sim = _cosine_sim(query_vec, fp.feature_vector())
            if sim >= self._sim_min:
                scored.append((sim, fp))
        scored.sort(key=lambda x: x[0], reverse=True)
        top_k = scored[:self._k]

        if not top_k:
            return self._default_warm_start()

        # 相似度加权融合
        total_sim = sum(s for s, _ in top_k)
        # 融合能量策略得分
        fused_energy: Dict[str, float] = defaultdict(float)
        fused_mutation: Dict[str, float] = defaultdict(float)
        for sim, fp in top_k:
            w = sim / total_sim if total_sim > 0 else 1.0 / len(top_k)
            for policy, score in fp.energy_policy_scores.items():
                fused_energy[policy] += w * score
            for op, weight in fp.mutation_weights.items():
                fused_mutation[op] += w * weight

        best_policy = max(fused_energy, key=fused_energy.get) if fused_energy else "coe"
        # 归一化变异权重
        mw_total = sum(fused_mutation.values()) or 1.0
        norm_mutation = {op: w / mw_total for op, w in fused_mutation.items()}

        return {
            'recommended_energy_policy': best_policy,
            'energy_policy_scores': dict(fused_energy),
            'mutation_weights': norm_mutation,
            'estimated_convergence_cycles': int(
                sum(s * fp.convergence_cycles for s, fp in top_k) / total_sim
            ),
            'similar_campaigns': [
                {'id': fp.campaign_id, 'similarity': round(sim, 4),
                 'arch': fp.arch, 'coverage': fp.total_coverage_edges}
                for sim, fp in top_k
            ],
            'confidence': round(min(1.0, total_sim / len(top_k)), 3),
        }

    def _default_warm_start(self) -> Dict[str, Any]:
        return {
            'recommended_energy_policy': 'coe',
            'energy_policy_scores': {'coe': 0.5, 'explore': 0.3, 'quad': 0.2},
            'mutation_weights': {},
            'estimated_convergence_cycles': 500,
            'similar_campaigns': [],
            'confidence': 0.0,
        }

    def best_practices(self, arch: Optional[str] = None) -> Dict[str, Any]:
        """汇总指定架构的最佳实践统计."""
        campaigns = (
            [c for c in self._campaigns if c.arch == arch]
            if arch else self._campaigns
        )
        if not campaigns:
            return {'error': 'no campaigns found'}
        policy_wins: Dict[str, int] = defaultdict(int)
        for c in campaigns:
            policy_wins[c.best_energy_policy] += 1
        avg_convergence = sum(c.convergence_cycles for c in campaigns) / len(campaigns)
        return {
            'n_campaigns': len(campaigns),
            'best_policy_by_wins': max(policy_wins, key=policy_wins.get),
            'policy_win_distribution': dict(policy_wins),
            'avg_convergence_cycles': round(avg_convergence, 1),
            'avg_crashes': round(sum(c.total_crashes for c in campaigns) / len(campaigns), 1),
        }

    def export(self) -> List[Dict[str, Any]]:
        """导出所有战役指纹为可序列化格式."""
        return [
            {
                'id': fp.campaign_id, 'arch': fp.arch,
                'size': fp.binary_size_bytes,
                'best_policy': fp.best_energy_policy,
                'edges': fp.total_coverage_edges,
                'crashes': fp.total_crashes,
                'convergence': fp.convergence_cycles,
            }
            for fp in self._campaigns
        ]

    def __len__(self) -> int:
        return len(self._campaigns)

def _cosine_sim(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na > 0 and nb > 0 else 0.0

class GPSurrogateOptimizer:
    """GP代理模型 —— 在k-NN检索之上叠加高斯过程回归.

    从历史战役的 (特征→收敛周期/崩溃数) 学习非线性映射,
    对新二进制给出带不确定度的预测.
    使用 RBF 核 + 白噪声核, 通过 Cholesky 分解求解.

    与纯 k-NN 的区别:
      k-NN 仅返回加权平均, 无不确定度.
      GP 给出后验均值 + 方差, 支持 UCB/EI 采集函数用于策略探索.
    """

    def __init__(self, length_scale: float = 1.0,
                 signal_var: float = 1.0, noise_var: float = 0.1):
        self._ls = length_scale      # RBF 长度尺度
        self._sigma_f2 = signal_var  # 信号方差
        self._sigma_n2 = noise_var   # 噪声方差
        self._X: List[List[float]] = []  # 训练特征
        self._y: List[float] = []        # 训练目标
        self._L = None                    # Cholesky 分解缓存
        self._alpha = None               # K^{-1} y 缓存

    def fit(self, fingerprints: List[CampaignFingerprint],
            target: str = 'convergence_cycles'):
        """从战役指纹列表训练 GP."""
        self._X = [fp.feature_vector() for fp in fingerprints]
        if target == 'convergence_cycles':
            self._y = [float(fp.convergence_cycles) for fp in fingerprints]
        elif target == 'crashes':
            self._y = [float(fp.total_crashes) for fp in fingerprints]
        else:
            self._y = [float(fp.total_coverage_edges) for fp in fingerprints]
        self._recompute()

    def _rbf_kernel(self, xi: List[float], xj: List[float]) -> float:
        sq_dist = sum((a - b) ** 2 for a, b in zip(xi, xj))
        return self._sigma_f2 * math.exp(-0.5 * sq_dist / (self._ls ** 2))

    def _recompute(self):
        n = len(self._X)
        if n == 0:
            self._L = self._alpha = None
            return
        K = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i, n):
                kv = self._rbf_kernel(self._X[i], self._X[j])
                if i == j:
                    kv += self._sigma_n2
                K[i][j] = kv
                K[j][i] = kv
        self._L = _cholesky_decompose(K)
        if self._L is not None:
            self._alpha = _cholesky_solve(self._L, self._y)

    def predict(self, x_new: List[float]) -> Tuple[float, float]:
        """返回 (后验均值, 后验方差)."""
        if self._L is None or self._alpha is None:
            return (500.0, 10000.0)  # 无训练数据 — 高不确定度
        n = len(self._X)
        k_star = [self._rbf_kernel(x_new, xi) for xi in self._X]
        mean = sum(k_star[i] * self._alpha[i] for i in range(n))
        v = _cholesky_solve(self._L, k_star)
        k_self = self._rbf_kernel(x_new, x_new) + self._sigma_n2
        var = k_self - sum(k_star[i] * v[i] for i in range(n))
        return (mean, max(1e-6, var))

    def ucb(self, x_new: List[float], beta: float = 2.0) -> float:
        """Upper Confidence Bound — 平衡探索与利用."""
        mean, var = self.predict(x_new)
        return mean + beta * math.sqrt(var)

    def expected_improvement(self, x_new: List[float],
                             best_y: float) -> float:
        """Expected Improvement over best_y."""
        mean, var = self.predict(x_new)
        std = math.sqrt(var)
        if std < 1e-9:
            return 0.0
        z = (best_y - mean) / std
        # EI = std * (z*Φ(z) + φ(z)), 用标准正态近似
        phi = math.exp(-0.5 * z * z) / math.sqrt(2 * math.pi)
        # Φ(z) 用 erf 近似
        Phi = 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))
        return std * (z * Phi + phi)

def _cholesky_decompose(K: List[List[float]]) -> Optional[List[List[float]]]:
    """Cholesky 分解 K = L L^T. 数值不稳定时加 jitter."""
    n = len(K)
    L = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            s = sum(L[i][k] * L[j][k] for k in range(j))
            if i == j:
                diag = K[i][i] - s
                if diag <= 0:
                    diag += 1e-6  # jitter
                if diag <= 0:
                    return None
                L[i][j] = math.sqrt(diag)
            else:
                L[i][j] = (K[i][j] - s) / L[j][j]
    return L

def _cholesky_solve(L: List[List[float]],
                    b: List[float]) -> List[float]:
    """用 Cholesky 分解 L 解 K x = b → L L^T x = b."""
    n = len(L)
    y = [0.0] * n
    for i in range(n):
        y[i] = (b[i] - sum(L[i][j] * y[j] for j in range(i))) / L[i][i]
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        x[i] = (y[i] - sum(L[j][i] * x[j] for j in range(i + 1, n))) / L[i][i]
    return x

def make_campaign_fingerprint(
    campaign_id: str,
    binary_info: Dict[str, Any],
    energy_results: Dict[str, float],
    mutation_profile: Dict[str, float],
    stats: Dict[str, Any],
) -> CampaignFingerprint:
    """从战役结果构造 CampaignFingerprint.
    适配现有 fuzz_campaign_tracker 的数据结构.
    """
    binfo = binary_info or {}
    return CampaignFingerprint(
        campaign_id=campaign_id,
        binary_features={
            'size': float(binfo.get('size', 0)),
            'has_aslr': 1.0 if binfo.get('aslr') else 0.0,
            'has_nx': 1.0 if binfo.get('nx') else 0.0,
            'has_pie': 1.0 if binfo.get('pie') else 0.0,
            'section_count': float(binfo.get('section_count', 0)),
            'text_entropy': float(binfo.get('text_entropy', 5.0)),
            'import_dangerous': float(binfo.get('dangerous_imports', 0)),
            'is_cpp': 1.0 if binfo.get('is_cpp') else 0.0,
        },
        best_energy_policy=max(energy_results, key=energy_results.get) if energy_results else 'coe',
        energy_policy_scores=dict(energy_results),
        mutation_weights=dict(mutation_profile),
        total_cycles=int(stats.get('total_cycles', 0)),
        total_coverage_edges=int(stats.get('total_edges', 0)),
        total_crashes=int(stats.get('total_crashes', 0)),
        convergence_cycles=int(stats.get('convergence_at_cycle', 0)),
        campaign_duration_s=float(stats.get('duration_s', 0)),
        arch=str(binfo.get('arch', '')),
        binary_size_bytes=int(binfo.get('size', 0)),
        created_at=time.time(),
    )
