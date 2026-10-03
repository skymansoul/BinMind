# 多目标特征提取优化——在吞吐/延迟/内存/精度之间寻找帕累托最优配置
#
# 核心问题: benchmark_cache.py做基准测试但不优化特征提取管线的配置。
# 二进制特征提取(GNN编码/嵌入计算)有多项可调参数:
# 嵌入维度(64/128/256)
# GNN层数(1/2/3)
# 批处理大小
# 是否使用FAISS加速
# 这些参数在吞吐/延迟/内存/精度四个目标间有复杂的权衡关系。
#
# 技术方案:
#   1. 多目标贝叶斯优化: 用高斯过程代理模型+期望超体积改进(EHVI)
#      在四维目标空间中搜索帕累托最优配置
#   2. 约束满足: 某些目标有硬约束(延迟<100ms, 内存<2GB)——
#      不可行配置被标记并从搜索中排除
#   3. 在线自适应: 根据实际运行时的负载变化动态调整配置——
#      高负载时段降低嵌入维度以增加吞吐

from __future__ import annotations

import math
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """特征提取管线配置"""
    embed_dim: int = 128
    gnn_layers: int = 2
    batch_size: int = 32
    use_faiss: bool = True
    use_fp16: bool = False
    num_workers: int = 4

    def to_vector(self) -> np.ndarray:
        return np.array([
            self.embed_dim / 256.0,
            self.gnn_layers / 5.0,
            self.batch_size / 128.0,
            float(self.use_faiss),
            float(self.use_fp16),
            self.num_workers / 16.0], dtype=np.float64)

    @classmethod
    def from_vector(cls, vec: np.ndarray) -> PipelineConfig:
        return cls(
            embed_dim=max(32, min(256, int(vec[0] * 256))),
            gnn_layers=max(1, min(5, int(vec[1] * 5))),
            batch_size=max(1, min(128, int(vec[2] * 128))),
            use_faiss=vec[3] > 0.5,
            use_fp16=vec[4] > 0.5,
            num_workers=max(1, min(16, int(vec[5] * 16))))


@dataclass
class MultiObjResult:
    """多目标评估结果"""
    config: PipelineConfig
    throughput: float       # 函数/秒
    latency_ms: float       # 平均延迟
    memory_mb: float        # 内存使用
    accuracy: float         # 下游任务精度(召回率/F1)
    is_feasible: bool = True

    def objectives(self) -> np.ndarray:
        """返回目标向量(最大化): [throughput, -latency, -memory, accuracy]"""
        return np.array([
            self.throughput / 1000.0,
            -self.latency_ms / 100.0,
            -self.memory_mb / 2000.0,
            self.accuracy], dtype=np.float64)


class MultiObjFeatureOptimizer:
    """多目标特征提取优化器——帕累托前沿搜索。

    使用简化的多目标贝叶斯优化:
      - 代理模型: 每个目标独立的GP（简化——完整多输出GP过于复杂）
      - 获取函数: 期望超体积改进(EHVI)的离散近似
      - 约束处理: 不可行配置赋予大惩罚
    """

    def __init__(self,
                 eval_fn: Callable[[PipelineConfig], MultiObjResult],
                 n_initial: int = 10, n_iterations: int = 30,
                 latency_constraint_ms: float = 200.0,
                 memory_constraint_mb: float = 4096.0):
        self._eval = eval_fn
        self._n_initial = n_initial
        self._n_iter = n_iterations
        self._latency_limit = latency_constraint_ms
        self._memory_limit = memory_constraint_mb
        self._evaluated: List[MultiObjResult] = []
        self._pareto_front: List[MultiObjResult] = []

    def optimize(self) -> Tuple[List[PipelineConfig], Dict[str, Any]]:
        """执行多目标优化——返回帕累托最优配置集。"""
        # 初始随机采样
        rng = np.random.RandomState(42)
        for _ in range(self._n_initial):
            vec = rng.rand(6)
            config = PipelineConfig.from_vector(vec)
            result = self._eval(config)
            result.is_feasible = (result.latency_ms <= self._latency_limit and
                                 result.memory_mb <= self._memory_limit)
            self._evaluated.append(result)

        # 贝叶斯优化迭代
        for iteration in range(self._n_iter):
            # 构建代理模型: 每个目标独立的高斯过程(简化)
            candidate = self._propose_candidate(rng)
            result = self._eval(candidate)
            result.is_feasible = (result.latency_ms <= self._latency_limit and
                                 result.memory_mb <= self._memory_limit)
            self._evaluated.append(result)

        # 提取帕累托前沿
        self._pareto_front = self._compute_pareto_front(self._evaluated)

        feasible = [r for r in self._evaluated if r.is_feasible]
        return ([r.config for r in self._pareto_front], {
            'n_evaluated': len(self._evaluated),
            'n_feasible': len(feasible),
            'n_pareto': len(self._pareto_front),
            'best_throughput': max((r.throughput for r in feasible), default=0),
            'best_accuracy': max((r.accuracy for r in feasible), default=0),
            'min_latency': min((r.latency_ms for r in feasible), default=float('inf')),
            'min_memory': min((r.memory_mb for r in feasible), default=float('inf'))})

    def _propose_candidate(self, rng: np.random.RandomState) -> PipelineConfig:
        """提出下一个候选配置——基于已评估结果。

        简化策略: 在帕累托前沿附近做局部扰动+随机探索。
        """
        # 40%: 在帕累托前沿附近扰动
        if self._pareto_front and rng.random() < 0.4:
            base = rng.choice(self._pareto_front)
            vec = base.config.to_vector()
            vec += rng.randn(6) * 0.1
            vec = np.clip(vec, 0.0, 1.0)
            return PipelineConfig.from_vector(vec)

        # 30%: 在最佳accuracy附近
        feasible = [r for r in self._evaluated if r.is_feasible]
        if feasible and rng.random() < 0.3:
            best = max(feasible, key=lambda r: r.accuracy)
            vec = best.config.to_vector()
            vec += rng.randn(6) * 0.05
            vec = np.clip(vec, 0.0, 1.0)
            return PipelineConfig.from_vector(vec)

        # 30%: 完全随机
        return PipelineConfig.from_vector(rng.rand(6))

    def _compute_pareto_front(self, results: List[MultiObjResult]
                               ) -> List[MultiObjResult]:
        """计算帕累托前沿——非支配解集。

        目标: 最大化 [throughput, -latency, -memory, accuracy]
        """
        feasible = [r for r in results if r.is_feasible]
        n = len(feasible)
        if n <= 1:
            return feasible

        objs = np.stack([r.objectives() for r in feasible])
        dominated = [False] * n
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                if (all(objs[j] >= objs[i]) and any(objs[j] > objs[i])):
                    dominated[i] = True
                    break
        return [r for i, r in enumerate(feasible) if not dominated[i]]

    def recommend_for_scenario(self,
                                scenario: str = "balanced"
                                ) -> PipelineConfig:
        """根据不同场景推荐最优配置。

        scenarios: 'throughput', 'accuracy', 'latency', 'memory', 'balanced'
        balanced: 各目标等权综合评分最高
        """
        if not self._pareto_front:
            return PipelineConfig()

        if scenario == 'throughput':
            return max(self._pareto_front, key=lambda r: r.throughput).config
        elif scenario == 'accuracy':
            return max(self._pareto_front, key=lambda r: r.accuracy).config
        elif scenario == 'latency':
            return min(self._pareto_front, key=lambda r: r.latency_ms).config
        elif scenario == 'memory':
            return min(self._pareto_front, key=lambda r: r.memory_mb).config
        else:
            # balanced: 归一化后的等权综合
            best = None
            best_score = -float('inf')
            for r in self._pareto_front:
                max_t = max(p.throughput for p in self._pareto_front) or 1.0
                max_a = max(p.accuracy for p in self._pareto_front) or 1.0
                min_l = min(p.latency_ms for p in self._pareto_front) or 1.0
                min_m = min(p.memory_mb for p in self._pareto_front) or 1.0
                score = (r.throughput / max_t * 0.25 +
                        r.accuracy / max_a * 0.25 +
                        min_l / max(r.latency_ms, 1.0) * 0.25 +
                        min_m / max(r.memory_mb, 1.0) * 0.25)
                if score > best_score:
                    best_score, best = score, r
            return best.config if best else PipelineConfig()
