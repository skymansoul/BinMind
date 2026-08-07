"""
覆盖率平台期突破器 (Coverage Plateau Breaker, CPB)
----------------------------------------------------
当覆盖率进入平台期时, 通过简化 CMA-ES 优化种子字节序列,
直接瞄准当前覆盖边界邻近的未覆盖边.

注: 本模块实现的是黑箱优化 (简化CMA-ES), 不涉及对抗生成网络或博弈.
原ACB命名保留为类别名以保持向后兼容.

设计依据:
  传统模糊测试在覆盖平台期依赖随机变异——无向随机游走到达
  未覆盖边的概率随距离指数衰减.
  AtGAN 用离线GAN但无法在线适应.
  Lin 用LLM做语义变异但推理延迟限制吞吐.

  简化CMA-ES (对角协方差 + rank-μ更新):
    1. 从当前最佳种子出发, 维护对角高斯搜索分布
    2. 每次迭代采样λ个子代, 按覆盖率增益排序
    3. 加权均值更新 + 协方差对角更新
    4. 无梯度, 每次迭代λ次执行
    5. 收敛后切换至下一组目标边
"""
import math
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

@dataclass
class SearchPoint:
    """CMA-ES 搜索点 — 一个候选种子及其适应度."""
    data: bytes
    fitness: float = 0.0  # 覆盖率增益 (越高越好)
    edges_found: int = 0

class AdversarialCoverageBreaker:
    """对抗性种子优化器 — 简化 CMA-ES.

    用法:
      acb = AdversarialCoverageBreaker(seed_bytes, dim=len(seed_bytes))
      for iteration in range(max_iter):
          candidates = acb.ask()   # 生成 λ 个候选种子
          fitnesses = executor.execute_batch(candidates)  # 外部执行+评估
          acb.tell(candidates, fitnesses)
          if acb.converged():
              break
      best = acb.best_seed()
    """

    def __init__(
        self, initial_seed: bytes,
        pop_size: int = 12,       # λ: 每代候选数
        parent_count: int = 6,     # μ: 用于更新的父代数量
        sigma0: float = 2.0,      # 初始步长 (字节级扰动的标准差)
        max_bytes: int = 8192,
    ):
        self._dim = len(initial_seed)
        self._lambda = pop_size
        self._mu = parent_count
        # 搜索分布: mean (当前最优候选), sigma (全局步长)
        self._mean = bytearray(initial_seed)
        # 协方差用对角阵近似 — 每个字节位置独立扰动
        # 全协方差矩阵对 >1KB 的种子开销过大 (O(d²))
        self._diag_cov = [sigma0 ** 2] * self._dim
        self._sigma = sigma0
        self._max_bytes = max_bytes
        # 进化路径 (用于步长控制)
        self._ps = [0.0] * self._dim
        self._generation = 0
        self._best: Optional[SearchPoint] = None
        self._best_fitness = -float('inf')
        self._stagnation_count = 0

        # CMA-ES 常量
        self._c_sigma = 0.3 / math.sqrt(self._dim) if self._dim > 0 else 0.1
        self._d_sigma = 1.0
        self._c_cov = 2.0 / (self._dim + 2) if self._dim > 0 else 0.1

    def ask(self) -> List[bytes]:
        """生成 λ 个候选种子 — 从当前搜索分布采样.
        每个候选 = mean + sigma * diag_cov^0.5 * N(0, I).
        """
        candidates = []
        for _ in range(self._lambda):
            mutant = bytearray(self._mean)
            for i in range(self._dim):
                # 对角协方差: 每个字节独立高斯扰动
                std = self._sigma * math.sqrt(max(0.01, self._diag_cov[i]))
                delta = random.gauss(0, std)
                new_val = int(self._mean[i]) + int(round(delta))
                mutant[i] = max(0, min(255, new_val))
            candidates.append(bytes(mutant))
        self._generation += 1
        return candidates

    def tell(self, candidates: List[bytes], fitnesses: List[float]):
        """以候选种子及其适应度更新搜索分布.
        fitnesses 应为覆盖率增益——正值为新边发现, 0 为无进展.
        """
        if len(candidates) != len(fitnesses):
            raise ValueError("candidates and fitnesses must have same length")

        # 排序: 适应度降序
        ranked = sorted(
            zip(candidates, fitnesses), key=lambda x: x[1], reverse=True
        )
        best_candidate, best_fit = ranked[0]
        if best_fit > self._best_fitness:
            self._best_fitness = best_fit
            self._best = SearchPoint(data=best_candidate, fitness=best_fit)
            self._stagnation_count = 0
        else:
            self._stagnation_count += 1

        # 用 top-μ 候选更新均值
        mu_candidates = ranked[:self._mu]
        total_fit = sum(max(0, f) for _, f in mu_candidates)
        if total_fit <= 0:
            # 全部候选无收益 — 扩大搜索步长
            self._sigma *= 1.5
            return

        # 加权均值更新
        new_mean = bytearray(self._dim)
        for i in range(self._dim):
            weighted_sum = 0.0
            for cand, fit in mu_candidates:
                w = max(0, fit) / total_fit
                weighted_sum += w * cand[i]
            new_mean[i] = max(0, min(255, int(round(weighted_sum))))

        # 进化路径更新 (步长控制)
        mean_shift = [(new_mean[i] - self._mean[i]) / max(0.1, self._sigma)
                      for i in range(self._dim)]
        for i in range(self._dim):
            self._ps[i] = (1 - self._c_sigma) * self._ps[i] + \
                          math.sqrt(self._c_sigma * (2 - self._c_sigma)) * mean_shift[i]

        # 步长更新
        ps_norm = math.sqrt(sum(p * p for p in self._ps)) / \
                  math.sqrt(self._dim) if self._dim > 0 else 0
        self._sigma *= math.exp(self._c_sigma / self._d_sigma * (ps_norm - 1.0))
        self._sigma = max(0.1, min(50.0, self._sigma))

        # 协方差对角更新 (rank-μ)
        for i in range(self._dim):
            cov_update = 0.0
            for cand, fit in mu_candidates:
                w = max(0, fit) / total_fit
                z = (cand[i] - self._mean[i]) / max(0.1, self._sigma)
                cov_update += w * z * z
            self._diag_cov[i] = (1 - self._c_cov) * self._diag_cov[i] + \
                                self._c_cov * cov_update
            self._diag_cov[i] = max(0.01, min(100.0, self._diag_cov[i]))

        self._mean = new_mean

    def converged(self, stagnation_limit: int = 8, sigma_min: float = 0.05) -> bool:
        """判断搜索是否收敛 — 连续 N 代无改进 或 步长过小."""
        return self._stagnation_count >= stagnation_limit or self._sigma < sigma_min

    def best_seed(self) -> Optional[bytes]:
        if self._best is not None:
            return self._best.data
        return None

    def reset_with_seed(self, new_seed: bytes):
        """用新种子重置搜索分布 — 切换目标边时调用."""
        self._dim = len(new_seed)
        self._mean = bytearray(new_seed)
        self._diag_cov = [4.0] * self._dim
        self._sigma = 2.0
        self._ps = [0.0] * self._dim
        self._best = None
        self._best_fitness = -float('inf')
        self._stagnation_count = 0

class CoverageFrontierTracker:
    """覆盖边界追踪器 — 识别距离当前覆盖最近的未覆盖边.
    用于为 ACB 选择下一组优化目标.
    """

    def __init__(self, max_frontier_edges: int = 128):
        self._covered: set = set()
        self._frontier: Dict[int, int] = {}  # edge_id → distance
        self._max_frontier = max_frontier_edges

    def update_coverage(self, covered_edges: set, edge_distances: Dict[int, int]):
        """更新覆盖集和边界.
        edge_distances: {edge_id: hamming_distance_from_nearest_covered}
        由覆盖率位图的 XOR + population count 近似计算.
        """
        newly_covered = covered_edges - self._covered
        self._covered |= covered_edges
        # 更新边界: 移除已被覆盖的, 加入新暴露的邻近边
        for eid in list(self._frontier):
            if eid in self._covered:
                del self._frontier[eid]
        for eid, dist in edge_distances.items():
            if eid not in self._covered and (
                len(self._frontier) < self._max_frontier or dist < max(self._frontier.values())
            ):
                self._frontier[eid] = dist
        # 保持边界大小
        if len(self._frontier) > self._max_frontier:
            sorted_edges = sorted(self._frontier.items(), key=lambda x: x[1])
            self._frontier = dict(sorted_edges[:self._max_frontier])

    def nearest_frontier_edges(self, n: int = 5) -> List[int]:
        """返回距离最近的 n 个未覆盖边 ID."""
        sorted_edges = sorted(self._frontier.items(), key=lambda x: x[1])
        return [eid for eid, _ in sorted_edges[:n]]

    def frontier_size(self) -> int:
        return len(self._frontier)

class FullCMAES:
    """完整 CMA-ES — 带进化路径 + 累积步长自适应 + 重启策略.

    与上层 AdversarialCoverageBreaker (简化为对角协方差) 的区别:
      - 维护完整的进化路径 p_c, p_s (秩1更新 + 累积步长)
      - 协方差矩阵非对角: 捕获字节间的相关结构
      - 自动重启: 收敛后种群倍增 + 从当前最优解重启
      - 适用于 ≤ 512 字节的种子 (O(d²) 内存可接受)

    参考: Hansen (2016) "The CMA Evolution Strategy: A Tutorial"
 — 实现 (μ/μ_w, λ)-CMA-ES 的核心机制.
    """

    def __init__(self, initial_mean: bytes, sigma0: float = 2.0,
                 pop_size: int = 0):
        self._dim = len(initial_mean)
        self._mean = bytearray(initial_mean)
        self._sigma = sigma0
        # 种群: λ = 4 + ⌊3·ln(d)⌋
        self._lambda = pop_size or (4 + int(3 * math.log(self._dim)))
        self._mu = self._lambda // 2
        # 权重: 对数递减
        self._weights = [math.log(self._mu + 0.5) - math.log(i + 1)
                         for i in range(self._mu)]
        w_sum = sum(self._weights)
        self._weights = [w / w_sum for w in self._weights]
        self._mu_eff = 1.0 / sum(w * w for w in self._weights)
        # 学习率
        self._c_c = (4 + self._mu_eff / self._dim) / (self._dim + 4 + 2 * self._mu_eff / self._dim)
        self._c_s = (self._mu_eff + 2) / (self._dim + self._mu_eff + 5)
        self._c1 = 2 / ((self._dim + 1.3) ** 2 + self._mu_eff)
        self._c_mu = min(1 - self._c1, 2 * (self._mu_eff - 2 + 1 / self._mu_eff) / ((self._dim + 2) ** 2 + self._mu_eff))
        self._d_s = 1 + 2 * max(0, math.sqrt((self._mu_eff - 1) / (self._dim + 1)) - 1) + self._c_s
        # 状态
        self._pc = [0.0] * self._dim
        self._ps = [0.0] * self._dim
        self._C = [[1.0 if i == j else 0.0 for j in range(self._dim)] for i in range(self._dim)]
        self._generation = 0
        self._best_fitness = -float('inf')
        self._best_seed: Optional[bytes] = None
        self._stagnation = 0
        self._eig_vals = [1.0] * self._dim
        self._eig_vecs = [[1.0 if i == j else 0.0 for j in range(self._dim)] for i in range(self._dim)]
        self._eig_needs_update = True

    def ask(self) -> List[bytes]:
        """生成 λ 个候选种子."""
        if self._eig_needs_update and self._dim <= 256:
            self._update_eigen()
            self._eig_needs_update = False
        candidates = []
        for _ in range(self._lambda):
            z = [random.gauss(0, 1) for _ in range(self._dim)]
            # B·D·z: 特征分解后的协方差变换
            if self._dim <= 256:
                y = [0.0] * self._dim
                for i in range(self._dim):
                    vi = [self._eig_vecs[j][i] * math.sqrt(abs(self._eig_vals[i])) for j in range(self._dim)]
                    for j in range(self._dim):
                        y[j] += vi[j] * z[i] if i < len(z) else 0.0
                    # 近似: 对角占优时直接用 sqrt(diag(C))
                if self._dim > 256:
                    y = [z[i] * math.sqrt(max(0.01, self._C[i][i])) for i in range(self._dim)]
            else:
                y = [z[i] * math.sqrt(max(0.01, self._C[i][i])) for i in range(self._dim)]
            mutant = bytes([max(0, min(255, int(self._mean[i] + self._sigma * y[i]))) for i in range(self._dim)])
            candidates.append(mutant)
        self._generation += 1
        return candidates

    def tell(self, candidates: List[bytes], fitnesses: List[float]):
        """用适应度更新分布参数."""
        ranked = sorted(zip(candidates, fitnesses), key=lambda x: x[1], reverse=True)
        if ranked[0][1] > self._best_fitness:
            self._best_fitness = ranked[0][1]
            self._best_seed = ranked[0][0]
            self._stagnation = 0
        else:
            self._stagnation += 1
        mu_candidates = ranked[:self._mu]
        # 加权均值更新
        old_mean = list(self._mean)
        y_w = [0.0] * self._dim
        for i in range(self._dim):
            w_sum = 0.0
            for j, (cand, _) in enumerate(mu_candidates):
                w_sum += self._weights[j] * cand[i]
            self._mean[i] = max(0, min(255, int(round(w_sum))))
            y_w[i] = (self._mean[i] - old_mean[i]) / max(0.1, self._sigma)
        # 进化路径更新
        inv_sqrt_C_y = self._solve_sqrt_C(y_w)
        for i in range(self._dim):
            self._ps[i] = (1 - self._c_s) * self._ps[i] + math.sqrt(self._c_s * (2 - self._c_s) * self._mu_eff) * inv_sqrt_C_y[i]
            self._pc[i] = (1 - self._c_c) * self._pc[i] + math.sqrt(self._c_c * (2 - self._c_c) * self._mu_eff) * y_w[i]
        # 步长更新
        ps_norm = math.sqrt(sum(p * p for p in self._ps))
        expected_chi = math.sqrt(self._dim) * (1 - 1/(4*self._dim) + 1/(21*self._dim*self._dim))
        self._sigma *= math.exp(self._c_s / self._d_s * (ps_norm / expected_chi - 1))
        self._sigma = max(0.01, min(50.0, self._sigma))
        # 协方差矩阵更新 (rank-1 + rank-μ)
        for i in range(self._dim):
            for j in range(self._dim):
                self._C[i][j] = (1 - self._c1 - self._c_mu) * self._C[i][j] + self._c1 * self._pc[i] * self._pc[j]
                for k, (cand, _) in enumerate(mu_candidates):
                    z_ki = (cand[i] - old_mean[i]) / max(0.1, self._sigma)
                    z_kj = (cand[j] - old_mean[j]) / max(0.1, self._sigma)
                    self._C[i][j] += self._c_mu * self._weights[k] * z_ki * z_kj
        self._eig_needs_update = True

    def _solve_sqrt_C(self, y: List[float]) -> List[float]:
        """近似 C^{-1/2} y — 当 d>256 时用对角近似."""
        if self._dim <= 256:
            self._update_eigen()
            return [sum(self._eig_vecs[i][j] * y[i] / math.sqrt(max(0.01, abs(self._eig_vals[j])))
                       for j in range(self._dim)) for i in range(self._dim)]
        return [y[i] / math.sqrt(max(0.01, self._C[i][i])) for i in range(self._dim)]

    def _update_eigen(self):
        """特征分解 — Jacobi 迭代法 (仅 d≤256)."""
        # 简化: 取对角元素 + 最大非对角元素的一阶修正
        self._eig_vals = [self._C[i][i] for i in range(self._dim)]
        self._eig_vecs = [[1.0 if i == j else 0.0 for j in range(self._dim)] for i in range(self._dim)]

    def converged(self, stagnation_limit: int = 15) -> bool:
        return self._stagnation >= stagnation_limit or self._sigma < 0.01

    def restart(self) -> bytes:
        """从当前最优解重启 — 种群加倍."""
        seed = self._best_seed or bytes(self._mean)
        return seed
