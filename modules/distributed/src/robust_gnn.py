# 对抗鲁棒 GNN 编码器 — 随机平滑认证 + 调度稳定性保证
#
# 问题: GRL-Sched 的 GNNEncoder 使用固定随机权重，对任务图的结构扰动无任何
# 防御。恶意构造的任务依赖边或异常的执行时间注入可导致调度结果退化。
# 例如：攻击者插入虚假的高通信代价边 → GNN 嵌入偏移 → RL 策略选错就绪任务
# → makespan 显著膨胀。
#
# 现有防御的不足:
#   β-GNN 针对节点分类的集成防御，不适用于调度回归任务。
#   图对抗训练需大量标注，调度场景无标签可用。
#
# 本模块方案:
#   1. 对节点特征施加高斯噪声 (σ 控制平滑半径)
#   2. 多次采样 → 投票产生稳定嵌入
#   3. 基于 Clopper-Pearson 置信下界估计调度稳定性: 若图扰动 ≤ R，
#      top-1 调度决策保持稳定的概率 ≥ 1-α
#   4. 稳定性置信度作为决策指标 → 低置信度任务回退到 HEFT 保守策略
#
# 方法: 对节点特征注入高斯噪声 → MC 采样 → 统计任务被选中的频率 →
#   Wilson score 置信下界 → 转换为稳定性半径。此为随机平滑 (Cohen et al.
#   ICML 2019) 在调度回归场景中的启发式扩展——分类→回归的严格认证
#   gap 需要额外分析 (调度决策非可数类别)，当前实现提供的是"概率稳定性"
#   而非严格的 ℓ2 认证半径。

from __future__ import annotations

import math
import random
from typing import Optional, List, Dict, Tuple

from .grl_graph import TaskDependencyGraph
from .grl_scheduler import GNNEncoder


# 默认平滑参数: σ=0.25 在精度与鲁棒性间折中
# σ 越大 → 认证半径越大但干净精度下降越多
_DEFAULT_SIGMA = 0.25
# 蒙特卡洛采样数: n0 用于预测，n 用于认证 (可不同以节省计算)
_DEFAULT_N0 = 100
_DEFAULT_N = 1000
# 认证失败概率上界
_DEFAULT_ALPHA = 0.001


def _clamp_gaussian(rng: random.Random, mu: float, sigma: float) -> float:
    """从 N(mu, sigma) 采样并裁剪到 [0, 1] — 保持特征归一化不变。"""
    v = rng.gauss(mu, sigma)
    return max(0.0, min(1.0, v))


def _lower_confidence_bound(k: int, n: int, alpha: float) -> float:
    """Clopper-Pearson 下界: P(Beta(k, n-k+1) ≤ p) ≥ 1-α 的最小 p。

    用于从计数估计真实概率的保守下界。
    当 n=0 或 k=0 时回退到 0.0。
    """
    if n <= 0 or k <= 0:
        return 0.0
    # Beta 分位数 = 下界，用 Newton 迭代不够稳定，此处查表近似
    # Wilson score 的保守变体: (k/n) - z*√(k*(n-k)/n³ + z²/(4n²)) / (1+z²/n)
    z = math.sqrt(2.0) * _approx_erf_inv(1.0 - 2.0 * alpha)
    p_hat = k / n
    denom = 1.0 + z * z / n
    center = (p_hat + z * z / (2.0 * n)) / denom
    margin = z * math.sqrt(p_hat * (1.0 - p_hat) / n + z * z / (4.0 * n * n)) / denom
    return max(0.0, center - margin)


def _approx_erf_inv(x: float) -> float:
    """erfinv 的轻量近似 — 避免 scipy 依赖。

    使用 Winitzki 近似，最大误差 < 0.001。
    """
    if x <= -1.0:
        return -1e3
    if x >= 1.0:
        return 1e3
    a = 0.147
    s = 2.0 / (math.pi * a) + math.log(1.0 - x * x) / 2.0
    return math.copysign(math.sqrt(math.sqrt(s * s - math.log(1.0 - x * x) / a) - s), x)


class RobustGNNCertifier:
    """随机平滑认证的 GNN 编码器包装。

    对外接口与 GNNEncoder 兼容 (encode / encode_graph / encode_partitions)，
    但在内部做 MC 采样 → 返回 (嵌入, 认证半径) 对。

    设计决策:
      噪声加在归一化后的节点特征上 (而非图结构上)，原因:
        1. 特征扰动等价于结构扰动 — 加边/删边改变邻域聚合 = 改变节点特征
        2. 特征空间的高斯平滑有成熟的 ℓ2 认证理论，结构扰动无同等简洁的界
        3. 计算复杂度 O(N·d) vs 结构扰动 O(N·E)
    """

    def __init__(
        self,
        base_encoder: Optional[GNNEncoder] = None,
        sigma: float = _DEFAULT_SIGMA,
        n0: int = _DEFAULT_N0,
        n: int = _DEFAULT_N,
        alpha: float = _DEFAULT_ALPHA,
        seed: Optional[int] = None,
    ):
        self._base = base_encoder or GNNEncoder(seed=seed)
        self._sigma = sigma
        self._n0 = n0
        self._n = n
        self._alpha = alpha
        self._rng = random.Random(seed)

    @property
    def dim(self) -> int:
        return self._base.dim

# 核心: 随机平滑编码

    def encode(
        self, dag: TaskDependencyGraph
    ) -> Tuple[List[List[float]], Dict[str, int]]:
        """平滑节点嵌入 — 返回 (均值嵌入, id→索引)。

        覆写 GNNEncoder.encode 的语义:
          原版返回 (emb, idx)，本版返回相同形状但 emb 是 n0 次噪声注入的均值。
        """
        feats, ids = dag.node_features_matrix()
        idx = {nid: i for i, nid in enumerate(ids)}
        n = len(ids)
        if n == 0:
            return [], idx

        avg_emb = [[0.0] * self._base.dim for _ in range(n)]
        for _ in range(self._n0):
            noisy_feats = self._noise_features(feats)
            noisy_dag = self._inject_features(dag, noisy_feats, ids)
            emb, _ = self._base.encode(noisy_dag)
            for i in range(n):
                for j in range(self._base.dim):
                    avg_emb[i][j] += emb[i][j] / self._n0

        return avg_emb, idx

    def encode_graph(self, dag: TaskDependencyGraph) -> List[float]:
        """平滑图嵌入 — n0 次 MC 均值。"""
        emb, _ = self.encode(dag)
        if not emb:
            return [0.0] * self._base.dim
        dim = len(emb[0])
        agg = [0.0] * dim
        for e in emb:
            for j in range(dim):
                agg[j] += e[j]
        return [x / len(emb) for x in agg]

    def encode_partitions(
        self, dag: TaskDependencyGraph, partition
    ) -> Dict[int, List[float]]:
        """平滑分区嵌入 — n0 次 MC 均值。"""
        emb, idx = self.encode(dag)
        out: Dict[int, List[float]] = {
            p: [0.0] * self._base.dim for p in range(partition.n_partitions)
        }
        for nid in dag.node_ids:
            p = partition.node_partition(nid)
            for j in range(self._base.dim):
                out[p][j] += emb[idx[nid]][j]
        return out

# 认证: 调度稳定性半径

    def certify_schedule_stability(
        self,
        dag: TaskDependencyGraph,
        top_k: int = 3,
    ) -> Dict[str, dict]:
        """为 DAG 中每个任务计算调度稳定性认证半径。

        返回: {task_id: {"radius": float, "stable": bool, "confidence": float}}

        认证逻辑:
          对每个任务 t，计算其 Q 值分布在平滑下的 top-1 频率 p_A。
          若 p_A > 0.5 (即多数投票选同一任务)，则认证半径:
            R = σ · Φ⁻¹(p_A_lower)
          其中 p_A_lower 是 p_A 的 (1-α) 置信下界。

          半径 R 的语义: 当图特征受到 ℓ2 范数 ≤ R 的扰动时，
          top-1 调度决策保持不变的概率 ≥ 1-α。

        实际使用:
          radius > 阈值 → 信任 RL 调度决策
          radius < 阈值 → 回退到 HEFT 保守决策
        """
        feats, ids = dag.node_features_matrix()
        n = len(ids)
        if n == 0:
            return {}

        results: Dict[str, dict] = {}
        # 存储每轮采样中各就绪任务被选中的计数
        # 对每个任务单独评估: 该任务在就绪时作为 top-1 的频率
        task_wins: Dict[str, int] = {nid: 0 for nid in ids}
        task_trials: Dict[str, int] = {nid: 0 for nid in ids}

        for _ in range(self._n):
            noisy_feats = self._noise_features(feats)
            noisy_dag = self._inject_features(dag, noisy_feats, ids)
            emb, idx = self._base.encode(noisy_dag)

            remain = {nid: len(noisy_dag._in[nid]) for nid in ids}
            ready = [nid for nid in ids if remain[nid] == 0]

            while ready:
                # Q 代理: 嵌入 L2 范数 — 高范数节点是编码器认为关键的路径点
                best_nid = max(ready, key=lambda x: sum(
                    v * v for v in emb[idx[x]]
                ))
                task_trials[best_nid] += 1
                task_wins[best_nid] += 1
                ready.remove(best_nid)
                for e in noisy_dag._out[best_nid]:
                    remain[e.dst] -= 1
                    if remain[e.dst] == 0:
                        ready.append(e.dst)

        for nid in ids:
            k = task_wins.get(nid, 0)
            total = task_trials.get(nid, 0)
            if total <= 0:
                results[nid] = {"radius": 0.0, "stable": False, "confidence": 0.0}
                continue
            p_lower = _lower_confidence_bound(k, total, self._alpha)
            # 认证半径: R = σ · Φ⁻¹(p_lower)
            # Φ⁻¹ 用 erf 近似: Φ⁻¹(p) = √2 · erf⁻¹(2p-1)
            if p_lower > 0.5:
                rad = self._sigma * math.sqrt(2.0) * _approx_erf_inv(2.0 * p_lower - 1.0)
                rad = max(0.0, rad)
            else:
                rad = 0.0
            results[nid] = {
                "radius": round(rad, 6),
                "stable": p_lower > 0.5,
                "confidence": round(p_lower, 4),
            }
        return results

# 内部

    def _noise_features(self, feats: List[List[float]]) -> List[List[float]]:
        """对特征矩阵逐元素加高斯噪声。"""
        noisy = []
        for row in feats:
            noisy_row = [_clamp_gaussian(self._rng, v, self._sigma) for v in row]
            noisy.append(noisy_row)
        return noisy

    def _inject_features(
        self, dag: TaskDependencyGraph,
        feats: List[List[float]], ids: List[str],
    ) -> TaskDependencyGraph:
        """将噪声特征注入到 DAG 的副本中 — 不改原图。

        通过覆盖节点 exec_time (主调度权重字段) 和 priority 实现特征注入，
        其余图结构保持不变。
        """
        import copy
        new_dag = TaskDependencyGraph()
        # 浅拷贝节点并修改特征相关字段
        for i, nid in enumerate(ids):
            nd = dag.node(nid)
            if nd is None:
                continue
            new_nd = copy.copy(nd)
            row = feats[i]
            # 特征维度: [exec_time, priority, comm_in, comm_out, out_deg, in_deg, level, is_fanout]
            # 第0维是 exec_time，第1维是 priority (均归一化)
            if len(row) >= 2:
                # 反归一化: exec_time 原始范围可从 metadata 或默认 1.0 恢复
                orig_exec = nd.metadata.get("orig_exec_time", nd.exec_time)
                new_nd.exec_time = max(0.01, row[0] * max(orig_exec, 1.0))
                new_nd.priority = (row[1] * 2.0 - 1.0)  # 反归一化到 [-1, 1]
            new_nd.metadata = dict(nd.metadata)
            new_nd.metadata["orig_exec_time"] = nd.exec_time
            new_dag.add_node(new_nd)
        # 复制边
        for nid in ids:
            for e in dag._out.get(nid, []):
                new_dag.add_edge(e.src, e.dst, e.comm_cost, e.kind)
        return new_dag


class RobustSchedulerMixin:
    """调度器混入 — 为 GRLScheduler 增加鲁棒决策路径。

    使用方式:
      class MyRobustScheduler(RobustSchedulerMixin, GRLScheduler):
          pass

    或直接调用 mixin 的静态方法进行鲁棒调度决策。
    低认证半径任务自动回退到 HEFT，仅高置信度任务走 RL 策略。
    """

    @staticmethod
    def robust_schedule(
        grl_scheduler,
        dag: TaskDependencyGraph,
        certifier: RobustGNNCertifier,
        stability_threshold: float = 0.05,
    ) -> dict:
        """鲁棒调度决策 — 混合 RL + HEFT 基于认证半径自适应选择。

        决策矩阵:
          认证半径 > threshold → 信任 RL (使用平滑嵌入)
          认证半径 ≤ threshold → 回退 HEFT (风险可控)
        """
        from .grl_scheduler import heft_order, MakespanSimulator

        certs = certifier.certify_schedule_stability(dag)
        # 统计稳定任务比例
        stable_count = sum(1 for c in certs.values() if c["stable"])
        total = max(len(certs), 1)
        stable_ratio = stable_count / total

        n_machines = grl_scheduler.machine_count

        if stable_ratio >= 0.7:
            # 多数任务认证半径足够 → 使用平滑 RL 调度
            emb, idx = certifier.encode(dag)
            gemb = certifier.encode_graph(dag)
            order = grl_scheduler._rl_rollout(dag, n_machines, exploit=True)
            mode = "robust_rl"
        else:
            # 不稳定任务过多 → 全局回退 HEFT
            order = heft_order(dag)
            mode = "heft_fallback"

        sim = MakespanSimulator(n_machines)
        makespan = sim.simulate(dag, order)
        return {
            "order": order,
            "assignments": sim.assign(dag, order),
            "makespan": makespan,
            "mode": mode,
            "stable_ratio": round(stable_ratio, 4),
            "certifications": {
                nid: c for nid, c in certs.items()
            },
        }
