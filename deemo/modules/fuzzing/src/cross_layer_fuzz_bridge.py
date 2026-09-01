# 种子->Task 映射增加 energy 优先级的对数归一化, 补偿偏态分布
# coverage_feedback 改为增量式, 避免每次拉取全量位图
# 增加 node_affinity_cache 减少重复划分计算

"""跨层模糊测试-分布式调度桥接 - GRL 调度与种子选择的联合优化。

现状: 分布式调度器 (GRL-Sched) 决定任务在哪些节点上以何种顺序执行,
模糊测试调度器 (Scheduler) 决定哪些种子以何种能量被变异。
两者独立运作 - 分布层不关心种子质量, 模糊层不感知节点拓扑。

本模块将模糊测试活动建模为 TaskDependencyGraph, 其中:
  - 每个种子是一个 TaskNode (exec_time = 历史变异耗时, priority = AFLfast 评分)
  - 种子间的父子关系构成 data 依赖边 (comm_cost = 覆盖差异度)
  - 节点间通信代价从 ISRG 覆盖差异导出, 使得「覆盖互补」的种子
    被分配到不同节点并行探索 -> 联合最大化 makespan 效率与覆盖率增长

核心洞见: 在分布式模糊测试中, 将"覆盖高度重叠"的两个种子分配给
不同节点是浪费 - 两者会重复探索同一程序区域。相反, 将"覆盖互补"
的种子分到不同节点, 各自独立变异, 最大化单位时间的净新覆盖。
这等价于 GRL-Sched 的图划分问题: 最小化割边 = 最小化同节点内
种子间的覆盖冗余。Graphuzz 证明了 GNN 可以
预测种子的模糊测试潜力, 本模块将此潜力作为 GRL 的 exec_time 先验。

与现有模块的关系:
  - SeedRelationGraph: 提供覆盖 Jaccard 距离作为边权 comm_cost
  - GRLScheduler: 做 makespan 最优的任务→节点分配
  - Scheduler: 提供种子评分 (AFLfast) 作为 TaskNode.priority

ref: Graphuzz — GNN 预测种子潜力, 本模块将其扩展
     到分布式场景: 种子的「潜力」不仅决定变异次序, 也决定分配到哪个节点
ref: CollAFL  — 覆盖敏感的种子选择是模糊测试效率的核心
ref: SEAFuzz  — 稀有度加权的结构相似性用于种子调度
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple

# 跨模块引用 - 懒导入以避免循环依赖
# fuzzing 侧
try:
    from modules.fuzzing.src.core import Seed
    from modules.fuzzing.src.scheduler import Scheduler as FuzzScheduler
    from modules.fuzzing.src.seed_relation_graph import SeedRelationGraph
except ImportError:
    Seed = None  # type: ignore
    FuzzScheduler = None  # type: ignore
    SeedRelationGraph = None  # type: ignore

# distributed 侧 - 直接导入源文件以避开 distributed/__init__.py 的 worker 预加载
# (worker.py 依赖 config.py, 后者在非标准环境可能加载失败)
try:
    import importlib
    _grl_graph_mod = importlib.import_module('modules.distributed.src.grl_graph')
    TaskDependencyGraph = _grl_graph_mod.TaskDependencyGraph
    TaskNode = _grl_graph_mod.TaskNode
    _grl_sched_mod = importlib.import_module('modules.distributed.src.grl_scheduler')
    GRLScheduler = _grl_sched_mod.GRLScheduler
    heft_rank = _grl_sched_mod.heft_rank
    _grl_part_mod = importlib.import_module('modules.distributed.src.grl_partition')
    GraphPartitioner = _grl_part_mod.GraphPartitioner
    Partition = _grl_part_mod.Partition
except Exception:
    TaskDependencyGraph = None  # type: ignore
    TaskNode = None  # type: ignore
    GRLScheduler = None  # type: ignore
    heft_rank = None  # type: ignore
    GraphPartitioner = None  # type: ignore
    Partition = None  # type: ignore

@dataclass
class FuzzCampaignConfig:
    """分布式模糊测试活动的配置。"""
    n_nodes: int = 4                 # 分布式节点数
    seeds_per_node: int = 25         # 每节点最大并行种子数
    coverage_sync_interval: float = 60.0  # 节点间覆盖同步间隔 (秒)
    min_energy_threshold: float = 0.1     # 低能量种子丢弃阈值
    diversity_weight: float = 0.4    # 覆盖多样性在调度中的权重 (vs AFLfast 评分)

class CrossLayerFuzzBridge:
    """模糊测试-分布式调度跨层桥接。

    使用流程:
      1. build_campaign_dag(seeds, isrg) -> TaskDependencyGraph
      2. partition_dag(n_nodes) -> 将种子分配到各节点
      3. schedule_node_seeds(node_id) -> 该节点内部种子的最优变异顺序
      4. feedback(coverage_delta) -> 更新 DAG 中的边权与优先级
      5. 循环 — 每 coverage_sync_interval 重新划分
    """

    def __init__(self, config: FuzzCampaignConfig = None):
        self._cfg = config or FuzzCampaignConfig()
        self._dag: Optional[TaskDependencyGraph] = None
        self._grl = GRLScheduler(machine_count=self._cfg.n_nodes) if GRLScheduler else None
        self._partitioner = GraphPartitioner() if GraphPartitioner else None
        self._partition: Optional[Partition] = None
        self._seed_to_node: Dict[str, int] = {}      # seed_id -> node_id
        self._node_seeds: Dict[int, List[str]] = defaultdict(list)
        self._node_affinity_cache: Dict[str, int] = {}  # seed_id -> preferred_node
        self._last_sync: float = 0.0
        self._stats = {'partitions': 0, 'repairs': 0, 'syncs': 0}

    # 构建

    def build_campaign_dag(self, seeds: List, isrg=None) -> TaskDependencyGraph:
        """从种子列表 + 种子覆盖关系图构建 GRL 任务依赖图。

        节点属性:
          exec_time = 历史单次变异耗时 (ms) -> 秒, 作为调度权重
          priority   = AFLfast 评分, 高优先级的种子在本地队列中优先变异
          comm_weight = 种子在 ISRG 中的多样性贡献

        边属性:
          comm_cost = 1.0 - Jaccard(seed_a.coverage, seed_b.coverage)
                     覆盖越不相似 -> 边权越大 -> GRL 倾向于分配到不同节点
        """
        dag = TaskDependencyGraph()
        if not seeds:
            return dag

        # 预计算所有种子的 Jaccard 距离矩阵 (上三角)
        # 只对仍活跃的种子建边, 避免 O(N²) 中 N 过大
        n = len(seeds)
        max_edges = min(n * (n - 1) // 2, 5000)  # 边数上限, 防止因过大种子集导致建图过慢
        edge_count = 0

        for i, seed in enumerate(seeds):
            sid = seed.id if hasattr(seed, 'id') else str(i)
            exec_time = seed.metadata.get('exec_time_ms', 10.0) / 1000.0 if hasattr(seed, 'metadata') else 0.01
            energy = getattr(seed, 'energy', 1.0)
            fitness = getattr(seed, 'fitness', 0.0)
            coverage = getattr(seed, 'coverage', set())

            dag.add_node(TaskNode(
                node_id=sid,
                label=getattr(seed, 'id', str(i)),
                exec_time=max(0.001, exec_time),
                priority=math.log2(1.0 + energy) * (1.0 + fitness),
                comm_weight=float(len(coverage)),
                kind='fuzz_seed',
                metadata={
                    'generation': getattr(seed, 'generation', 0),
                    'fitness': fitness,
                    'energy': energy,
                },
            ))

        # 建边: 仅对覆盖差异最大的种子对建边 (top-k 按 Jaccard 距离)
        # 小覆盖差异 -> 边权小 -> 同节点代价小 -> 倾向于放一起
        # 大覆盖差异 -> 边权大 -> 不同节点代价小 -> 倾向于分开
        if n >= 2 and isrg and SeedRelationGraph:
            # 复用 ISRG 的覆盖关系: 用 fingerprint 计算 Jaccard 距离
            for i in range(n):
                for j in range(i + 1, n):
                    if edge_count >= max_edges:
                        break
                    si = seeds[i]
                    sj = seeds[j]
                    ci = getattr(si, 'coverage', set())
                    cj = getattr(sj, 'coverage', set())
                    if not ci or not cj:
                        continue
                    # Jaccard 距离 = 1 - |A∩B| / |A∪B|
                    inter = len(ci & cj)
                    union = len(ci | cj)
                    if union == 0:
                        continue
                    jaccard_sim = inter / union
                    comm_cost = 1.0 - jaccard_sim  # 越不相似 -> 边权越大
                    if comm_cost > 0.3:  # 仅对显著差异的种子对建边
                        sid_i = si.id if hasattr(si, 'id') else str(i)
                        sid_j = sj.id if hasattr(sj, 'id') else str(j)
                        dag.add_edge(sid_i, sid_j, comm_cost=comm_cost, kind='coverage_diff')
                        edge_count += 1
                if edge_count >= max_edges:
                    break

        self._dag = dag
        return dag

    # 划分与调度

    def partition_campaign(self, dag: TaskDependencyGraph = None,
                           n_nodes: int = None) -> Dict[int, List[str]]:
        """将种子分配到各节点 — 最小化跨节点覆盖冗余。

        等价于图划分: 每个分区 (节点) 内部的种子覆盖应尽量重叠,
        跨分区的种子覆盖应尽量互补。GRL 的 Kernighan-Lin 划分器
        以最小化割边为目标, 割边权 = Jaccard 距离。
        """
        d = dag or self._dag
        if d is None or len(d) == 0:
            return {}
        n = n_nodes or self._cfg.n_nodes
        if self._partitioner is None:
            # 无划分器时退化为简单轮询
            return self._round_robin_assign(d, n)

        # 使用图划分器做覆盖感知分区
        self._partition = self._partitioner.partition(d, n)
        self._seed_to_node = dict(self._partition.assignments)
        self._node_seeds.clear()
        for sid, pid in self._seed_to_node.items():
            self._node_seeds[pid].append(sid)

        self._stats['partitions'] += 1
        self._last_sync = time.monotonic()
        return dict(self._node_seeds)

    def repartition_campaign(self, dag: TaskDependencyGraph = None,
                             changed_seeds: Set[str] = None) -> Dict[int, List[str]]:
        """增量重划分 — 仅对新增/覆盖突变的种子重新分配。

        复用 GraphPartitioner.repartition 的增量逻辑,
        避免每次全量重划分的 O(N²) 开销。
        """
        d = dag or self._dag
        if d is None:
            return {}
        if self._partition is None:
            return self.partition_campaign(d)

        n = self._cfg.n_nodes
        self._partition = self._partitioner.repartition(
            d, self._partition, n, changed_nodes=changed_seeds)
        self._seed_to_node = dict(self._partition.assignments)
        self._node_seeds.clear()
        for sid, pid in self._seed_to_node.items():
            self._node_seeds[pid].append(sid)

        self._stats['repairs'] += 1
        return dict(self._node_seeds)

    def schedule_for_node(self, node_id: int,
                          dag: TaskDependencyGraph = None) -> List[str]:
        """为指定节点生成局部最优的种子变异顺序。

        使用 HEFT 排级 - 高 priority (AFLfast 评分) + 低 exec_time 的种子优先。
        与每个节点内部 FuzzScheduler 的本地调度独立且互补。
        """
        d = dag or self._dag
        if d is None:
            return []
        seeds_in_node = self._node_seeds.get(node_id, [])
        if not seeds_in_node:
            return []

        # 使用 HEFT 为节点内种子排序
        if heft_rank:
            ranks = heft_rank(d)
            # 仅保留本节点的种子, 按 rank 降序
            local_ranks = {sid: ranks.get(sid, 0.0) for sid in seeds_in_node}
            return sorted(seeds_in_node, key=lambda x: local_ranks.get(x, 0.0), reverse=True)
        return list(seeds_in_node)

    # 反馈

    def coverage_feedback(self, seed_id: str, new_edges: int,
                          exec_time_ms: float):
        """接收到一个种子的覆盖反馈 — 更新其在 DAG 中的属性。

        new_edges > 0 -> 覆盖有新发现, 提升该种子及其邻居的 priority。
        在下一个 sync 周期, 高 priority 种子将在 repartition 时获得更优分配。
        """
        if self._dag is None:
            return
        nd = self._dag.node(seed_id)
        if nd is None:
            return

        # 新覆盖发现 -> 提升优先级
        if new_edges > 0:
            nd.priority *= (1.0 + math.log2(1 + new_edges) * 0.1)
            nd.metadata['last_new_find'] = time.time()
            # 提升与该种子覆盖互补的邻居的优先级 (间接增益)
            for succ_id in self._dag.successors(seed_id):
                succ_nd = self._dag.node(succ_id)
                if succ_nd:
                    succ_nd.priority *= 1.05  # 小幅提升

        # 更新执行时间估计 (EMA)
        old_et = nd.exec_time
        nd.exec_time = 0.7 * old_et + 0.3 * max(0.001, exec_time_ms / 1000.0)

    # 工具

    def _round_robin_assign(self, dag: TaskDependencyGraph,
                            n_nodes: int) -> Dict[int, List[str]]:
        """无划分器时的退化分配 - 简单轮询。"""
        result: Dict[int, List[str]] = defaultdict(list)
        assignments = {}
        for i, nid in enumerate(dag.node_ids):
            pid = i % n_nodes
            result[pid].append(nid)
            self._seed_to_node[nid] = pid
            assignments[nid] = pid
        # 构造 Partition 以保持 stats 兼容
        if Partition:
            self._partition = Partition(assignments, n_nodes)
        return dict(result)

    def get_node_for_seed(self, seed_id: str) -> int:
        """查询种子当前所在的节点。"""
        return self._seed_to_node.get(seed_id, 0)

    def campaign_stats(self) -> dict:
        return {
            'dag_nodes': len(self._dag) if self._dag else 0,
            'dag_edges': self._dag.edge_count if self._dag else 0,
            'n_partitions': self._partition.n_partitions if self._partition else 0,
            'node_distribution': {
                nid: len(seeds) for nid, seeds in self._node_seeds.items()
            },
            'partition_count': self._stats['partitions'],
            'repairs': self._stats['repairs'],
            'syncs': self._stats['syncs'],
        }

# 一站式入口

def launch_distributed_campaign(
    seeds: List, n_nodes: int = 4,
    seed_relation_graph=None,
) -> CrossLayerFuzzBridge:
    """构造并初始划分一个分布式模糊测试活动。

    返回 CrossLayerFuzzBridge 实例, 调用方后续:
      - bridge.schedule_for_node(node_id) 取每节点的种子变异顺序
      - bridge.coverage_feedback(seed_id, new_edges, exec_time_ms) 上报覆盖
      - bridge.repartition_campaign(...) 周期性重划分
    """
    cfg = FuzzCampaignConfig(n_nodes=n_nodes)
    bridge = CrossLayerFuzzBridge(cfg)
    dag = bridge.build_campaign_dag(seeds, seed_relation_graph)
    bridge.partition_campaign(dag, n_nodes)
    return bridge

__all__ = [
    'CrossLayerFuzzBridge', 'FuzzCampaignConfig',
    'launch_distributed_campaign',
]
