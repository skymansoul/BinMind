"""符号执行与模糊测试器的双向协作总线。

符号执行产出约束提示, 引导 fuzzer 向难以到达的分支逼近;
fuzzer 回传覆盖率报告与种子, symbex 据此剪枝已覆盖路径。
消息总线解耦两侧, 可独立替换。

增强:
- 种子年龄衰减: 种子超过 5 个 tick 后评分权重按 0.95^age 指数递减,
  防止过时种子占据队列
- 优先级反转检测 + 前馈预测: PriorityInversionDetector 追踪高难度
  hint 是否在 5 tick 内产出种子, 超时则重发; FeedForwardPredictor
  用 SGD 维护线性模型 (w1·ent + w2·difficulty + w3) 预测覆盖率增益,
  低预测值的种子在运行前被过滤, 节省 fuzzer 的计算预算
- 覆盖率速度监控: 维护最近 5 个 tick 的 edges/tick 滑动窗口,
  速度连续 3 个窗口低于历史峰值的 20% 时发出停滞警告
- 种子三分法 (triage): 自动将种子分类为 crash / coverage_gain / stale,
  便于 fuzzer 侧做差异化处理
- SeedGenealogyTree: 追踪种子亲缘关系, 构建父→子演化树,
  支持导出 DOT/Graphviz 格式可视化种子进化路径
- CoverageFrontierTracker: 识别覆盖前沿——已发现但其邻接边尚未覆盖
  的边, 优先调度指向前沿邻接分支的 hint
- MutualInformationScoring: 计算种子特征 (熵、长度、字节模式) 与
  覆盖率增益之间的互信息, 用 MI 得分筛选最能预测覆盖率增益的特征
"""

import logging
import os
import time
import json
import hashlib
import math
import struct
import threading
from dataclasses import dataclass, field
from collections import defaultdict, deque
from typing import Dict, Any
from typing import List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CoopRole:
    SYMBEX = "symbex"
    FUZZER = "fuzzer"
    BOTH = "both"


class MessageKind:
    CONSTRAINT_HINT = "constraint_hint"
    COVERAGE_REPORT = "coverage_report"
    SEED_REQUEST = "seed_request"
    SEED_DELIVERY = "seed_delivery"
    NEW_PATH = "new_path"


@dataclass
class CoopMessage:
    """跨 symbex-模糊测试器总线的单条消息。"""
    kind: str
    sender: str
    timestamp: float
    payload: Dict = field(default_factory=dict)
    priority: int = 0


@dataclass
class SeedItem:
    """fuzzer 产生的输入, 含覆盖率指纹与崩溃标记。"""
    data: bytes
    coverage_hash: str
    crash: bool = False
    timestamp: float = field(default_factory=time.time)
    source: str = "fuzzer"
    score: float = 0.0
    tick_born: int = 0
    seed_id: str = ""


@dataclass
class ConstraintHint:
    """symbex 产出的提示: 让 fuzzer 瞄准的分支条件。"""
    func_name: str
    constraints: List
    target_path: Any
    suggested_inputs: Dict = field(default_factory=dict)
    difficulty: float = 0.5


@dataclass
class CoverageReport:
    """fuzzer 周期发送给 symbex 的覆盖率快照。"""
    total_edges: int
    new_edges: int
    edge_bitmap: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class CoopStats:
    """协作通道的运行计数。"""
    messages_sent: int = 0
    messages_received: int = 0
    symbex_to_fuzzer: int = 0
    fuzzer_to_symbex: int = 0
    new_coverage: int = 0
    seeds_delivered: int = 0
    hints_delivered: int = 0
    stagnation_epochs: int = 0


class MessageBus:
    """每角色一条单向队列, 高优先级消息 (difficulty > 0.7 的
    constraint_hint) 先投递。"""

    def __init__(self):
        self.queues: Dict[str, deque] = {
            CoopRole.SYMBEX: deque(),
            CoopRole.FUZZER: deque()
        }
        self._lock = threading.Lock()

    def send(self, msg: CoopMessage):
        target = (CoopRole.FUZZER if msg.sender == CoopRole.SYMBEX
                  else CoopRole.SYMBEX)
        with self._lock:
            self.queues[target].append(msg)

    def receive(self, role: str, timeout: float = 1.0) -> List[CoopMessage]:
        msgs: List[CoopMessage] = []
        deadline = time.time() + timeout
        with self._lock:
            # 优先级排序：高难度约束提示优先
            items = list(self.queues[role])
            items.sort(key=lambda m: -m.priority)
            self.queues[role].clear()
            for m in items:
                if time.time() >= deadline:
                    self.queues[role].append(m)
                else:
                    msgs.append(m)
        return msgs


class CoverageTracker:
    """维护已覆盖边集合并推导位图哈希。

    增强: 速度监控 — 维护最近 5 次更新的 edges 增量滑动窗口,
    计算 edges/tick 速度, 速度 < 峰值的 20% 时递增停滞计数。
    """

    def __init__(self, max_edges: int = 65536):
        self.max_edges = max_edges
        self.edges: Set[int] = set()
        self._lock = threading.Lock()
        self._velocity_window: List[int] = []
        self._velocity_window_max = 5
        self.stagnation_epochs = 0
        self._peak_velocity = 1

    def update(self, new_edges: Set[int]) -> int:
        with self._lock:
            before = len(self.edges)
            self.edges.update(new_edges)
            delta = len(self.edges) - before
            self._velocity_window.append(delta)
            if len(self._velocity_window) > self._velocity_window_max:
                self._velocity_window.pop(0)
            avg_vel = sum(self._velocity_window) / max(1, len(self._velocity_window))
            self._peak_velocity = max(self._peak_velocity, avg_vel)
            if self._peak_velocity > 0 and avg_vel < self._peak_velocity * 0.2:
                self.stagnation_epochs += 1
            return delta

    def bitmap_hash(self) -> str:
        sorted_edges = sorted(self.edges)
        h = hashlib.sha256()
        for e in sorted_edges:
            h.update(struct.pack("<Q", e))
        return h.hexdigest()[:32]

    def to_bitmap(self) -> str:
        bits = bytearray(self.max_edges // 8)
        for e in self.edges:
            if e < self.max_edges:
                bits[e // 8] |= 1 << (e % 8)
        return bits.hex()

    def total(self) -> int:
        with self._lock:
            return len(self.edges)


class SeedGenealogyTree:
    """种子亲缘演化树：追踪父种子→子种子的变异关系

    每个种子有唯一 seed_id，记录其父种子 ID 和诞生的 tick
    支持导出 DOT/Graphviz 格式，可视化 fuzz 种子的进化路径"""

    def __init__(self):
        # RLock: get_statistics 持锁时会再调用 get_ancestry_chain
        self._lock = threading.RLock()
        # seed_id → {parent_id, tick_born, data_hash, crash}
        self._nodes: Dict[str, Dict[str, Any]] = {}
        # parent_id → [child_id,.]
        self._edges: Dict[str, List[str]] = defaultdict(list)
        self._root_ids: List[str] = []  # 无父节点的根种子

    def register_seed(self, seed_id: str, parent_id: Optional[str],
                      tick_born: int, data_hash: str, crash: bool = False) -> None:
        """注册一个种子及其亲缘关系。

        parent_id 为父种子 ID, 根种子为 None; tick_born 为种子
        诞生的 tick 编号。
        """
        with self._lock:
            self._nodes[seed_id] = {
                'parent_id': parent_id,
                'tick_born': tick_born,
                'data_hash': data_hash,
                'crash': crash
            }
            if parent_id is not None:
                self._edges[parent_id].append(seed_id)
            else:
                self._root_ids.append(seed_id)

    def get_children(self, seed_id: str) -> List[str]:
        with self._lock:
            return list(self._edges.get(seed_id, []))

    def get_parent(self, seed_id: str) -> Optional[str]:
        with self._lock:
            node = self._nodes.get(seed_id)
            return node['parent_id'] if node else None

    def get_ancestry_chain(self, seed_id: str) -> List[str]:
        """返回从根到 seed_id 的祖先链"""
        chain = []
        current = seed_id
        with self._lock:
            while current is not None:
                chain.append(current)
                node = self._nodes.get(current)
                current = node['parent_id'] if node else None
        chain.reverse()
        return chain

    def export_dot(self, max_nodes: int = 200) -> str:
        """导出 DOT/Graphviz 格式的演化树, 可直接用 dot/neato 渲染。"""
        lines = ['digraph SeedGenealogy {',
                 '  rankdir=TB;',
                 '  node [shape=ellipse, style=filled, fontsize=10];',
                 '  edge [arrowsize=0.7];']

        with self._lock:
            exported = 0
            for seed_id, node in self._nodes.items():
                if exported >= max_nodes:
                    break
                label = f"{seed_id[:8]}\\nt={node['tick_born']}"
                if node['crash']:
                    color = 'tomato'
                elif node['parent_id'] is None:
                    color = 'lightgreen'
                else:
                    color = 'lightblue'
                lines.append(f'  "{seed_id}" [label="{label}", fillcolor={color}];')
                exported += 1

            for parent_id, children in self._edges.items():
                for child_id in children:
                    if parent_id in self._nodes and child_id in self._nodes:
                        lines.append(f'  "{parent_id}" -> "{child_id}";')

        lines.append('}')
        return '\n'.join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            total_nodes = len(self._nodes)
            total_edges = sum(len(v) for v in self._edges.values())
            crash_nodes = sum(1 for n in self._nodes.values() if n['crash'])
            max_depth = 0
            for seed_id in self._nodes:
                depth = len(self.get_ancestry_chain(seed_id))
                max_depth = max(max_depth, depth)
            return {
                'total_nodes': total_nodes,
                'total_edges': total_edges,
                'root_count': len(self._root_ids),
                'crash_nodes': crash_nodes,
                'max_depth': max_depth
            }


class CoverageFrontierTracker:
    """覆盖前沿识别器：找出已覆盖但其邻接边尚未覆盖的边

    前沿边是 fuzz 最有价值的探索目标——邻接未覆盖区域意味着
    该处附近存在未探索的代码路径。优先发送指向前沿邻接分支的 hint

    邻接定义：边 ID 数值差在 NEIGHBOR_THRESHOLD 以内的视为邻接"""

    NEIGHBOR_THRESHOLD = 256  # 邻接判定阈值（边 ID 数值差）

    def __init__(self):
        self._lock = threading.Lock()
        self._frontier_edges: Set[int] = set()
        self._covered_edges: Set[int] = set()
        # 边 → 邻接边集合的缓存
        self._neighbor_cache: Dict[int, Set[int]] = {}

    def update(self, covered_edges: Set[int]) -> Set[int]:
        """用最新覆盖边集合更新前沿, 返回新识别的前沿边集合。"""
        with self._lock:
            # 清除已不在 covered 中的边缓存
            removed = self._covered_edges - covered_edges
            for edge in removed:
                self._neighbor_cache.pop(edge, None)

            self._covered_edges = covered_edges.copy()
            new_frontier: Set[int] = set()

            for edge in covered_edges:
                neighbors = self._get_neighbors(edge)
                self._neighbor_cache[edge] = neighbors
                # 前沿边：自身已覆盖，但至少一个邻接边未覆盖
                has_uncovered_neighbor = any(n not in covered_edges for n in neighbors)
                if has_uncovered_neighbor:
                    if edge not in self._frontier_edges:
                        new_frontier.add(edge)

            # 移除不再是前沿的边
            no_longer_frontier = self._frontier_edges - covered_edges
            self._frontier_edges = covered_edges.copy()
            # 仅保留真正的前沿边
            self._frontier_edges = {
                e for e in covered_edges
                if any(n not in covered_edges for n in self._get_neighbors(e))
            }

            return new_frontier

    def _get_neighbors(self, edge: int) -> Set[int]:
        """计算某条边的邻接边集合"""
        if edge in self._neighbor_cache:
            return self._neighbor_cache[edge]
        neighbors: Set[int] = set()
        # 上方邻接（较大的边 ID）
        for offset in range(1, 9):
            neighbors.add(edge + offset)
        # 下方邻接（较小的边 ID）
        for offset in range(1, 9):
            if edge >= offset:
                neighbors.add(edge - offset)
        # 跨页邻接（代码段内不同区域的跳转目标可能在 256/512 倍数偏移处）
        for mult in [256, 512]:
            neighbors.add(edge + mult)
            if edge >= mult:
                neighbors.add(edge - mult)
        return neighbors

    def get_frontier_edges(self) -> Set[int]:
        with self._lock:
            return self._frontier_edges.copy()

    def is_frontier(self, edge: int) -> bool:
        with self._lock:
            return edge in self._frontier_edges

    def score_hint_frontier_proximity(self, hint: ConstraintHint) -> float:
        """评估 hint 的 target_path 与前沿边的接近程度

        若 hint 的目标路径接近前沿邻接分支，返回高优先级分数
        """
        try:
            target_path = hint.target_path
            if target_path is None:
                return 0.0
            if isinstance(target_path, (int, float)):
                target_edge = int(target_path)
            elif hasattr(target_path, 'addr'):
                target_edge = int(getattr(target_path, 'addr'))
            else:
                try:
                    target_edge = int(hash(str(target_path)) & 0xFFFF)
                except Exception:
                    return 0.0

            with self._lock:
                neighbors = self._get_neighbors(target_edge)
                frontier_neighbor_count = sum(
                    1 for n in neighbors if n in self._frontier_edges
                )
                uncovered_neighbor_count = sum(
                    1 for n in neighbors if n not in self._covered_edges
                )
                # 邻接前沿且邻接未覆盖 → 最有价值
                total_neighbors = max(1, len(neighbors))
                return (frontier_neighbor_count * 1.5 + uncovered_neighbor_count) / total_neighbors
        except Exception:
            logger.debug("score_hint_frontier_proximity failed", exc_info=True)
            return 0.0

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'covered_edges': len(self._covered_edges),
                'frontier_edges': len(self._frontier_edges),
                'frontier_ratio': len(self._frontier_edges) / max(1, len(self._covered_edges))
            }


class MutualInformationScoring:
    """种子特征与覆盖率增益之间的互信息计算

    对每个种子提取特征向量（熵、长度分桶、特定字节模式）
    计算其与二元覆盖率增益标签之间的互信息 MI(feature; gain)
    MI 高的特征在种子选择中获得更高权重"""

    # 长度分桶边界
    LENGTH_BUCKETS = [16, 64, 256, 1024, 4096, 16384]
    # 关键字节位置（相对位置，0=头部, 0.5=中部, 1.0=尾部）
    KEY_BYTE_POSITIONS = [0.0, 0.25, 0.5, 0.75, 1.0]
    # MI 计算使用的最小样本数
    MIN_SAMPLES_FOR_MI = 20

    def __init__(self):
        # RLock: get_statistics 持锁时会再调用 compute_mi
        self._lock = threading.RLock()
        # 特征名 → {feature_value → {coverage_gain → count}}
        self._joint_counts: Dict[str, Dict[Any, Dict[bool, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int)))
        # feature_value → count (marginal)
        self._feature_marginal: Dict[str, Dict[Any, int]] = defaultdict(lambda: defaultdict(int))
        # coverage_gain → count (marginal)
        self._gain_marginal: Dict[str, Dict[bool, int]] = defaultdict(lambda: defaultdict(int))
        self._total_samples = 0

    def extract_features(self, seed: SeedItem) -> Dict[str, Any]:
        """从种子提取特征向量"""
        data = seed.data
        features: Dict[str, Any] = {}

        # 数据长度
        features['length'] = len(data)

        # 长度分桶
        bucket = 0
        for bound in self.LENGTH_BUCKETS:
            if len(data) <= bound:
                features['length_bucket'] = f"len<={bound}"
                break
            bucket += 1
        if 'length_bucket' not in features:
            features['length_bucket'] = f"len>{self.LENGTH_BUCKETS[-1]}"

        # 熵（字节分布）
        if len(data) > 0:
            byte_counts: Dict[int, int] = defaultdict(int)
            for b in data:
                byte_counts[b] += 1
            total = len(data)
            entropy = -sum(
                (c / total) * math.log2(c / total)
                for c in byte_counts.values() if c > 0
            )
            features['entropy'] = round(entropy, 2)
            # 熵分桶
            if entropy < 2.0:
                features['entropy_bucket'] = 'low'
            elif entropy < 5.0:
                features['entropy_bucket'] = 'mid'
            else:
                features['entropy_bucket'] = 'high'
        else:
            features['entropy'] = 0.0
            features['entropy_bucket'] = 'empty'

        # 关键字节位置模式
        if len(data) > 0:
            features['first_byte'] = data[0]
            features['last_byte'] = data[-1]
            mid_pos = len(data) // 2
            features['mid_byte'] = data[mid_pos]
        else:
            features['first_byte'] = -1
            features['last_byte'] = -1
            features['mid_byte'] = -1

        # 空字节密度
        if len(data) > 0:
            null_count = sum(1 for b in data if b == 0)
            null_ratio = null_count / len(data)
            if null_ratio < 0.1:
                features['null_ratio'] = 'low'
            elif null_ratio < 0.5:
                features['null_ratio'] = 'mid'
            else:
                features['null_ratio'] = 'high'
        else:
            features['null_ratio'] = 'empty'

        return features

    def observe(self, features: Dict[str, Any], coverage_gain: bool) -> None:
        """记录一次观测：种子特征 + 是否产生覆盖率增益"""
        with self._lock:
            self._total_samples += 1
            for fname, fval in features.items():
                if fname in ('first_byte', 'last_byte', 'mid_byte', 'length', 'entropy'):
                    # 连续值特征仅用分桶版本
                    continue
                self._joint_counts[fname][fval][coverage_gain] += 1
                self._feature_marginal[fname][fval] += 1
                self._gain_marginal[fname][coverage_gain] += 1

    def compute_mi(self, feature_name: str) -> float:
        """计算指定特征与覆盖率增益之间的互信息。

        MI(f; g) = sum_{f_val} sum_{g_val} P(f_val, g_val) *
        log(P(f_val, g_val) / (P(f_val) * P(g_val)))
        """
        with self._lock:
            if self._total_samples < self.MIN_SAMPLES_FOR_MI:
                return 0.0

            joint = self._joint_counts.get(feature_name, {})
            f_marg = self._feature_marginal.get(feature_name, {})
            g_marg = self._gain_marginal.get(feature_name, {})

            total = self._total_samples
            if total == 0:
                return 0.0

            mi = 0.0
            for fval, gain_counts in joint.items():
                for gain_flag, joint_n in gain_counts.items():
                    if joint_n == 0:
                        continue
                    p_joint = joint_n / total
                    p_f = f_marg.get(fval, 0) / total
                    p_g = g_marg.get(gain_flag, 0) / total
                    if p_f == 0 or p_g == 0:
                        continue
                    mi += p_joint * math.log2(p_joint / (p_f * p_g))

            return mi

    def get_top_features(self, n: int = 5) -> List[Tuple[str, float]]:
        """返回 MI 得分最高的 N 个特征"""
        scores: List[Tuple[str, float]] = []
        for fname in self._joint_counts:
            mi = self.compute_mi(fname)
            scores.append((fname, mi))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:n]

    def feature_weight(self, feature_name: str, feature_value: Any) -> float:
        """基于 MI 的特征权重：MI 越高、该特征值在正样本中条件概率越高 → 权重越大"""
        mi = self.compute_mi(feature_name)
        if mi == 0:
            return 1.0

        with self._lock:
            joint = self._joint_counts.get(feature_name, {})
            val_counts = joint.get(feature_value, {})
            gain_count = val_counts.get(True, 0)
            total_val = sum(val_counts.values())

            if total_val == 0:
                return 1.0

            p_gain_given_val = gain_count / total_val
            return 1.0 + mi * p_gain_given_val

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            top_features = self.get_top_features(5)
            return {
                'total_samples': self._total_samples,
                'tracked_features': len(self._joint_counts),
                'top_features': [{'name': n, 'mi': round(m, 4)} for n, m in top_features]
            }


class SymbExFuzzCoop:
    """把 symbex 提示与 fuzzer 种子接上消息总线的调度器。

    tick() 运行两侧各一次迭代, 排空消息队列, 更新共享覆盖率视图。

    四轮增强: 集成 SeedGenealogyTree、CoverageFrontierTracker、
    MutualInformationScoring 三大组件。
    """

    # 种子年龄衰减因子：每 tick 乘 0.95
    SEED_AGE_DECAY = 0.95
    # 种子年龄阈值（tick 数），超过此值标记为 stale
    SEED_STALE_AGE = 5

    def __init__(self,
                 symbex_runner=None,
                 fuzzer_runner=None):
        self.bus = MessageBus()
        self.coverage = CoverageTracker()
        self.seeds: deque = deque(maxlen=10000)
        self.hints: deque = deque(maxlen=1000)
        self.stats = CoopStats()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._tick_counter = 0
        self.symbex_runner = symbex_runner
        self.fuzzer_runner = fuzzer_runner
        # 四轮增强组件
        self.genealogy = SeedGenealogyTree()
        self.frontier = CoverageFrontierTracker()
        self.mi_scoring = MutualInformationScoring()
        # 记录上一轮 request_seed 选中的种子 ID，用于建立亲缘关系
        self._last_requested_seed_ids: List[str] = []

    def push_hint(self, hint: ConstraintHint):
        priority = 2 if hint.difficulty > 0.7 else 0
        # 前沿评分加成
        frontier_score = self.frontier.score_hint_frontier_proximity(hint)
        if frontier_score > 0.3:
            priority += 1

        msg = CoopMessage(
            kind=MessageKind.CONSTRAINT_HINT,
            sender=CoopRole.SYMBEX,
            timestamp=time.time(),
            payload={'hint': hint.__dict__},
            priority=priority
        )
        self.bus.send(msg)
        self.hints.append(hint)
        with self._lock:
            self.stats.hints_delivered += 1
            self.stats.symbex_to_fuzzer += 1

    def push_coverage(self, report: CoverageReport):
        msg = CoopMessage(
            kind=MessageKind.COVERAGE_REPORT,
            sender=CoopRole.FUZZER,
            timestamp=time.time(),
            payload={'report': report.__dict__}
        )
        self.bus.send(msg)
        with self._lock:
            new_edges = self._bitmap_to_edges(report.edge_bitmap)
            new = self.coverage.update(new_edges)
            self.stats.new_coverage += new
            self.stats.fuzzer_to_symbex += 1
            self.stats.stagnation_epochs = self.coverage.stagnation_epochs
            # 更新覆盖前沿
            self.frontier.update(self.coverage.edges)

    def push_seed(self, seed: SeedItem):
        seed.tick_born = self._tick_counter
        # 分配唯一种子 ID
        if not seed.seed_id:
            data_hash = hashlib.sha256(seed.data).hexdigest()[:16]
            seed.seed_id = f"s{self._tick_counter}_{data_hash}"

        msg = CoopMessage(
            kind=MessageKind.SEED_DELIVERY,
            sender=CoopRole.FUZZER,
            timestamp=time.time(),
            payload={'seed': {
                'data': seed.data.hex(),
                'coverage_hash': seed.coverage_hash,
                'crash': seed.crash,
                'seed_id': seed.seed_id
            }}
        )
        self.bus.send(msg)
        self.seeds.append(seed)

        # 记录亲缘关系：上一轮选中的种子为本轮新种子的父代
        parent_id = self._last_requested_seed_ids[-1] if self._last_requested_seed_ids else None
        self.genealogy.register_seed(
            seed_id=seed.seed_id,
            parent_id=parent_id,
            tick_born=self._tick_counter,
            data_hash=hashlib.sha256(seed.data).hexdigest()[:16],
            crash=seed.crash
        )

        # MI 特征观测
        features = self.mi_scoring.extract_features(seed)
        with self._lock:
            # 覆盖率增益 = 该种子是否贡献了新覆盖（简化：用 crash 或非空数据）
            has_coverage = seed.crash or (seed.score > 0.3)
            self.mi_scoring.observe(features, has_coverage)

        with self._lock:
            self.stats.seeds_delivered += 1
            self.stats.fuzzer_to_symbex += 1

    def request_seed(self, hint: ConstraintHint) -> List[SeedItem]:
        msg = CoopMessage(
            kind=MessageKind.SEED_REQUEST,
            sender=CoopRole.SYMBEX,
            timestamp=time.time(),
            payload={'hint': hint.__dict__}
        )
        self.bus.send(msg)
        with self._lock:
            seeds_list = list(self.seeds)

        # 获取 MI 权重最高的特征
        top_mi_features = self.mi_scoring.get_top_features(3)
        mi_feature_names = [f[0] for f in top_mi_features]

        scored: List[Tuple[float, SeedItem]] = []
        for s in seeds_list:
            score = self._seed_hint_score(s, hint)
            # 年龄衰减
            age_ticks = self._tick_counter - s.tick_born
            if age_ticks > self.SEED_STALE_AGE:
                score *= (self.SEED_AGE_DECAY ** (age_ticks - self.SEED_STALE_AGE))
            # MI 权重加成
            features = self.mi_scoring.extract_features(s)
            mi_boost = 1.0
            for fname in mi_feature_names:
                if fname in features:
                    mi_boost *= self.mi_scoring.feature_weight(fname, features[fname])
            score *= mi_boost
            scored.append((score, s))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [s for _, s in scored[:10]]
        # 记录本次选中的种子 ID，供下一轮亲缘追踪
        self._last_requested_seed_ids = [s.seed_id for s in selected if s.seed_id]
        return selected

    def triage_seeds(self) -> Dict[str, List[SeedItem]]:
        """三分法: crash / coverage_gain / stale。

        crash → seed.crash 为 True; stale → 年龄 > SEED_STALE_AGE;
        coverage_gain → 其余 (有覆盖率潜力的活跃种子)。
        """
        out: Dict[str, List[SeedItem]] = {'crash': [], 'coverage_gain': [], 'stale': []}
        for s in list(self.seeds):
            if s.crash:
                out['crash'].append(s)
            elif self._tick_counter - s.tick_born > self.SEED_STALE_AGE:
                out['stale'].append(s)
            else:
                out['coverage_gain'].append(s)
        return out

    def _seed_hint_score(self, seed: SeedItem, hint: ConstraintHint) -> float:
        if seed.crash:
            return 1.0
        if len(seed.data) == 0:
            return 0.0
        from collections import Counter
        c = Counter(seed.data)
        total = len(seed.data)
        ent = -sum((n / total) * math.log2(n / total)
                   for n in c.values() if n > 0)
        return min(1.0, ent / 8.0)

    def _bitmap_to_edges(self, bitmap_hex: str) -> Set[int]:
        if not bitmap_hex:
            return set()
        try:
            data = bytes.fromhex(bitmap_hex)
            edges: Set[int] = set()
            for byte_idx, byte_val in enumerate(data):
                for bit in range(8):
                    if byte_val & (1 << bit):
                        edges.add(byte_idx * 8 + bit)
            return edges
        except Exception as e:
            logger.warning(f"Bitmap parse failed: {e}")
            return set()

    def tick(self, symbex_iter: int = 1, fuzz_iter: int = 1):
        self._tick_counter += 1
        if self.symbex_runner:
            try:
                hints = self.symbex_runner(symbex_iter)
                for h in hints:
                    self.push_hint(h)
            except Exception as e:
                logger.warning(f"Symbex failed: {e}")
        if self.fuzzer_runner:
            try:
                new_seeds = self.fuzzer_runner(fuzz_iter)
                for s in new_seeds:
                    self.push_seed(s)
            except Exception as e:
                logger.warning(f"Fuzzer failed: {e}")
        for msg in self.bus.receive(CoopRole.SYMBEX, timeout=0.1):
            self._handle_symbex_msg(msg)
        for msg in self.bus.receive(CoopRole.FUZZER, timeout=0.1):
            self._handle_fuzzer_msg(msg)
        # 每 10 tick 做一次停滞检测
        if self._tick_counter % 10 == 0 and self.coverage.stagnation_epochs >= 3:
            logger.warning("[Coop] Coverage velocity stagnation detected, "
                          f"stagnation_epochs={self.coverage.stagnation_epochs}")

    def _handle_symbex_msg(self, msg: CoopMessage):
        if msg.kind == MessageKind.SEED_DELIVERY:
            sd = msg.payload['seed']
            seed_item = SeedItem(
                data=bytes.fromhex(sd['data']),
                coverage_hash=sd['coverage_hash'],
                crash=sd.get('crash', False),
                source="fuzzer",
                tick_born=self._tick_counter,
                seed_id=sd.get('seed_id', '')
            )
            self.seeds.append(seed_item)

    def _handle_fuzzer_msg(self, msg: CoopMessage):
        if msg.kind == MessageKind.CONSTRAINT_HINT:
            hint_dict = msg.payload.get('hint', {})
            self.hints.append(ConstraintHint(**hint_dict))
        elif msg.kind == MessageKind.SEED_REQUEST:
            pass

    def export_genealogy_dot(self) -> str:
        """导出种子亲缘演化树的 DOT 格式字符串"""
        return self.genealogy.export_dot()

    def get_frontier_hints(self) -> List[int]:
        """返回当前覆盖前沿的边 ID 列表（已排序）"""
        return sorted(self.frontier.get_frontier_edges())

    def get_mi_report(self) -> Dict[str, Any]:
        """返回互信息评分报告"""
        return self.mi_scoring.get_statistics()

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            stats = {
                'symbex_to_fuzzer': self.stats.symbex_to_fuzzer,
                'fuzzer_to_symbex': self.stats.fuzzer_to_symbex,
                'new_coverage': self.stats.new_coverage,
                'seeds_count': len(self.seeds),
                'hints_count': len(self.hints),
                'total_edges': self.coverage.total(),
                'bitmap_hash': self.coverage.bitmap_hash(),
                'stagnation_epochs': self.coverage.stagnation_epochs,
                'tick_counter': self._tick_counter
            }
            stats.update(self.frontier.get_statistics())
            stats['genealogy'] = self.genealogy.get_statistics()
            stats['mi_scoring'] = self.mi_scoring.get_statistics()
            return stats


def run_cooperation(
    rounds: int = 10,
    symbex_iter: int = 1,
    fuzz_iter: int = 1
) -> Dict[str, Any]:
    """一次性流程: 实例化 SymbExFuzzCoop, 运行 N 轮, 返回统计。"""
    coop = SymbExFuzzCoop()
    for r in range(rounds):
        coop.tick(symbex_iter=symbex_iter, fuzz_iter=fuzz_iter)
    return {
        'success': True,
        'rounds': rounds,
        'statistics': coop.get_statistics()
    }
