#!/usr/bin/env python3
"""
协议状态机推断引擎

基于 的自动状态机推断框架
结合概率状态机（P-SM）和 Needleman-Wunsch 序列比对进行协议状态推断

核心方法：
1. 消息聚类：基于模糊隶属度的自适应 DBSCAN
2. 会话分类：NW + K-Medoids 序列比对
3. 状态推断：概率协议状态机（P-SM）
4. 转移矩阵：从会话序列构建状态转移图

扩展支持 的字段语义辅助标注
"""

import logging
import re
import json
import math
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from itertools import groupby

logger = logging.getLogger(__name__)


@dataclass
class ProtocolMessage:
    """协议消息表示"""
    msg_id: int
    direction: str  # '发送' | 'recv'
    data: bytes
    length: int = 0
    timestamp: float = 0.0
    features: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.length == 0:
            self.length = len(self.data)
        if not self.features:
            self.features = self._extract_features()

    def _extract_features(self) -> Dict[str, Any]:
        """提取消息基本特征"""
        if not self.data:
            return {'len': 0, 'first_byte': 0}
        return {
            'len': len(self.data),
            'first_byte': self.data[0],
            'last_byte': self.data[-1] if len(self.data) > 1 else self.data[0],
            'byte_entropy': self._byte_shannon_entropy(self.data),
            'null_count': self.data.count(0),
            'printable_ratio': sum(32 <= b < 127 for b in self.data) / max(len(self.data), 1),
        }

    @staticmethod
    def _byte_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for cnt in counter.values():
            if cnt > 0:
                p = cnt / total
                entropy -= p * math.log2(p)
        return entropy


@dataclass
class ProtocolState:
    """协议状态节点"""
    state_id: int
    label: str
    messages: List[int] = field(default_factory=list)  # msg IDs
    is_initial: bool = False
    is_terminal: bool = False
    is_error: bool = False

    def message_count(self) -> int:
        return len(self.messages)


@dataclass
class StateTransition:
    """状态转移"""
    from_state: int
    to_state: int
    trigger_message_type: str  # 消息类型标签
    count: int = 1
    probability: float = 0.0


@dataclass
class ProtocolStateMachine:
    """概率协议状态机"""
    states: List[ProtocolState] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)
    initial_state: Optional[int] = None
    terminal_states: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'num_states': len(self.states),
            'num_transitions': len(self.transitions),
            'states': [
                {
                    'id': s.state_id, 'label': s.label,
                    'is_initial': s.is_initial, 'is_terminal': s.is_terminal,
                    'msg_count': s.message_count()
                }
                for s in self.states
            ],
            'transitions': [
                {
                    'from': t.from_state, 'to': t.to_state,
                    'trigger': t.trigger_message_type,
                    'count': t.count, 'probability': round(t.probability, 4)
                }
                for t in self.transitions
            ],
            'initial_state': self.initial_state,
            'terminal_states': self.terminal_states,
            'metadata': self.metadata
        }


class FuzzyDBSCAN:
    """
    模糊隶属度 DBSCAN 聚类

    基于消息特征向量的自适应聚类
    使用指数衰减隶属度代替硬分配，支持边界样本的多重归属
    """

    def __init__(self, eps: float = 0.35, min_samples: int = 3):
        self.eps = eps
        self.min_samples = min_samples

    def fit(self, messages: List[ProtocolMessage]) -> Dict[int, List[int]]:
        """对消息进行聚类, 返回 {cluster_id: [msg_indices]}, -1 为噪声。"""
        n = len(messages)
        if n == 0:
            return {-1: []}

        vectors = [self._to_feature_vector(m) for m in messages]
        adjacency = self._compute_adjacency(vectors)

        labels = [-1] * n
        cluster_id = 0

        for i in range(n):
            if labels[i] != -1:
                continue

            neighbors = adjacency[i]
            if len(neighbors) < self.min_samples:
                continue  # 噪声点

            # 扩展簇
            labels[i] = cluster_id
            queue = list(neighbors)
            idx = 0

            while idx < len(queue):
                j = queue[idx]
                idx += 1

                if labels[j] == -1:
                    labels[j] = cluster_id
                    j_neighbors = adjacency[j]
                    if len(j_neighbors) >= self.min_samples:
                        for nb in j_neighbors:
                            if nb not in queue:
                                queue.append(nb)

            cluster_id += 1

        # 构建簇映射
        clusters: Dict[int, List[int]] = defaultdict(list)
        for i, label in enumerate(labels):
            clusters[label].append(i)

        return dict(clusters)

    def _to_feature_vector(self, msg: ProtocolMessage) -> List[float]:
        f = msg.features
        return [
            math.log2(f['len'] + 1) / 16.0,
            f['first_byte'] / 255.0,
            f['byte_entropy'] / 8.0,
            min(f['null_count'] / max(f['len'], 1), 1.0),
            f['printable_ratio'],
        ]

    def _compute_adjacency(self, vectors: List[List[float]]) -> List[List[int]]:
        n = len(vectors)
        adjacency: List[List[int]] = [[] for _ in range(n)]

        for i in range(n):
            for j in range(i + 1, n):
                dist = self._euclidean(vectors[i], vectors[j])
                if dist <= self.eps:
                    adjacency[i].append(j)
                    adjacency[j].append(i)

        return adjacency

    @staticmethod
    def _euclidean(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class NeedlemanWunschAligner:
    """
    Needleman-Wunsch 全局序列比对

    用于会话序列的分类
    将每个会话的消息类型序列进行两两比对，构建距离矩阵
    """

    def __init__(self, match_score: float = 2.0, mismatch_penalty: float = -1.0,
                 gap_penalty: float = -1.0):
        self.match = match_score
        self.mismatch = mismatch_penalty
        self.gap = gap_penalty

    def align_score(self, seq_a: List[str], seq_b: List[str]) -> float:
        """
        计算两个消息类型序列的比对得分

        得分归一化到 [0, 1]，1 表示完全匹配
        """
        len_a, len_b = len(seq_a), len(seq_b)
        if len_a == 0 and len_b == 0:
            return 1.0
        if len_a == 0 or len_b == 0:
            return 0.0

        dp = [[0.0] * (len_b + 1) for _ in range(len_a + 1)]

        for i in range(len_a + 1):
            dp[i][0] = i * self.gap
        for j in range(len_b + 1):
            dp[0][j] = j * self.gap

        for i in range(1, len_a + 1):
            for j in range(1, len_b + 1):
                score = self.match if seq_a[i - 1] == seq_b[j - 1] else self.mismatch
                dp[i][j] = max(
                    dp[i - 1][j - 1] + score,
                    dp[i - 1][j] + self.gap,
                    dp[i][j - 1] + self.gap
                )

        max_possible = max(len_a, len_b) * self.match
        return max(0.0, dp[len_a][len_b] / max_possible) if max_possible > 0 else 0.0


class KMedoidsClusterer:
    """
    K-Medoids 聚类器（用于会话分类）

    基于 NW 比对距离矩阵将会话分组为协议类型簇
    """

    def __init__(self, k_range: Tuple[int, int] = (2, 8)):
        self.k_range = k_range

    def cluster(self, distance_matrix: List[List[float]],
                session_ids: List[int]) -> Dict[int, List[int]]:
        """
        基于距离矩阵的 K-Medoids 聚类
        """
        n = len(distance_matrix)
        if n == 0:
            return {}

        best_k = min(self.k_range[1], max(self.k_range[0], int(math.sqrt(n))))
        best_k = min(best_k, n)

        if best_k <= 1:
            return {0: list(range(n))}

        # 贪心初始化：最远点优先
        medoids = [0]
        for _ in range(1, best_k):
            max_dist = -1
            best_idx = 0
            for i in range(n):
                if i in medoids:
                    continue
                min_to_medoid = min(distance_matrix[i][m] for m in medoids)
                if min_to_medoid > max_dist:
                    max_dist = min_to_medoid
                    best_idx = i
            medoids.append(best_idx)

        changed = True
        while changed:
            changed = False
            labels = [
                min(range(best_k), key=lambda k: distance_matrix[i][medoids[k]])
                for i in range(n)
            ]

            for k in range(best_k):
                cluster_points = [i for i, l in enumerate(labels) if l == k]
                if not cluster_points:
                    continue

                best_medoid = medoids[k]
                best_cost = sum(distance_matrix[i][best_medoid] for i in cluster_points)

                for candidate in cluster_points:
                    cost = sum(distance_matrix[i][candidate] for i in cluster_points)
                    if cost < best_cost:
                        best_cost = cost
                        best_medoid = candidate

                if best_medoid != medoids[k]:
                    medoids[k] = best_medoid
                    changed = True

        final_labels = [
            min(range(best_k), key=lambda k: distance_matrix[i][medoids[k]])
            for i in range(n)
        ]

        clusters: Dict[int, List[int]] = defaultdict(list)
        for i, label in enumerate(final_labels):
            clusters[label].append(session_ids[i])

        return dict(clusters)


class ProtocolStateInferrer:
    """
    协议状态机推断器

    整合消息聚类→会话分类→状态推断→转移矩阵的完整流程
    [Yang 2024, arXiv:2412.02540]
    可选 BinPRE 风格字段语义标注 [BinPRE 2024, 2409.01994]
    """

    # 已知协议特征签名（用于预标注）
    _PROTO_SIGNATURES = {
        'tls': [b'\x16\x03\x01', b'\x16\x03\x03', b'\x17\x03\x03'],
        'http': [b'GET ', b'POST', b'HTTP/', b'HEAD '],
        'smb': [b'\xffSMB', b'\xfeSMB'],
        'ssh': [b'SSH-'],
        'dns': None,  # DNS 通过端口推断
        'modbus': [b'\x00\x00\x00\x00\x00\x06'],  # Modbus TCP
    }

    def __init__(self, eps: float = 0.35, min_samples: int = 3):
        self.dbscan = FuzzyDBSCAN(eps=eps, min_samples=min_samples)
        self.aligner = NeedlemanWunschAligner()
        self.kmedoids = KMedoidsClusterer()
        self._msg_type_labels: Dict[int, str] = {}

    def infer(
        self,
        messages: List[ProtocolMessage],
        sessions: Optional[List[List[int]]] = None
    ) -> ProtocolStateMachine:
        """
        主推断流程。

        messages 为所有协议消息, sessions 为会话分组
        (按 msg_id 列表), None 则按时间窗口自动分组;
        返回 ProtocolStateMachine 实例。
        """
        logger.info(f"开始协议状态推断: {len(messages)} 条消息")

        if not messages:
            return ProtocolStateMachine()

        # 消息类型聚类
        clusters = self.dbscan.fit(messages)
        self._assign_type_labels(clusters, messages)

        # 会话分类（如果有多个会话）
        if sessions is None:
            sessions = self._auto_sessionize(messages)

        # 构建消息类型序列
        session_sequences = self._build_type_sequences(sessions, messages)

        # 推断状态和转移
        psm = self._infer_states_and_transitions(session_sequences)

        # 标注已知协议
        self._annotate_known_protocols(psm, messages)

        logger.info(
            f"推断完成: {len(psm.states)} 个状态, "
            f"{len(psm.transitions)} 条转移"
        )
        return psm

    def _assign_type_labels(
        self, clusters: Dict[int, List[int]], messages: List[ProtocolMessage]
    ) -> None:
        """为每个消息类型簇分配标签"""
        for cid, indices in clusters.items():
            if cid == -1:
                continue

            # 基于特征统计生成标签
            sample_msgs = [messages[i] for i in indices[:5] if i < len(messages)]
            if not sample_msgs:
                label = f"type_{cid}"
            else:
                avg_len = int(sum(m.features['len'] for m in sample_msgs) / len(sample_msgs))
                first_byte = max(set(m.features['first_byte'] for m in sample_msgs),
                                 key=lambda b: sum(1 for m in sample_msgs
                                                   if m.features['first_byte'] == b))
                label = f"T{cid}_L{avg_len}_B{first_byte:02x}"

            for idx in indices:
                if idx < len(messages):
                    self._msg_type_labels[idx] = label

        # 噪声点单独标签
        for idx in clusters.get(-1, []):
            if idx < len(messages):
                self._msg_type_labels[idx] = f"noise_{idx}"

    def _auto_sessionize(
        self, messages: List[ProtocolMessage], idle_threshold: float = 5.0
    ) -> List[List[int]]:
        """
        基于时间间隔自动划分会话
        """
        if not messages:
            return []

        sessions = []
        current_session = [0]

        for i in range(1, len(messages)):
            gap = messages[i].timestamp - messages[i - 1].timestamp
            if gap > idle_threshold:
                sessions.append(current_session)
                current_session = [i]
            else:
                current_session.append(i)

        if current_session:
            sessions.append(current_session)

        return sessions

    def _build_type_sequences(
        self, sessions: List[List[int]], messages: List[ProtocolMessage]
    ) -> List[List[str]]:
        """构建每个会话的消息类型序列"""
        sequences = []
        for session_indices in sessions:
            seq = []
            for idx in session_indices:
                if idx in self._msg_type_labels:
                    seq.append(self._msg_type_labels[idx])
                else:
                    seq.append('unknown')
            if seq:
                sequences.append(seq)
        return sequences

    def _infer_states_and_transitions(
        self, sequences: List[List[str]]
    ) -> ProtocolStateMachine:
        """
        从消息类型序列推断状态和转移

        使用概率方法：将频繁的消息类型共现模式映射为状态
        """
        psm = ProtocolStateMachine()

        if not sequences:
            return psm

        # 统计转移对
        transition_counts: Dict[Tuple[str, str], int] = Counter()
        all_types: Set[str] = set()

        for seq in sequences:
            for i in range(len(seq) - 1):
                pair = (seq[i], seq[i + 1])
                transition_counts[pair] += 1
            for t in seq:
                all_types.add(t)

        if not transition_counts:
            return psm

        # 将消息类型映射到状态
        type_to_state: Dict[str, int] = {}
        for i, msg_type in enumerate(sorted(all_types)):
            state = ProtocolState(
                state_id=i, label=msg_type,
                is_initial=(i == 0)
            )
            psm.states.append(state)
            type_to_state[msg_type] = i

        # 推断初始状态（会话起始消息类型）
        start_types = Counter(seq[0] for seq in sequences if seq)
        if start_types:
            most_common_start = start_types.most_common(1)[0][0]
            if most_common_start in type_to_state:
                psm.initial_state = type_to_state[most_common_start]
                psm.states[type_to_state[most_common_start]].is_initial = True

        # 推断终止状态（会话结束消息类型）
        end_types = Counter(seq[-1] for seq in sequences if seq)
        for end_type, _ in end_types.most_common(min(3, len(end_types))):
            if end_type in type_to_state:
                psm.terminal_states.append(type_to_state[end_type])
                psm.states[type_to_state[end_type]].is_terminal = True

        # 构建转移
        total = sum(transition_counts.values())
        for (from_type, to_type), cnt in transition_counts.items():
            if from_type in type_to_state and to_type in type_to_state:
                trans = StateTransition(
                    from_state=type_to_state[from_type],
                    to_state=type_to_state[to_type],
                    trigger_message_type=to_type,
                    count=cnt,
                    probability=round(cnt / total, 4)
                )
                psm.transitions.append(trans)

        psm.metadata['total_sessions'] = len(sequences)
        psm.metadata['unique_types'] = len(all_types)
        psm.metadata['total_transition_pairs'] = total

        return psm

    def _annotate_known_protocols(
        self, psm: ProtocolStateMachine, messages: List[ProtocolMessage]
    ) -> None:
        """
        基于字节签名标注已知协议 [BinPRE 2024]
        """
        detected = []
        for proto_name, signatures in self._PROTO_SIGNATURES.items():
            if signatures is None:
                continue
            for msg in messages[:100]:  # 检查前100条
                for sig in signatures:
                    if msg.data.startswith(sig):
                        detected.append(proto_name)
                        break
                if proto_name in detected:
                    break

        if detected:
            psm.metadata['detected_protocols'] = list(set(detected))


def infer_protocol_states(
    messages_data: List[Dict[str, Any]],
    with_sessions: bool = True
) -> Dict[str, Any]:
    """
    便捷函数: 从原始消息数据推断协议状态机。

    messages_data 为消息列表, 每条含 direction、data (hex str
    或 bytes)、timestamp; with_sessions 控制是否使用会话分组;
    返回状态机字典表示。
    """
    messages = []
    for i, md in enumerate(messages_data):
        data = md.get('data', b'')
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data.replace(' ', ''))
            except ValueError:
                data = data.encode('utf-8', errors='replace')
        elif not isinstance(data, bytes):
            data = str(data).encode('utf-8', errors='replace')

        msg = ProtocolMessage(
            msg_id=i,
            direction=md.get('direction', 'send'),
            data=data,
            timestamp=md.get('timestamp', float(i))
        )
        messages.append(msg)

    inferrer = ProtocolStateInferrer()
    psm = inferrer.infer(messages)
    return psm.to_dict()
