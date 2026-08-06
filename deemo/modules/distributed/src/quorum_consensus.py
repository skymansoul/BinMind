"""
法定人数共识 — 分布式分析节点的 BFT 风格结果聚合。

分布式二进制分析中, 多个节点独立分析同一目标——由于不同的
反编译器版本/求解器配置/架构推断, 结果可能冲突。例如:
  节点A: "函数 f 有 3 个参数 (int, char*, size_t)"
  节点B: "函数 f 有 4 个参数 (int, char*, size_t, int)"
  节点C: "函数 f 有 3 个参数 (int, void*, size_t)"

本模块通过法定人数 (quorum) 共识解决冲突——不要求所有节点一致,
仅要求 ≥2f+1 个节点在 N=3f+1 的网络中就结果达成一致。

共识算法:
  1. 证据收集: 每个节点提交结果 + 证据强度 (置信度分数)
  2. 冲突检测: 按分析维度 (函数签名/类型/漏洞) 分组, 检测分歧
  3. 加权法定人数: 每个节点按历史准确率加权, 加权多数 ≥ 2/3 → 共识达成
  4. 冲突分解: 无法达成共识的维度标记为 "disputed" 并保留所有版本

为什么选择加权法定人数而非简单多数:
  分析节点的质量不均匀——反编译器 A 的置信度 0.95 vs 反编译器 B 的 0.6。
  简单多数会忽略质量差异。加权法定人数让更可靠的节点有更大投票权。

为什么 BFT 风格的 ≥2f+1 而非 Paxos/Raft:
  分析节点可能产生任意错误 (Byzantine)——不是简单的 crash fault。
  例如损坏的二进制导致某节点输出完全错误的类型推断。
  BFT 法定人数容忍 f 个任意错误节点 (N ≥ 3f+1)。

ref: PBFT (Castro & Liskov, OSDI 1999) — practical Byzantine fault tolerance,
     本项目取其法定人数阈值但简化复制状态机为分析结果聚合
ref: Ensemble methods in ML — weighted majority voting,
     本项目的加权方案借鉴 Bagging/Boosting 的概率融合
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Any, Optional


@dataclass
class NodeResult:
    """单个分析节点的分析结果。"""
    node_id: str
    dimension: str       # 'function_signature' | 'type_inference' | 'vuln_detection'
    target_id: str       # 目标标识 (函数名/CVE id)
    value: Any           # 分析结果 (任意类型)
    confidence: float = 0.5
    node_weight: float = 1.0  # 节点权重 (基于历史准确率)


@dataclass
class ConsensusResult:
    """法定人数共识的结果——达成共识 or 冲突保留。"""
    dimension: str
    target_id: str
    consensus_reached: bool
    agreed_value: Any = None
    confidence: float = 0.0
    supporting_nodes: int = 0
    dissenting_nodes: list[str] = field(default_factory=list)
    all_versions: list[Any] = field(default_factory=list)
    status: str = ''  # 'consensus' | 'disputed' | 'insufficient_nodes'


# --- 加权法定人数 ---

def weighted_quorum_vote(results: list[NodeResult],
                         quorum_threshold: float = 2.0 / 3.0) -> ConsensusResult:
    """对一组分析结果执行加权法定人数投票。

    每个节点的投票权重 = node_weight × confidence。
    总权重 > quorum_threshold → 共识达成。"""
    if not results:
        return ConsensusResult(
            dimension='', target_id='',
            consensus_reached=False, status='insufficient_nodes')

    dim = results[0].dimension
    tid = results[0].target_id
    total_weight = sum(r.node_weight * r.confidence for r in results)

    if total_weight < 1.0:
        return ConsensusResult(
            dimension=dim, target_id=tid,
            consensus_reached=False, status='insufficient_nodes')

    # 按值分组——聚合相同的分析结论
    value_groups: dict[str, list[NodeResult]] = defaultdict(list)
    for r in results:
        key = _value_to_key(r.value)
        value_groups[key].append(r)

    # 计算每组的总权重
    group_weights = {}
    for key, group in value_groups.items():
        group_weights[key] = sum(r.node_weight * r.confidence for r in group)

    # 找最大权重组
    best_key = max(group_weights, key=group_weights.get)
    best_weight = group_weights[best_key]
    best_group = value_groups[best_key]

    consensus = best_weight / total_weight >= quorum_threshold
    dissenting = [r.node_id for r in results
                  if _value_to_key(r.value) != best_key]

    return ConsensusResult(
        dimension=dim, target_id=tid,
        consensus_reached=consensus,
        agreed_value=best_group[0].value if consensus else None,
        confidence=round(best_weight / total_weight, 3),
        supporting_nodes=len(best_group),
        dissenting_nodes=dissenting if consensus else [],
        all_versions=[r.value for r in results],
        status='consensus' if consensus else 'disputed',
    )


def _value_to_key(value: Any) -> str:
    """将分析结果序列化为可比较的字符串 key。"""
    if isinstance(value, dict):
        return str(sorted(value.items()))
    if isinstance(value, (list, tuple)):
        return str(list(value))
    return str(value)


# --- 节点权重管理 ---

class NodeWeightTracker:
    """追踪每个分析节点的历史准确率——用于加权投票。"""

    __slots__ = ('_weights', '_history')

    def __init__(self):
        self._weights: dict[str, float] = defaultdict(lambda: 1.0)
        self._history: dict[str, list[bool]] = defaultdict(list)

    def record_outcome(self, node_id: str, correct: bool) -> None:
        """记录一次分析结果是否正确 (由 ground truth 或更高权威验证)。"""
        self._history[node_id].append(correct)
        # EMA 更新权重
        alpha = 0.1
        reward = 1.0 if correct else 0.0
        self._weights[node_id] = (
            (1 - alpha) * self._weights[node_id] + alpha * reward)

    def get_weight(self, node_id: str) -> float:
        return max(0.1, self._weights.get(node_id, 1.0))

    def stats(self) -> dict:
        return {
            nid: {
                'weight': round(w, 3),
                'accuracy': round(
                    sum(self._history[nid]) / max(1, len(self._history[nid])), 3
                ) if self._history[nid] else 0.0,
                'n_trials': len(self._history[nid]),
            }
            for nid, w in self._weights.items()
        }


# --- 冲突分解器 ---

class QuorumConsensusEngine:
    """完整法定人数共识引擎——收集结果→加权投票→冲突分解。"""

    __slots__ = ('_weight_tracker', '_pending_results', '_consensus_log')

    def __init__(self):
        self._weight_tracker = NodeWeightTracker()
        self._pending_results: dict[tuple[str, str], list[NodeResult]] = defaultdict(list)
        self._consensus_log: list[ConsensusResult] = []

    def submit(self, node_id: str, dimension: str, target_id: str,
               value: Any, confidence: float = 0.5) -> None:
        weight = self._weight_tracker.get_weight(node_id)
        self._pending_results[(dimension, target_id)].append(NodeResult(
            node_id=node_id, dimension=dimension, target_id=target_id,
            value=value, confidence=confidence, node_weight=weight,
        ))

    def resolve(self, dimension: str, target_id: str) -> ConsensusResult:
        """对指定维度的挂起结果执行共识决议。"""
        key = (dimension, target_id)
        results = self._pending_results.get(key, [])
        consensus = weighted_quorum_vote(results)

        # 记录对 ground truth 一致的节点为 "正确"
        if consensus.consensus_reached:
            for r in results:
                self._weight_tracker.record_outcome(
                    r.node_id, _value_to_key(r.value) == _value_to_key(consensus.agreed_value))

        self._consensus_log.append(consensus)
        del self._pending_results[key]
        return consensus

    def resolve_all(self) -> list[ConsensusResult]:
        keys = list(self._pending_results.keys())
        result = []
        for dim, tid in keys:
            result.append(self.resolve(dim, tid))
        return result

    def stats(self) -> dict:
        resolved = len(self._consensus_log)
        disputed = sum(1 for c in self._consensus_log if c.status == 'disputed')
        return {
            'total_resolved': resolved,
            'consensus_rate': round((resolved - disputed) / max(1, resolved), 3),
            'nodes': self._weight_tracker.stats(),
        }


__all__ = [
    'QuorumConsensusEngine', 'NodeResult', 'ConsensusResult',
    'NodeWeightTracker', 'weighted_quorum_vote',
]
