"""
决策溯源图 (DPG) —— 路由决策的不可变审计链。

PROVEX 为 IDS 告警提供因果溯源, LAMP
提取 LLM 决策边界用于审计。本模块填补的是二者未覆盖的领域:
安全工具路由决策本身的溯源 —— 从原始输入到采集器选择的全链路。

每条路由决策生成一个 ProvenanceNode, 节点间以哈希链连接。
链上记录完整的决策上下文: 输入 → 分类 → 校准 → 路由 → 结果。
通过重放链上的中间状态可验证任意历史决策的正确性。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .intent_route import IntentCategory


def _hash(obj: Any) -> str:
    """确定性哈希, 用于节点链接和完整性校验。"""
    raw = json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


@dataclass
class ProvenanceNode:
    """决策链上的一个节点。"""
    node_id: str                   # 节点唯一标识 (hash)
    parent_hash: str               # 前驱节点哈希, 创世节点为空
    step: str                      # "classify" | "calibrate" | "route" | "outcome"
    timestamp: float
    # 决策数据 (按 step 不同, 部分字段为空)
    input_text: str = ""           # step=classify: 原始请求文本
    intent_category: str = ""      # step=classify/calibrate: 分类结果
    raw_confidence: float = 0.0    # step=classify: 原始置信度
    calibrated_prob: float = 0.0   # step=calibrate: 校准后概率
    deferral_decision: str = ""    # step=calibrate: route/defer/escalate
    routed_action_ids: List[str] = field(default_factory=list)  # step=route
    routed_target: str = ""        # step=route
    collector_useful: Optional[bool] = None  # step=outcome
    collector_quality: float = 0.0           # step=outcome
    latency_ms: float = 0.0                  # step=outcome
    # 元数据
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass
class ProvenanceChain:
    """一条完整的决策溯源链。"""
    chain_id: str
    nodes: List[ProvenanceNode]
    root_input: str
    final_outcome: str  # 简短描述
    verified: bool = False
    tampered: bool = False


class DecisionProvenanceEngine:
    """
    决策溯源引擎。

    三阶段:
    1. 决策时: 创建节点并追加到活跃链
    2. 结果返回时: 在链上记录采集结果 (闭合反馈环)
    3. 审计时: 重放链上哈希验证完整性, 检测篡改

    哈希链结构:
    node_0.hash = H(input + step + timestamp)
    node_n.hash = H(node_{n-1}.hash + payload_n)
    任意节点的篡改会导致后续所有哈希不匹配。
    """

    def __init__(self, max_chain_length: int = 50):
        self._active_chains: Dict[str, List[ProvenanceNode]] = {}
        self._completed_chains: List[ProvenanceChain] = []
        self._max_length = max_chain_length

    def open_chain(self, input_text: str) -> str:
        """开启新溯源链, 返回 chain_id。"""
        chain_id = _hash(input_text + str(time.time()))
        genesis = ProvenanceNode(
            node_id="",
            parent_hash="",
            step="classify",
            timestamp=time.time(),
            input_text=input_text[:500],
        )
        genesis.node_id = _hash({
            "parent": "", "step": "classify",
            "ts": genesis.timestamp, "input": genesis.input_text,
        })
        self._active_chains[chain_id] = [genesis]
        self._trim()
        return chain_id

    def record_classify(
        self, chain_id: str, category: IntentCategory,
        confidence: float, used_llm: bool,
    ) -> Optional[str]:
        """记录分类步骤。更新创世节点的分类字段。"""
        nodes = self._active_chains.get(chain_id)
        if not nodes:
            return None
        node = nodes[0]
        node.intent_category = category.value
        node.raw_confidence = confidence
        node.extra["used_llm"] = str(used_llm)
        # 重新哈希以包含分类数据
        node.node_id = _hash({
            "parent": "", "step": "classify", "ts": node.timestamp,
            "input": node.input_text, "category": node.intent_category,
            "confidence": node.raw_confidence,
        })
        return node.node_id

    def append_calibrate(
        self, chain_id: str, calibrated_prob: float, deferral: str,
    ) -> Optional[str]:
        """追加校准节点。"""
        return self._append(chain_id, "calibrate", {
            "calibrated_prob": calibrated_prob,
            "deferral_decision": deferral,
        })

    def append_route(
        self, chain_id: str, action_ids: List[str], target: str,
    ) -> Optional[str]:
        """追加路由决策节点。"""
        return self._append(chain_id, "route", {
            "routed_action_ids": action_ids,
            "routed_target": target,
        })

    def append_outcome(
        self, chain_id: str, useful: bool, quality: float, latency_ms: float,
    ) -> Optional[str]:
        """追加采集结果节点, 并自动闭合链。"""
        node_id = self._append(chain_id, "outcome", {
            "collector_useful": useful, "collector_quality": quality,
            "latency_ms": latency_ms,
        })
        if node_id:
            self._finalize_chain(chain_id)
        return node_id

    def _append(self, chain_id: str, step: str, fields: Dict[str, Any]) -> Optional[str]:
        nodes = self._active_chains.get(chain_id)
        if not nodes:
            return None
        parent_hash = nodes[-1].node_id
        ts = time.time()
        payload = {"parent": parent_hash, "step": step, "ts": ts, **fields}
        node = ProvenanceNode(
            node_id="", parent_hash=parent_hash, step=step, timestamp=ts,
        )
        for k, v in fields.items():
            if hasattr(node, k):
                setattr(node, k, v)
        node.node_id = _hash(payload)
        nodes.append(node)
        return node.node_id

    def _finalize_chain(self, chain_id: str) -> None:
        """闭合链: 验证完整性后移入已完成列表。"""
        nodes = self._active_chains.pop(chain_id, [])
        if len(nodes) < 2:
            return
        root = nodes[0]
        chain = ProvenanceChain(
            chain_id=chain_id,
            nodes=list(nodes),
            root_input=root.input_text,
            final_outcome=self._summarize(nodes),
            verified=self.verify_chain(nodes),
        )
        self._completed_chains.append(chain)
        # 限制已完成链数量
        if len(self._completed_chains) > self._max_length:
            self._completed_chains = self._completed_chains[-self._max_length:]

    def _summarize(self, nodes: List[ProvenanceNode]) -> str:
        parts: List[str] = []
        for n in nodes:
            if n.step == "classify" and n.intent_category:
                parts.append(f"分类={n.intent_category}")
            elif n.step == "route" and n.routed_action_ids:
                parts.append(f"路由={','.join(n.routed_action_ids[:3])}")
            elif n.step == "outcome":
                parts.append("有用" if n.collector_useful else "无用")
        return " → ".join(parts) if parts else "空链"

    @staticmethod
    def verify_chain(nodes: List[ProvenanceNode]) -> bool:
        """重放哈希链验证完整性。任意节点哈希不匹配返回 False。"""
        for i, node in enumerate(nodes):
            if i == 0:
                expected = _hash({
                    "parent": "", "step": "classify", "ts": node.timestamp,
                    "input": node.input_text, "category": node.intent_category,
                    "confidence": node.raw_confidence,
                })
            else:
                payload = {"parent": nodes[i - 1].node_id, "step": node.step,
                           "ts": node.timestamp}
                if node.step == "calibrate":
                    payload["calibrated_prob"] = node.calibrated_prob
                    payload["deferral_decision"] = node.deferral_decision
                elif node.step == "route":
                    payload["routed_action_ids"] = node.routed_action_ids
                    payload["routed_target"] = node.routed_target
                elif node.step == "outcome":
                    payload["collector_useful"] = node.collector_useful
                    payload["collector_quality"] = node.collector_quality
                    payload["latency_ms"] = node.latency_ms
                expected = _hash(payload)
            if node.node_id != expected:
                return False
        return True

    def get_chain(self, chain_id: str) -> Optional[ProvenanceChain]:
        """按 ID 查询已完成链。"""
        for c in self._completed_chains:
            if c.chain_id == chain_id:
                return c
        return None

    def recent_chains(self, n: int = 10) -> List[ProvenanceChain]:
        return self._completed_chains[-n:]

    def _trim(self) -> None:
        if len(self._active_chains) > self._max_length:
            oldest = sorted(self._active_chains.keys())[:len(self._active_chains) - self._max_length]
            for k in oldest:
                del self._active_chains[k]

    @property
    def chain_count(self) -> int:
        return len(self._completed_chains) + len(self._active_chains)


__all__ = [
    "ProvenanceNode",
    "ProvenanceChain",
    "DecisionProvenanceEngine",
]
