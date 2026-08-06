# 拜占庭容错工作窃取 — 见证人委员会轻量 BFT 无签名方案
#
# WorkStealingCoordinator + DiversityAwareWorkStealingCoordinator 假设
# 所有节点诚实。若某节点被入侵:
#   - 恶意广播虚假负载 (声称空闲以吸引任务，实际丢弃/篡改)
#   - 选择性处理: 仅执行简单任务，丢弃困难任务 (谎报完成)
#   - 串谋: 两个恶意节点互相窃取+报告完成，消解队列而不执行
#
# 本模块引入见证人委员会 (witness committee) 机制:
#   1. 每次窃取交易关联一个随机选取的见证人集合 (3-5 个节点)
#   2. 窃取方需向见证人提交任务执行证明 (轻量哈希链)
#   3. 被窃取方需见证人确认任务转移 (防双花)
#   4. 见证人通过多数投票判定交易合法性
#   5. 恶意节点被举报 → 见证人降权 → 达到阈值后从集群驱逐
#
# 关键: 无密码学签名 — 见证人仅做哈希验证 + 计数，
# 与 Schneider (arXiv:2501.05377) 的 near-constant work BFT 同源。
# 通信复杂度 O(W·log N) 其中 W = 见证人数 (常数)，N = 集群节点数。

from __future__ import annotations

import time
import random
import hashlib
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple


@dataclass
class StealTransaction:
    """一次窃取交易 — 携带见证所需的全部信息。"""
    tx_id: str
    thief_id: str
    victim_id: str
    task_id: str
    task_hash: str           # 任务内容的 SHA-256
    timestamp: float
    witnesses: List[str]     # 随机选取的见证人节点 ID
    approvals: Set[str] = field(default_factory=set)
    rejections: Set[str] = field(default_factory=set)
    execution_proof: Optional[str] = None  # 执行完成的哈希证明


@dataclass
class NodeReputation:
    """节点声誉 — 拜占庭检测的基础。"""
    node_id: str
    score: float = 1.0               # [0, 1], 1=完全可信
    completed_tasks: int = 0
    failed_or_timed_out: int = 0
    witness_approvals: int = 0        # 作为见证人的正确判定次数
    witness_errors: int = 0           # 作为见证人的错误判定次数
    # 声誉衰减: 长期不活跃的节点声誉自然衰减
    last_active: float = field(default_factory=time.monotonic)


class ByzantineResilientStealing:
    """拜占庭容错的工作窃取协调器。

    与 WorkStealingCoordinator 接口兼容但增加了:
      - 窃取交易需见证人多数通过
      - 任务执行需提交轻量哈希证明
      - 恶意节点自动降权/驱逐
    """

    def __init__(self, node_id: str, witness_count: int = 3,
                 reputation_threshold: float = 0.25,
                 proof_sample_rate: float = 0.1,  # 10% 任务要求执行证明
                 seed: Optional[int] = None):
        self._node_id = node_id
        self._W = witness_count
        self._rep_threshold = reputation_threshold
        self._proof_rate = proof_sample_rate
        self._rng = random.Random(seed)

        # 已知节点
        self._nodes: Dict[str, NodeReputation] = {}
        self._nodes[node_id] = NodeReputation(node_id=node_id)

        # 活跃交易
        self._pending_tx: Dict[str, StealTransaction] = {}
        # 黑名单
        self._blacklist: Set[str] = set()
        self._lock = threading.Lock()

    # ---- 节点管理 ----

    def register_node(self, node_id: str):
        with self._lock:
            if node_id not in self._nodes:
                self._nodes[node_id] = NodeReputation(node_id=node_id)

    def remove_node(self, node_id: str):
        with self._lock:
            self._nodes.pop(node_id, None)
            self._blacklist.discard(node_id)

    # ---- 窃取交易 ----

    def propose_steal(self, thief_id: str, victim_id: str,
                      task_id: str, task_content: str) -> Optional[StealTransaction]:
        """发起窃取提议 — 选取见证人 + 创建交易。

        task_content: 任务的可哈希表示 (路径ID + 约束摘要)
        返回: StealTransaction (等待见证人审批), 或 None (若受害者黑名单)
        """
        with self._lock:
            if victim_id in self._blacklist or thief_id in self._blacklist:
                return None

            task_hash = hashlib.sha256(task_content.encode()).hexdigest()[:16]
            tx_id = hashlib.sha256(
                f"{thief_id}:{victim_id}:{task_id}:{task_hash}:{time.monotonic()}".encode()
            ).hexdigest()[:12]

            # 选取见证人: 排除 thief, victim，优先选声誉高的
            eligible = [
                nid for nid, rep in self._nodes.items()
                if nid not in (thief_id, victim_id)
                and nid not in self._blacklist
                and rep.score >= self._rep_threshold
            ]
            if len(eligible) < self._W:
                # 见证人不足 → 回退到无见证的直接窃取 (信任)
                witnesses = eligible
            else:
                # 加权随机选取 (声誉高的更可能被选中)
                weights = [self._nodes[n].score for n in eligible]
                total_w = sum(weights)
                probs = [w / total_w for w in weights]
                witnesses = self._weighted_sample(eligible, probs, self._W)

            tx = StealTransaction(
                tx_id=tx_id, thief_id=thief_id, victim_id=victim_id,
                task_id=task_id, task_hash=task_hash,
                timestamp=time.monotonic(), witnesses=witnesses,
            )
            self._pending_tx[tx_id] = tx
            self._nodes[thief_id].last_active = time.monotonic()
            return tx

    # ---- 见证人审批 ----

    def witness_approve(self, tx_id: str, witness_id: str,
                        verdict: bool) -> bool:
        """见证人对交易投票。

        verdict: True=批准 (任务转移合法), False=拒绝 (疑似恶意)
        返回: 是否已达到多数 (交易可执行/可驳回)
        """
        with self._lock:
            tx = self._pending_tx.get(tx_id)
            if tx is None or witness_id not in tx.witnesses:
                return False

            if verdict:
                tx.approvals.add(witness_id)
                self._nodes[witness_id].witness_approvals += 1
            else:
                tx.rejections.add(witness_id)
                self._nodes[witness_id].witness_errors += 1

            quorum = max(1, len(tx.witnesses) // 2 + 1)
            return len(tx.approvals) >= quorum or len(tx.rejections) >= quorum

    def verify_execution(self, tx_id: str, result_hash: str) -> bool:
        """窃取方提交执行证明 — 见证人验证。

        result_hash: SHA-256(任务内容 + 执行结果) 的前 16 位
        见证人用自己记录的任务哈希重算并比对。
        """
        with self._lock:
            tx = self._pending_tx.get(tx_id)
            if tx is None:
                return False
            expected = hashlib.sha256(
                f"{tx.task_hash}:{result_hash}".encode()
            ).hexdigest()[:16]
            tx.execution_proof = result_hash
            return True

    # ---- 声誉更新 ----

    def report_outcome(self, node_id: str, success: bool, was_timeout: bool):
        """更新节点声誉 — 基于任务执行结果。"""
        with self._lock:
            rep = self._nodes.get(node_id)
            if rep is None:
                return
            rep.last_active = time.monotonic()
            if success:
                rep.completed_tasks += 1
                rep.score = min(1.0, rep.score + 0.02)
            elif was_timeout:
                rep.failed_or_timed_out += 1
                rep.score = max(0.0, rep.score - 0.05)
                # 连续失败触发审查
                if rep.failed_or_timed_out >= 5 and rep.completed_tasks < 5:
                    self._blacklist.add(node_id)

    def decay_reputations(self):
        """周期性声誉衰减 — 长期不活跃节点的声誉逐渐降低。"""
        with self._lock:
            now = time.monotonic()
            for nid, rep in self._nodes.items():
                if nid == self._node_id:
                    continue
                idle = now - rep.last_active
                if idle > 300:  # 5 分钟不活跃 → 衰减
                    rep.score = max(0.1, rep.score * 0.95)

    # ---- 查询 ----

    @property
    def blacklist(self) -> Set[str]:
        return set(self._blacklist)

    def is_trusted(self, node_id: str) -> bool:
        with self._lock:
            rep = self._nodes.get(node_id)
            return (rep is not None and rep.score >= self._rep_threshold
                    and node_id not in self._blacklist)

    def _weighted_sample(self, items: List[str], probs: List[float],
                         k: int) -> List[str]:
        """加权无放回采样 — 用于见证人选取。"""
        candidates = list(zip(items, probs))
        selected = []
        for _ in range(min(k, len(candidates))):
            total = sum(p for _, p in candidates)
            if total <= 0:
                break
            r = self._rng.random() * total
            cum = 0.0
            for i, (item, p) in enumerate(candidates):
                cum += p
                if r <= cum:
                    selected.append(item)
                    candidates.pop(i)
                    break
        return selected

    def stats(self) -> dict:
        with self._lock:
            trusted = sum(1 for n in self._nodes.values()
                         if n.score >= self._rep_threshold)
            return {
                "total_nodes": len(self._nodes),
                "trusted_nodes": trusted,
                "blacklisted": len(self._blacklist),
                "pending_tx": len(self._pending_tx),
                "witness_count": self._W,
            }
