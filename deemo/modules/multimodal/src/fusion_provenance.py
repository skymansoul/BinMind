# 修改记录:
# 2025-07-18 08:45 - 加入 Merkle 树哈希以支持增量验证
# 2025-07-22 14:31 - 引入因果边标记（causal_edge）区分相关性与因果性

"""融合溯源追踪 — 记录每次融合决策的完整证据链。

在安全分析场景中，"为何判定为漏洞"比"判定结果"本身更关键。
本模块为每次多模态融合决策建立不可篡改的溯源链：
- 哪个模态贡献了哪些维度的信息
- 融合权重为何如此分配
- 最终分数可回溯至原始分析证据

设计原则：
- 每条溯源记录以 Merkle 树叶子节点存储，支持增量哈希验证，
  防止融合链被篡改后无法察觉。
- 区分相关性边（A 出现在 B 附近）和因果边（A 直接导致 B），
  后者权重更高且不可被门控衰减。

ref: W3C PROV-DM (Provenance Data Model)，在此基础上增加
     安全分析特有的因果标记机制。
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ProvenanceEdge:
    """溯源图中的证据边。

    causal=True: 表示因果关系（如 taint source → sink），
    不可被后续融合降权。
    causal=False: 相关性边，融合时可被门控调节。
    """
    source: str           # 证据来源模块
    target: str           # 结论/下游模块
    evidence_hash: str    # 证据内容的 SHA256
    weight: float         # 该边在融合中的贡献权重
    causal: bool = False  # True=因果边, False=相关性边
    timestamp: float = field(default_factory=time.time)


@dataclass
class FusionRecord:
    """单次融合操作的完整记录。

    trace_id 用于追溯整条分析链路——从原始二进制到最终漏洞判定。
    modal_weights 记录每个模态在此次融合中的影响力。
    edges 是此次融合引入的证据边。
    """
    trace_id: str
    modal_weights: Dict[str, float]
    edges: List[ProvenanceEdge] = field(default_factory=list)
    pre_state_hash: str = ""   # 融合前的 Merkle 根
    post_state_hash: str = ""  # 融合后的 Merkle 根
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "modal_weights": self.modal_weights,
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "evidence_hash": e.evidence_hash,
                    "weight": e.weight,
                    "causal": e.causal,
                }
                for e in self.edges
            ],
            "pre_state_hash": self.pre_state_hash,
            "post_state_hash": self.post_state_hash,
            "timestamp": self.timestamp,
        }


class FusionProvenanceTracker:
    """多模态融合溯源追踪器。

    维护一棵 Merkle 树，每片叶子对应一个 FusionRecord。
    每追加一条融合记录就重建 Merkle 根——任何篡改都会改变根哈希。

    使用方式：
      tracker = FusionProvenanceTracker()
      tracker.begin_session(binary_hash)
      record = tracker.record_fusion(modal_weights, edges)
      # ... 后续分析步骤 ...
      tracker.end_session()
      tracker.verify()  # 验证整条溯源链未被篡改
    """

    def __init__(self, max_records: int = 10000):
        self._records: List[FusionRecord] = []
        self._session_hash: str = ""
        self._merkle_root: str = ""
        self._max_records = max_records
        self._active = False

    def begin_session(self, binary_hash: str) -> str:
        """开始新分析会话。binary_hash 作为溯源链的创始哈希。"""
        self._records.clear()
        self._session_hash = binary_hash
        self._merkle_root = self._compute_merkle_root()
        self._active = True
        return self._merkle_root

    def end_session(self) -> Tuple[str, int]:
        """结束会话。返回 (最终 merkle_root, 记录总数)。"""
        self._active = False
        self._merkle_root = self._compute_merkle_root()
        return self._merkle_root, len(self._records)

    def record_fusion(
        self,
        modal_weights: Dict[str, float],
        edges: List[ProvenanceEdge],
        trace_id: Optional[str] = None,
    ) -> FusionRecord:
        """记录一次融合操作。

        自动生成 trace_id（基于前一条记录的哈希 + 时间戳），
        确保每条记录可沿链回溯。
        """
        if not self._active:
            raise RuntimeError("provenance session not started")

        _pre_root = self._merkle_root
        _trace_id = trace_id or self._make_trace_id()

        _record = FusionRecord(
            trace_id=_trace_id,
            modal_weights=dict(modal_weights),
            edges=list(edges),
            pre_state_hash=_pre_root,
            timestamp=time.time(),
        )

        self._records.append(_record)
        if len(self._records) > self._max_records:
            # 超限触发压缩：合并最早两条记录以控制存储
            self._compact_oldest()

        self._merkle_root = self._compute_merkle_root()
        _record.post_state_hash = self._merkle_root
        return _record

    def verify(self) -> Tuple[bool, str]:
        """验证溯源链完整性。

        重新计算 Merkle 根并与存储值对比。
        返回 (is_valid, reason)。
        """
        _computed_root = self._compute_merkle_root()
        if _computed_root != self._merkle_root:
            return False, (
                f"merkle root mismatch: computed={_computed_root[:16]}..., "
                f"stored={self._merkle_root[:16]}..."
            )
        return True, "ok"

    def get_causal_edges(self) -> List[ProvenanceEdge]:
        """提取所有因果边——安全决策中不可降权。"""
        _causal: List[ProvenanceEdge] = []
        for _r in self._records:
            for _e in _r.edges:
                if _e.causal:
                    _causal.append(_e)
        return _causal

    def get_modal_contribution_summary(self) -> Dict[str, float]:
        """汇总每个模态在整条融合链中的累计贡献度。"""
        _contrib: Dict[str, float] = {}
        for _r in self._records:
            for _name, _w in _r.modal_weights.items():
                _contrib[_name] = _contrib.get(_name, 0.0) + _w
        if _contrib:
            _total = sum(_contrib.values())
            for _name in _contrib:
                _contrib[_name] /= _total
        return _contrib

    # ---- 内部方法 ----

    def _make_trace_id(self) -> str:
        _seed = (
            self._merkle_root
            + self._session_hash
            + str(len(self._records))
            + str(time.time())
        )
        return hashlib.sha256(_seed.encode()).hexdigest()[:16]

    def _compute_merkle_root(self) -> str:
        """从 session_hash 和所有 record 构建 Merkle 树根。

        简化实现：叶子 = SHA256(session_hash || record_hashes)，
        足以验证整条链是否被篡改。
        注意：post_state_hash 不参与输入以规避循环依赖——
        它是本函数的输出，不可作为输入。
        """
        if not self._records:
            return hashlib.sha256(self._session_hash.encode()).hexdigest()

        # 收集叶子哈希
        _leaves = [self._session_hash]
        for _r in self._records:
            # 排除 post_state_hash —— 它是本函数的输出，非输入
            _d = _r.to_dict()
            _d.pop("post_state_hash", None)
            _leaf_str = json.dumps(_d, sort_keys=True, default=str)
            _leaves.append(hashlib.sha256(_leaf_str.encode()).hexdigest())

        # 逐层归并到根
        while len(_leaves) > 1:
            _next_level = []
            for i in range(0, len(_leaves), 2):
                if i + 1 < len(_leaves):
                    _combined = _leaves[i] + _leaves[i + 1]
                else:
                    _combined = _leaves[i] + _leaves[i]  # 奇数叶子自复制
                _next_level.append(
                    hashlib.sha256(_combined.encode()).hexdigest()
                )
            _leaves = _next_level

        return _leaves[0]

    def _compact_oldest(self) -> None:
        """压缩最旧的两条记录以控制存储。

        仅在超过 max_records 时触发。
        合并后的记录保留两者的边集和平均权重。
        """
        if len(self._records) < 3:
            return
        _r0, _r1 = self._records[0], self._records[1]
        _merged_weights: Dict[str, float] = {}
        _all_keys = set(_r0.modal_weights) | set(_r1.modal_weights)
        for _k in _all_keys:
            _w0 = _r0.modal_weights.get(_k, 0.0)
            _w1 = _r1.modal_weights.get(_k, 0.0)
            _merged_weights[_k] = (_w0 + _w1) / 2.0

        _record = FusionRecord(
            trace_id=f"compact:{_r0.trace_id}+{_r1.trace_id}",
            modal_weights=_merged_weights,
            edges=_r0.edges + _r1.edges,
            pre_state_hash=_r0.pre_state_hash,
            timestamp=_r0.timestamp,
        )
        self._records = [_record] + self._records[2:]


def _test_merkle():
    """冒烟测试 — Merkle 树构建与验证。"""
    _t = FusionProvenanceTracker()
    _t.begin_session("test_binary_hash_abc123")
    _e1 = ProvenanceEdge(
        source="static_analysis", target="vuln_detector",
        evidence_hash="abc", weight=0.6, causal=False,
    )
    _e2 = ProvenanceEdge(
        source="dynamic_taint", target="vuln_detector",
        evidence_hash="def", weight=0.9, causal=True,
    )
    _t.record_fusion(
        modal_weights={"static": 0.4, "dynamic": 0.6},
        edges=[_e1, _e2],
    )
    _ok, _reason = _t.verify()
    assert _ok, f"verification failed: {_reason}"
    assert len(_t.get_causal_edges()) == 1
    _t.end_session()
    print("[OK] FusionProvenanceTracker smoke test passed.")


if __name__ == "__main__":
    _test_merkle()
