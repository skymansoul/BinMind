# 差分跨实现预言机 —— N≥3共识投票+字段级增量最小化。
# 三路投票隔离少数派实现(若A=B≠C→C可疑)，二路无法判定责任方。
# 与ParDiff(静态FSM比对)/NEZHA(字节级δ调试)的差异: 协议字段级结构化比对+动态反馈闭环。

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


class DiffVerdict(Enum):
    EQUIVALENT          = auto()  # 所有实现响应等价
    DIVERGENT_AMBIGUOUS = auto()  # 存在分歧但无多数派(如2v2)
    CONSENSUS_MINORITY_BUG = auto()  # 少数派实现疑似有bug
    INDETERMINATE       = auto()  # 信息不足以判定


@dataclass
class ImplResponse:
    """单一协议实现的响应结构。

    status: 高层状态码(如HTTP 200, Modbus function code + exception)
    fields: {field_name → value} 结构化字段映射
    raw: 原始响应字节
    impl_name: 实现标识(如 "openssl", "gnutls", "mbedtls")
    """
    status: int
    fields: Dict[str, Any] = field(default_factory=dict)
    raw: bytes = b""
    impl_name: str = ""
    latency_ms: float = 0.0


@dataclass
class OracleVerdict:
    """差分预言机的完整判定"""
    verdict: DiffVerdict
    majority_impls: List[str] = field(default_factory=list)
    minority_impls: List[str] = field(default_factory=list)
    consensus_ratio: float = 0.0      # 多数派占比
    divergence_fields: List[str] = field(default_factory=list)
    confidence: float = 0.0           # [0,1] 用于MAB奖励


@dataclass
class MinimizedMessage:
    """最小化后的复现消息"""
    original: bytes
    minimized: bytes
    removed_fields: List[str]
    removed_bytes: int
    still_triggers: bool


class ResponseComparator:
    """结构化响应比较器 —— 按字段语义等价性比较两个实现响应。

    不比较原始字节(session ID/随机nonce等天然跨实现不同)，
    仅比较协议语义层结构化字段。数值用容差比较，字符串去空白后比较。
    """

    _NUMERIC_TOLERANCE = 0.001
    # 比较时忽略的字段名模式 —— 这些字段天然跨实现不同
    _IGNORE_FIELD_PATTERNS = [
        re.compile(p, re.IGNORECASE) for p in [
            r'session.*id', r'nonce', r'timestamp', r'random',
            r'cookie', r'token', r'etag', r'x-.+', r'server',
        ]
    ]

    @classmethod
    def _should_ignore(cls, field_name: str) -> bool:
        return any(p.match(field_name) for p in cls._IGNORE_FIELD_PATTERNS)

    @classmethod
    def compare(cls, a: ImplResponse, b: ImplResponse) -> Tuple[bool, Set[str]]:
        """比较两个响应。

        返回 (等价性, 分歧字段集)。
        等价性定义: status相同 且 所有非忽略字段的值在容差内一致。
        """
        if a.status != b.status:
            return False, {"__status__"}

        all_fields = set(a.fields.keys()) | set(b.fields.keys())
        diverged: Set[str] = set()

        for fname in all_fields:
            if cls._should_ignore(fname):
                continue
            va = a.fields.get(fname)
            vb = b.fields.get(fname)
            if va is None and vb is None:
                continue
            if va is None or vb is None:
                diverged.add(fname)
            elif not cls._values_equal(va, vb):
                diverged.add(fname)

        return len(diverged) == 0, diverged

    @classmethod
    def _values_equal(cls, a: Any, b: Any) -> bool:
        """带类型感知的值比较"""
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            if math.isinf(a) or math.isinf(b):
                return a == b
            denom = max(abs(a), abs(b), 1.0)
            return abs(a - b) / denom < cls._NUMERIC_TOLERANCE
        if isinstance(a, bytes) and isinstance(b, bytes):
            return a == b
        if isinstance(a, str) and isinstance(b, str):
            return cls._normalize_str(a) == cls._normalize_str(b)
        return str(a) == str(b)

    @staticmethod
    def _normalize_str(s: str) -> str:
        return " ".join(s.lower().split())


class ConsensusVoter:
    """N≥3共识投票器。输入多实现响应，按多数投票判定分歧归属。

    判定: N≥3, 存在≥ceil(N/2)的等价组→多数派正确, 少数派可疑。
    无多数派(如2v2)→DIVERGENT_AMBIGUOUS。二路比较不适用。
    """

    def __init__(self, comparator: Optional[ResponseComparator] = None):
        self._cmp = comparator or ResponseComparator()

    def vote(self, responses: List[ImplResponse]) -> OracleVerdict:
        n = len(responses)
        if n < 3:
            return OracleVerdict(
                verdict=DiffVerdict.INDETERMINATE,
                confidence=0.0)

        # 构建等价关系无向图: 节点=索引，边=等价
        equiv_graph: Dict[int, Set[int]] = {i: set() for i in range(n)}
        all_diverged_fields: Set[str] = set()

        for i in range(n):
            for j in range(i + 1, n):
                eq, div_fields = self._cmp.compare(responses[i], responses[j])
                if eq:
                    equiv_graph[i].add(j)
                    equiv_graph[j].add(i)
                else:
                    all_diverged_fields.update(div_fields)

        # 寻找最大团(等价类)作为多数派
        visited: Set[int] = set()
        components: List[Set[int]] = []
        for i in range(n):
            if i not in visited:
                comp = self._bfs_component(i, equiv_graph)
                visited.update(comp)
                components.append(comp)

        if not components:
            return OracleVerdict(verdict=DiffVerdict.INDETERMINATE, confidence=0.0)

        largest = max(components, key=len)
        majority_threshold = math.ceil(n / 2)

        if len(largest) >= majority_threshold:
            majority_names = [responses[i].impl_name for i in largest]
            minority_names = [responses[i].impl_name
                            for i in range(n) if i not in largest]
            # 置信度 = majority比例 × 字段分歧一致性惩罚
            ratio = len(largest) / n
            # 若n-1个等价1个分歧 → 高置信度；若仅过半 → 中等
            field_penalty = 1.0 / max(len(all_diverged_fields), 1)
            confidence = ratio * (0.7 + 0.3 * (1.0 - field_penalty))
            return OracleVerdict(
                verdict=DiffVerdict.CONSENSUS_MINORITY_BUG,
                majority_impls=majority_names,
                minority_impls=minority_names,
                consensus_ratio=ratio,
                divergence_fields=sorted(all_diverged_fields),
                confidence=min(confidence, 1.0),
            )
        else:
            return OracleVerdict(
                verdict=DiffVerdict.DIVERGENT_AMBIGUOUS,
                divergence_fields=sorted(all_diverged_fields),
                confidence=0.3,
            )

    @staticmethod
    def _bfs_component(start: int,
                       graph: Dict[int, Set[int]]) -> Set[int]:
        comp: Set[int] = set()
        queue = [start]
        while queue:
            node = queue.pop()
            if node in comp:
                continue
            comp.add(node)
            queue.extend(graph.get(node, set()) - comp)
        return comp


class DeltaMinimizer:
    """字段级ddmin最小化器: 对触发分歧的协议消息字段做递归二分搜索，
    找到维持分歧的最小字段子集。O(|fields| × log|fields|) oracle调用。
    """

    def __init__(self, max_iterations: int = 200):
        self._max_iter = max_iterations
        self._call_count = 0

    def minimize_fields(self,
                        fields: List[Tuple[str, Any]],
                        still_diverges: Callable[[List[Tuple[str, Any]]], bool]
                        ) -> Tuple[List[Tuple[str, Any]], int]:
        """对字段列表做ddmin最小化。

        still_diverges: 给定字段子集→重建消息→发送至多实现→是否仍分歧。
        返回 (最小字段列表, oracle调用次数)。
        """
        self._call_count = 0
        result = self._ddmin(fields, still_diverges, 2)
        return result, self._call_count

    def _ddmin(self, subset: List[Tuple[str, Any]],
               oracle: Callable[[List[Tuple[str, Any]]], bool],
               granularity: int) -> List[Tuple[str, Any]]:
        n = len(subset)
        if n <= 1:
            return subset
        if self._call_count >= self._max_iter:
            return subset

        chunk_size = max(1, n // granularity)
        # 测试每个补集: 去除chunk_size个字段后是否仍触发分歧
        for i in range(0, n, chunk_size):
            complement = subset[:i] + subset[i + chunk_size:]
            self._call_count += 1
            if self._call_count >= self._max_iter:
                break
            try:
                if oracle(complement):
                    # 补集仍触发→该chunk非必需→递归处理补集
                    return self._ddmin(complement, oracle, max(granularity - 1, 2))
            except Exception:
                continue

        # 所有chunk均为必需→提高粒度
        if granularity < n:
            return self._ddmin(subset, oracle, min(granularity * 2, n))
        return subset


def evaluate_cross_impl(responses: List[ImplResponse],
                        voter: Optional[ConsensusVoter] = None
                        ) -> OracleVerdict:
    """便捷入口：对多实现响应列表执行差分判定"""
    return (voter or ConsensusVoter()).vote(responses)


def differential_reward_from_verdict(verdict: OracleVerdict,
                                     crash_detected: bool = False,
                                     new_coverage: bool = False) -> float:
    """差分判定→[0,1]奖励: CONSENSUS_MINORITY_BUG=0.6×置信度,
    DIVERGENT_AMBIGUOUS=0.3, EQUIVALENT=0.05。崩溃+0.3, 新覆盖+0.1。
    """
    base = 0.0
    if verdict.verdict == DiffVerdict.CONSENSUS_MINORITY_BUG:
        base = 0.6 * verdict.confidence
    elif verdict.verdict == DiffVerdict.DIVERGENT_AMBIGUOUS:
        base = 0.3 * verdict.confidence
    elif verdict.verdict == DiffVerdict.EQUIVALENT:
        base = 0.05

    if crash_detected:
        base = min(1.0, base + 0.3)
    if new_coverage and base < 0.9:
        base = min(1.0, base + 0.1)

    return base


__all__ = [
    "DiffVerdict", "ImplResponse", "OracleVerdict", "MinimizedMessage",
    "ResponseComparator", "ConsensusVoter", "DeltaMinimizer",
    "evaluate_cross_impl", "differential_reward_from_verdict",
]
