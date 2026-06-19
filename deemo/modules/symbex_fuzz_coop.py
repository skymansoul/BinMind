"""
符号执行与模糊测试协同框架模块

功能:
    1. 符号执行定期将难以求解的路径约束发送给模糊测试, 利用随机搜索突破
    2. 模糊测试又将新覆盖的路径反馈给符号执行
    3. 实现双向驱动, 提升代码覆盖率

核心技术:
    - 接口: 模糊测试提供 seed pool, 符号执行提供约束 hint
    - 协同调度: 轮询 + 反馈
    - 覆盖率整合 (edge bitmap)
"""

import logging
import os
import time
import json
import hashlib
import threading
from typing import Dict, Any, List, Optional, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class CoopRole(Enum):
    SYMBEX = "symbex"
    FUZZER = "fuzzer"
    BOTH = "both"


class MessageKind(Enum):
    CONSTRAINT_HINT = "constraint_hint"     # 符号执行 -> 模糊测试
    COVERAGE_REPORT = "coverage_report"     # 模糊测试 -> 符号执行
    SEED_REQUEST = "seed_request"           # 符号执行 -> 模糊测试
    SEED_DELIVERY = "seed_delivery"         # 模糊测试 -> 符号执行
    NEW_PATH = "new_path"                   # 双向


@dataclass
class CoopMessage:
    """协同消息"""
    kind: MessageKind
    sender: CoopRole
    timestamp: float
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SeedItem:
    """语料项"""
    data: bytes
    coverage_hash: str
    crash: bool = False
    timestamp: float = field(default_factory=time.time)
    source: str = "fuzzer"
    score: float = 0.0


@dataclass
class ConstraintHint:
    """约束提示"""
    func_name: str
    constraints: List[str]
    target_path: str
    suggested_inputs: Dict[str, int] = field(default_factory=dict)
    difficulty: float = 0.5


@dataclass
class CoverageReport:
    """覆盖率报告"""
    total_edges: int
    new_edges: int
    edge_bitmap: str        # hex 编码
    timestamp: float = field(default_factory=time.time)


@dataclass
class CoopStats:
    """协同统计"""
    messages_sent: int = 0
    messages_received: int = 0
    symbex_to_fuzzer: int = 0
    fuzzer_to_symbex: int = 0
    new_coverage: int = 0
    seeds_delivered: int = 0
    hints_delivered: int = 0


class MessageBus:
    """消息总线"""

    def __init__(self):
        self.queues: Dict[CoopRole, deque] = {
            CoopRole.SYMBEX: deque(),
            CoopRole.FUZZER: deque()
        }
        self._lock = threading.Lock()

    def send(self, msg: CoopMessage):
        target = (CoopRole.FUZZER if msg.sender == CoopRole.SYMBEX
                  else CoopRole.SYMBEX)
        with self._lock:
            self.queues[target].append(msg)

    def receive(self, role: CoopRole,
                timeout: float = 1.0) -> List[CoopMessage]:
        msgs: List[CoopMessage] = []
        deadline = time.time() + timeout
        with self._lock:
            while self.queues[role] and time.time() < deadline:
                msgs.append(self.queues[role].popleft())
        return msgs


class CoverageTracker:
    """覆盖率追踪"""

    def __init__(self, max_edges: int = 65536):
        self.max_edges = max_edges
        self.edges: Set[int] = set()
        self._lock = threading.Lock()

    def update(self, new_edges: Set[int]) -> int:
        """更新并返回新增数"""
        with self._lock:
            before = len(self.edges)
            self.edges.update(new_edges)
            return len(self.edges) - before

    def bitmap_hash(self) -> str:
        sorted_edges = sorted(self.edges)
        h = hashlib.sha256()
        for e in sorted_edges:
            h.update(struct.pack("<Q", e))
        return h.hexdigest([:32])

    def to_bitmap(self) -> str:
        """压缩为 hex 字符串"""
        bits = bytearray(self.max_edges // 8)
        for e in self.edges:
            if e < self.max_edges:
                bits[e // 8] |= 1 << (e % 8)
        return bits.hex()

    def total(self) -> int:
        with self._lock:
            return len(self.edges)


import struct


class SymbExFuzzCoop:
    """
    符号执行 + 模糊测试 协同器
    """

    def __init__(self,
                 symbex_runner: Optional[Callable[..., List[ConstraintHint]]] = None,
                 fuzzer_runner: Optional[Callable[..., List[SeedItem]]] = None):
        self.bus = MessageBus()
        self.coverage = CoverageTracker()
        self.seeds: deque = deque(maxlen=10000)
        self.hints: deque = deque(maxlen=1000)
        self.stats = CoopStats()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.symbex_runner = symbex_runner
        self.fuzzer_runner = fuzzer_runner

    def push_hint(self, hint: ConstraintHint):
        """符号执行侧: 推入约束提示"""
        msg = CoopMessage(
            kind=MessageKind.CONSTRAINT_HINT,
            sender=CoopRole.SYMBEX,
            timestamp=time.time(),
            payload={'hint': hint.__dict__}
        )
        self.bus.send(msg)
        self.hints.append(hint)
        with self._lock:
            self.stats.hints_delivered += 1
            self.stats.symbex_to_fuzzer += 1

    def push_coverage(self, report: CoverageReport):
        """模糊测试侧: 推入覆盖率报告"""
        msg = CoopMessage(
            kind=MessageKind.COVERAGE_REPORT,
            sender=CoopRole.FUZZER,
            timestamp=time.time(),
            payload={'report': report.__dict__}
        )
        self.bus.send(msg)
        with self._lock:
            new = self.coverage.update(
                self._bitmap_to_edges(report.edge_bitmap)
            )
            self.stats.new_coverage += new
            self.stats.fuzzer_to_symbex += 1

    def push_seed(self, seed: SeedItem):
        """模糊测试侧: 推入新种子"""
        msg = CoopMessage(
            kind=MessageKind.SEED_DELIVERY,
            sender=CoopRole.FUZZER,
            timestamp=time.time(),
            payload={'seed': {
                'data': seed.data.hex(),
                'coverage_hash': seed.coverage_hash,
                'crash': seed.crash
            }}
        )
        self.bus.send(msg)
        self.seeds.append(seed)
        with self._lock:
            self.stats.seeds_delivered += 1
            self.stats.fuzzer_to_symbex += 1

    def request_seed(self, hint: ConstraintHint) -> List[SeedItem]:
        """符号执行侧: 请求匹配提示的种子"""
        msg = CoopMessage(
            kind=MessageKind.SEED_REQUEST,
            sender=CoopRole.SYMBEX,
            timestamp=time.time(),
            payload={'hint': hint.__dict__}
        )
        self.bus.send(msg)
        with self._lock:
            seeds = list(self.seeds)
        # 评分: 相似度
        scored: List[Tuple[float, SeedItem]] = []
        for s in seeds:
            score = self._seed_hint_score(s, hint)
            scored.append((score, s))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:10]]

    def _seed_hint_score(self, seed: SeedItem, hint: ConstraintHint) -> float:
        if seed.crash:
            return 1.0
        # 简单: 字节熵 + 大小匹配
        if len(seed.data) == 0:
            return 0.0
        from collections import Counter
        c = Counter(seed.data)
        ent = -sum((n / len(seed.data)) * (n / len(seed.data)).bit_length()
                   for n in c.values())
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
            logger.warning(f"bitmap 解析失败: {e}")
            return set()

    def tick(self, symbex_iter: int = 1, fuzz_iter: int = 1):
        """执行一轮协同调度"""
        # 1. 符号执行: 产生 hint
        if self.symbex_runner:
            try:
                hints = self.symbex_runner(symbex_iter)
                for h in hints:
                    self.push_hint(h)
            except Exception as e:
                logger.warning(f"symbex 失败: {e}")
        # 2. 模糊测试: 产生 seeds + coverage
        if self.fuzzer_runner:
            try:
                new_seeds = self.fuzzer_runner(fuzz_iter)
                for s in new_seeds:
                    self.push_seed(s)
            except Exception as e:
                logger.warning(f"fuzzer 失败: {e}")
        # 3. 处理消息
        for msg in self.bus.receive(CoopRole.SYMBEX, timeout=0.1):
            self._handle_symbex_msg(msg)
        for msg in self.bus.receive(CoopRole.FUZZER, timeout=0.1):
            self._handle_fuzzer_msg(msg)

    def _handle_symbex_msg(self, msg: CoopMessage):
        if msg.kind == MessageKind.SEED_DELIVERY:
            seed_data = bytes.fromhex(msg.payload['seed']['data'])
            self.seeds.append(SeedItem(
                data=seed_data,
                coverage_hash=msg.payload['seed']['coverage_hash'],
                crash=msg.payload['seed'].get('crash', False),
                source="fuzzer"
            ))

    def _handle_fuzzer_msg(self, msg: CoopMessage):
        if msg.kind == MessageKind.CONSTRAINT_HINT:
            hint_dict = msg.payload.get('hint', {})
            self.hints.append(ConstraintHint(**hint_dict))
        elif msg.kind == MessageKind.SEED_REQUEST:
            # 模糊测试侧处理: 选择匹配的种子
            pass

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'symbex_to_fuzzer': self.stats.symbex_to_fuzzer,
                'fuzzer_to_symbex': self.stats.fuzzer_to_symbex,
                'new_coverage': self.stats.new_coverage,
                'seeds_count': len(self.seeds),
                'hints_count': len(self.hints),
                'total_edges': self.coverage.total(),
                'bitmap_hash': self.coverage.bitmap_hash()
            }


def run_cooperation(
    rounds: int = 10,
    symbex_iter: int = 1,
    fuzz_iter: int = 1
) -> Dict[str, Any]:
    """便捷入口"""
    coop = SymbExFuzzCoop()
    for r in range(rounds):
        coop.tick(symbex_iter=symbex_iter, fuzz_iter=fuzz_iter)
    return {
        'success': True,
        'rounds': rounds,
        'statistics': coop.get_statistics()
    }
