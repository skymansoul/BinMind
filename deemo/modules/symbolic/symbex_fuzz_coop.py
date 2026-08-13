"""Bidirectional symbex–fuzzer cooperation bus.

Symbolic execution produces constraint hints that guide the fuzzer toward
hard-to-reach branches. The fuzzer feeds back coverage reports and seeds
that symbex uses to prune already-covered paths. A message-bus decouples
the two so either side can be swapped independently.
"""

import logging
import os
import time
import json
import hashlib
import struct
import threading
from dataclasses import dataclass, field
from collections import defaultdict, deque
from typing import Dict, Any
from typing import List, Optional

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
    """Single message across the symbex–fuzzer bus."""
    kind: str
    sender: str
    timestamp: float
    payload: Dict = field(default_factory=dict)


@dataclass
class SeedItem:
    """A fuzzer-produced input with coverage fingerprint and crash flag."""
    data: bytes
    coverage_hash: str
    crash: bool = False
    timestamp: float = field(default_factory=time.time)
    source: str = "fuzzer"
    score: float = 0.0


@dataclass
class ConstraintHint:
    """Symbex-produced hint: a branch condition the fuzzer should target."""
    func_name: str
    constraints: List
    target_path: Any
    suggested_inputs: Dict = field(default_factory=dict)
    difficulty: float = 0.5


@dataclass
class CoverageReport:
    """Fuzzer's periodic coverage snapshot sent to symbex."""
    total_edges: int
    new_edges: int
    edge_bitmap: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class CoopStats:
    """Running counters for the cooperation channel."""
    messages_sent: int = 0
    messages_received: int = 0
    symbex_to_fuzzer: int = 0
    fuzzer_to_symbex: int = 0
    new_coverage: int = 0
    seeds_delivered: int = 0
    hints_delivered: int = 0


class MessageBus:
    """Unidirectional queues per role. Symbex writes to fuzzer's queue,
    fuzzer writes to symbex's queue."""

    def __init__(self):
        self.queues: Dict[str, deque] = {
            CoopRole.SYMBEX: deque(),
            CoopRole.FUZZER: deque()
        }
        self._lock = threading.Lock()

    def send(self, msg: CoopMessage):
        """Route message to the opposite role's queue."""
        target = (CoopRole.FUZZER if msg.sender == CoopRole.SYMBEX
                  else CoopRole.SYMBEX)
        with self._lock:
            self.queues[target].append(msg)

    def receive(self, role: str,
                timeout: float = 1.0) -> List[CoopMessage]:
        """Drain available messages for a role, up to the deadline."""
        msgs: List[CoopMessage] = []
        deadline = time.time() + timeout
        with self._lock:
            while self.queues[role] and time.time() < deadline:
                msgs.append(self.queues[role].popleft())
        return msgs


class CoverageTracker:
    """Maintains a set of covered edges and derives a bitmap hash for
    efficient comparison across the bus."""

    def __init__(self, max_edges: int = 65536):
        self.max_edges = max_edges
        self.edges: Set[int] = set()
        self._lock = threading.Lock()

    def update(self, new_edges: Set[int]) -> int:
        """Add edges; return count of genuinely new ones."""
        with self._lock:
            before = len(self.edges)
            self.edges.update(new_edges)
            return len(self.edges) - before

    def bitmap_hash(self) -> str:
        """SHA-256 over the sorted edge list — compact coverage fingerprint."""
        sorted_edges = sorted(self.edges)
        h = hashlib.sha256()
        for e in sorted_edges:
            h.update(struct.pack("<Q", e))
        return h.hexdigest()[:32]

    def to_bitmap(self) -> str:
        """Dense hex bitmap; one bit per edge index."""
        bits = bytearray(self.max_edges // 8)
        for e in self.edges:
            if e < self.max_edges:
                bits[e // 8] |= 1 << (e % 8)
        return bits.hex()

    def total(self) -> int:
        """Current edge count."""
        with self._lock:
            return len(self.edges)


class SymbExFuzzCoop:
    """Orchestrator that wires symbex hints and fuzzer seeds through the bus.

    Each tick() runs one iteration of both sides, drains the message queues,
    and updates the shared coverage view. Plug in custom symbex_runner and
    fuzzer_runner callables to swap backends."""

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
        """Symbex → Fuzzer: deliver a constraint to target."""
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
        """Fuzzer → Symbex: update the shared coverage bitmap."""
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
        """Fuzzer → Symbex: share a seed for seeding symbolic state."""
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
        """Symbex → Fuzzer: ask for seeds matching a constraint hint.
        Scores available seeds by entropy; returns top 10."""
        msg = CoopMessage(
            kind=MessageKind.SEED_REQUEST,
            sender=CoopRole.SYMBEX,
            timestamp=time.time(),
            payload={'hint': hint.__dict__}
        )
        self.bus.send(msg)
        with self._lock:
            seeds = list(self.seeds)
        scored: List[Tuple[float, SeedItem]] = []
        for s in seeds:
            score = self._seed_hint_score(s, hint)
            scored.append((score, s))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:10]]

    def _seed_hint_score(self, seed: SeedItem, hint: ConstraintHint) -> float:
        """Score a seed against a hint using byte-entropy as a diversity proxy."""
        if seed.crash:
            return 1.0
        if len(seed.data) == 0:
            return 0.0
        import math
        from collections import Counter
        c = Counter(seed.data)
        total = len(seed.data)
        ent = -sum((n / total) * math.log2(n / total)
                   for n in c.values() if n > 0)
        return min(1.0, ent / 8.0)

    def _bitmap_to_edges(self, bitmap_hex: str) -> Set[int]:
        """Decode a hex coverage bitmap back into an edge-index set."""
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
        """Advance one cooperation round: run both sides, then drain the bus."""
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

    def _handle_symbex_msg(self, msg: CoopMessage):
        """Process messages arriving at the symbex side."""
        if msg.kind == MessageKind.SEED_DELIVERY:
            seed_data = bytes.fromhex(msg.payload['seed']['data'])
            self.seeds.append(SeedItem(
                data=seed_data,
                coverage_hash=msg.payload['seed']['coverage_hash'],
                crash=msg.payload['seed'].get('crash', False),
                source="fuzzer"
            ))

    def _handle_fuzzer_msg(self, msg: CoopMessage):
        """Process messages arriving at the fuzzer side."""
        if msg.kind == MessageKind.CONSTRAINT_HINT:
            hint_dict = msg.payload.get('hint', {})
            self.hints.append(ConstraintHint(**hint_dict))
        elif msg.kind == MessageKind.SEED_REQUEST:
            pass

    def get_statistics(self) -> Dict[str, Any]:
        """Snapshot of cooperation channel metrics."""
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
    """One-shot: instantiate SymbExFuzzCoop, run N rounds, return statistics."""
    coop = SymbExFuzzCoop()
    for r in range(rounds):
        coop.tick(symbex_iter=symbex_iter, fuzz_iter=fuzz_iter)
    return {
        'success': True,
        'rounds': rounds,
        'statistics': coop.get_statistics()
    }
