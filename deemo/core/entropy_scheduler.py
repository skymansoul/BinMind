"""
Entropy-guided fuzzing seed scheduler.

Allocates energy to seeds based on the global rarity of the coverage edges
they hit, using an exponential forgetting factor so historical frequency
decays over time and the scheduler remains sensitive to newly discovered edges.

Uses the core formula from Entropic with an exponential
decay window instead of a fixed one.

Distinct from adaptive_scheduler.py (MAB method-level) and complementary to
rarity_weighted_scheduler.py (frequency-based rarity) by adding temporal decay.

Key parameters:
  halflife: half-life of coverage frequency counts (in executions)
  min_energy / max_energy: mutation energy bounds

References:
  Böhme et al., 2020, IEEE S&P, "Entropic: Boosting Fuzzing with Information Theory"
  T-Scheduler
"""


import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class EntropySeedScheduler:
    """Seed energy scheduler based on Shannon entropy.

    Each seed tracks its covered edge set. The scheduler maintains per-edge
    global coverage frequency with exponential decay and allocates energy
    proportional to each seed's information content during select()."""

    def __init__(
        self,
        halflife: float = 10000.0,
        min_energy: float = 1.0,
        max_energy: float = 100.0,
        decay_base: float = 0.9999,
    ):
        """
        Args:
            halflife: half-life of coverage counts (executions), smaller = faster decay
            min_energy: minimum energy per round
            max_energy: maximum energy per round
            decay_base: per-execution decay factor (0.9999 gives half-life ~7000 execs)
        """
        self.halflife = halflife
        self.min_energy = min_energy
        self.max_energy = max_energy
        self.decay_base = decay_base

        self._edge_freq: Dict[int, float] = defaultdict(float)
        self._seed_edges: Dict[str, Set[int]] = {}
        self._seed_energy: Dict[str, float] = {}
        self._total_execs: int = 0

    def register_seed(self, seed_id: str, covered_edges: List[int]) -> None:
        """Register a new seed and its covered edges. Appends edges for existing seeds."""
        if seed_id not in self._seed_edges:
            self._seed_edges[seed_id] = set()
            self._seed_energy[seed_id] = self.min_energy

        new_edges = set(covered_edges) - self._seed_edges[seed_id]
        for e in new_edges:
            self._edge_freq[e] += 1.0
        self._seed_edges[seed_id] |= new_edges

    def record_execution(self, hit_edges: List[int], seed_id: str = "") -> None:
        """Record edges hit in one execution, updating global frequency with decay.

        Each call: increments global exec count, decays all edge frequencies,
        increments hit edges, and optionally updates the seed's edge set."""
        self._total_execs += 1

        # Decay all edge frequencies
        for e in list(self._edge_freq.keys()):
            self._edge_freq[e] *= self.decay_base
            if self._edge_freq[e] < 0.001:
                del self._edge_freq[e]

        # Edges hit in this execution
        for e in hit_edges:
            self._edge_freq[e] = self._edge_freq.get(e, 0.0) + 1.0

        if seed_id and seed_id in self._seed_edges:
            self._seed_edges[seed_id] |= set(hit_edges)

        # Periodic energy recomputation every 500 execs
        if self._total_execs % 500 == 0:
            self._recompute_energies()

    def _recompute_energies(self) -> None:
        """Recompute Shannon information content for all seeds."""
        total_execs = max(1, self._total_execs)
        for sid, edges in self._seed_edges.items():
            if not edges:
                self._seed_energy[sid] = self.min_energy
                continue

            # Shannon info: I(seed) = Σ_{e∈edges} -log₂(freq(e) / total)
            info = 0.0
            for e in edges:
                freq = max(0.001, self._edge_freq.get(e, 0.001))
                p = freq / total_execs
                info += -math.log2(p)

            # Normalize to [min_energy, max_energy]
            normalized = info / max(1, math.log2(total_execs))
            energy = self.min_energy + normalized * (self.max_energy - self.min_energy)
            self._seed_energy[sid] = min(self.max_energy, max(self.min_energy, energy))

    def select_seed(self) -> Optional[str]:
        """Select a seed with probability proportional to its energy.

        High-information seeds are more likely to be chosen but not guaranteed,
        preserving some exploration (softmax-style rather than argmax)."""
        if not self._seed_energy:
            return None

        total = sum(self._seed_energy.values())
        if total <= 0:
            return None

        import random
        r = random.uniform(0, total)
        cum = 0.0
        for sid, energy in self._seed_energy.items():
            cum += energy
            if r <= cum:
                return sid

        return list(self._seed_energy.keys())[-1]

    def get_energy(self, seed_id: str) -> float:
        """Return the current energy value for a seed."""
        return self._seed_energy.get(seed_id, self.min_energy)

    def top_seeds(self, n: int = 5) -> List[Tuple[str, float]]:
        """Return the top n seeds by energy."""
        sorted_seeds = sorted(
            self._seed_energy.items(), key=lambda x: -x[1]
        )
        return sorted_seeds[:n]

    def stats(self) -> Dict[str, Any]:
        """Scheduler statistics snapshot."""
        return {
            "total_execs": self._total_execs,
            "active_seeds": len(self._seed_edges),
            "tracked_edges": len(self._edge_freq),
            "total_energy": round(sum(self._seed_energy.values()), 1),
            "top_energy": round(max(self._seed_energy.values()) if self._seed_energy else 0, 1),
            "avg_energy": round(
                sum(self._seed_energy.values()) / max(1, len(self._seed_energy)), 1
            ),
        }
