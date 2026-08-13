"""Coverage-guided symbolic exploration with genetic and greedy strategies.

Maintains a block/edge coverage bitmap and uses it to score path candidates.
Supports four exploration strategies:
  - GREEDY: always pick the highest-scoring unexplored path
  - GENETIC: evolve a population of input seeds via crossover/mutation
  - RANDOM: uniform random selection
  - HYBRID: interleave genetic (every 5th step) and greedy

The genetic optimizer uses roulette-wheel selection, single-point crossover,
and per-byte mutation. Fitness = coverage_gain × 0.7 + risk_score × 0.3.
"""

import logging
import os
import random
import time
import json
import hashlib
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

__log = logging.getLogger(__name__)


class ExplorationStrategy(Enum):
    """Available path selection strategies."""
    GREEDY = "greedy"
    GENETIC = "genetic"
    RANDOM = "random"
    HYBRID = "hybrid"


class CoverageMetric(Enum):
    """Granularity of coverage measurement."""
    BLOCK = "block"
    EDGE = "edge"
    PATH = "path"
    FUNCTION = "function"


@dataclass
class CoverageInfo:
    """Snapshot of covered blocks, edges, functions, and paths."""
    blocks: Set[int] = field(default_factory=set)
    edges: Set[Tuple[int, int]] = field(default_factory=set)
    functions: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    total_blocks: int = 0
    total_edges: int = 0

    def coverage_ratio(self, metric: CoverageMetric) -> float:
        """Fraction of the target space covered."""
        if metric == CoverageMetric.BLOCK:
            return len(self.blocks) / max(1, self.total_blocks)
        elif metric == CoverageMetric.EDGE:
            return len(self.edges) / max(1, self.total_edges)
        elif metric == CoverageMetric.FUNCTION:
            return len(self.functions) / max(1, self.total_edges)
        return 0.0


@dataclass
class PathState:
    """A candidate path with scoring metadata for greedy selection."""
    path_id: str
    constraints: List = field(default_factory=list)
    depth: int = 0
    coverage_gain: float = 0.0
    risk_score: float = 0.0
    explored: bool = False
    timestamp: float = 0.0
    metadata: Dict = field(default_factory=dict)

    def score(self) -> float:
        """Weighted composite: coverage gain dominates, risk breaks ties."""
        return self.coverage_gain * 0.6 + self.risk_score * 0.4


@dataclass
class GeneticSeed:
    """One individual in the genetic population: input bytes + fitness."""
    input_bytes: bytes
    fitness: float = 0.0
    coverage_bits: int = 0
    generation: int = 0
    parent_ids: List = field(default_factory=list)

    def compute_id(self) -> str:
        """Short hash for lineage tracking."""
        return hashlib.sha256(self.input_bytes).hexdigest()[:16]


class CoverageTracker:
    """Thread-safe block/edge recorder with a sliding history window for
    computing recent coverage velocity."""

    def __init__(self):
        self._coverage = CoverageInfo()
        self._history: List[CoverageInfo] = []
        self._lock = threading.RLock()

    def record(self, blocks: Set[int], edges: Optional[Set[Tuple[int, int]]] = None):
        """Record newly covered blocks and edges; returns count of new blocks."""
        with self._lock:
            prev_blocks = len(self._coverage.blocks)
            self._coverage.blocks.update(blocks)
            if edges:
                self._coverage.edges.update(edges)
            new_blocks = len(self._coverage.blocks) - prev_blocks
            self._history.append(CoverageInfo(
                blocks=self._coverage.blocks.copy(),
                edges=self._coverage.edges.copy(),
                total_blocks=self._coverage.total_blocks,
                total_edges=self._coverage.total_edges
            ))
            return new_blocks

    @property
    def coverage(self):
        """Current coverage snapshot."""
        return self._coverage

    def get_current(self) -> CoverageInfo:
        """Thread-safe copy of current coverage."""
        with self._lock:
            return self._coverage

    def set_total(self, total_blocks: int, total_edges: int):
        """Set the denominator for coverage ratio calculations."""
        with self._lock:
            self._coverage.total_blocks = total_blocks
            self._coverage.total_edges = total_edges

    def coverage_gain_recent(self, window: int = 10) -> float:
        """Average block coverage gain over the last `window` snapshots."""
        with self._lock:
            if len(self._history) < 2:
                return 0.0
            recent = self._history[-window:]
            if len(recent) < 2:
                return 0.0
            first = len(recent[0].blocks)
            last = len(recent[-1].blocks)
            return (last - first) / max(1, len(recent))


class GeneticPathOptimizer:
    """Roulette-wheel selection, single-point crossover, per-byte mutation.
    Elitism preserves the top N individuals each generation."""

    def __init__(self, population_size: int = 50, mutation_rate: float = 0.1,
                 crossover_rate: float = 0.7, elitism: int = 5):
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._elitism = elitism
        self.population: List[GeneticSeed] = []
        self.generation = 0

    @property
    def population_size(self):
        return self._population_size

    @property
    def mutation_rate(self):
        return self._mutation_rate

    @property
    def crossover_rate(self):
        return self._crossover_rate

    @property
    def elitism(self):
        return self._elitism

    def initialize(self, seed_inputs: List[bytes]):
        """Seed the population from a list of initial byte inputs."""
        self.population = [
            GeneticSeed(input_bytes=s, generation=0)
            for s in seed_inputs[:self.population_size]
        ]

    def evaluate(self, evaluator):
        """Score every individual using the provided fitness evaluator."""
        for seed in self.population:
            seed.fitness, seed.coverage_bits = evaluator(seed.input_bytes)

    def select(self) -> Tuple[GeneticSeed, GeneticSeed]:
        """Roulette-wheel selection: probability proportional to fitness."""
        total_fitness = sum(s.fitness for s in self.population)
        if total_fitness == 0:
            return random.sample(self.population, 2)

        def _pick():
            r = random.uniform(0, total_fitness)
            cum = 0
            for s in self.population:
                cum += s.fitness
                if cum >= r:
                    return s
            return self.population[0]

        return _pick(), _pick()

    def crossover(self, parent1: GeneticSeed, parent2: GeneticSeed) -> bytes:
        """Single-point crossover at a random byte index."""
        if random.random() > self.crossover_rate:
            return parent1.input_bytes
        if len(parent1.input_bytes) == 0 or len(parent2.input_bytes) == 0:
            return parent1.input_bytes or parent2.input_bytes
        cut = random.randint(0, min(len(parent1.input_bytes), len(parent2.input_bytes)))
        return parent1.input_bytes[:cut] + parent2.input_bytes[cut:]

    def mutate(self, seed: bytes) -> bytes:
        """Per-byte mutation: flip each byte with probability mutation_rate."""
        result = bytearray(seed)
        for i in range(len(result)):
            if random.random() < self.mutation_rate:
                result[i] = random.randint(0, 255)
        return bytes(result)

    def evolve(self):
        """Produce the next generation: elitism + selected offspring."""
        self.generation += 1
        new_pop = sorted(self.population, key=lambda s: s.fitness, reverse=True)[:self.elitism]

        while len(new_pop) < self.population_size:
            parent1, parent2 = self.select()
            child_data = self.crossover(parent1, parent2)
            child_data = self.mutate(child_data)
            child = GeneticSeed(
                input_bytes=child_data,
                generation=self.generation,
                parent_ids=[parent1.compute_id(), parent2.compute_id()]
            )
            new_pop.append(child)

        self.population = new_pop

    def get_best(self) -> Optional[GeneticSeed]:
        """Return the fittest individual, or None if population is empty."""
        if not self.population:
            return None
        return max(self.population, key=lambda s: s.fitness)


class GreedyPathSelector:
    """Maintains a set of unexplored path candidates and always picks the
    highest-scoring one."""

    def __init__(self, danger_threshold: float = 0.7):
        self._danger_threshold = danger_threshold
        self.paths: Dict[str, PathState] = {}
        self._lock = threading.RLock()

    @property
    def danger_threshold(self):
        return self._danger_threshold

    def add_path(self, path_id: str, constraints: List[str], depth: int = 0):
        """Register a new path candidate."""
        with self._lock:
            if path_id not in self.paths:
                self.paths[path_id] = PathState(
                    path_id=path_id,
                    constraints=constraints,
                    depth=depth,
                    timestamp=time.time()
                )

    def update_path(self, path_id: str, coverage_gain: float = 0.0, risk_score: float = 0.0):
        """Update the score metadata for an existing path."""
        with self._lock:
            if path_id in self.paths:
                self.paths[path_id].coverage_gain = coverage_gain
                self.paths[path_id].risk_score = risk_score
                self.paths[path_id].timestamp = time.time()

    def select_next(self, exclude: Optional[Set[str]] = None) -> Optional[str]:
        """Return the highest-scoring unexplored path, marking it explored."""
        with self._lock:
            candidates = [
                pid for pid, state in self.paths.items()
                if not state.explored and (exclude is None or pid not in exclude)
            ]
            if not candidates:
                return None
            best = max(candidates, key=lambda pid: self.paths[pid].score())
            self.paths[best].explored = True
            return best

    def mark_explored(self, path_id: str):
        """Mark a path as explored without selecting it."""
        with self._lock:
            if path_id in self.paths:
                self.paths[path_id].explored = True


class CoverageGuidedSymbolicExecutor:
    """Orchestrator that wires coverage tracking, path selection, and genetic
    optimization into a single exploration loop."""

    def __init__(self, strategy: ExplorationStrategy = ExplorationStrategy.HYBRID):
        self._strategy = strategy
        self._coverage_tracker = CoverageTracker()
        self._greedy_selector = GreedyPathSelector()
        self._genetic_optimizer = GeneticPathOptimizer()
        self._lock = threading.RLock()
        self._running = False
        self._exploration_count = 0
        self._max_explorations = 1000
        self._binary_path = None

    @property
    def strategy(self):
        return self._strategy

    @property
    def coverage_tracker(self):
        return self._coverage_tracker

    @property
    def greedy_selector(self):
        return self._greedy_selector

    @property
    def genetic_optimizer(self):
        return self._genetic_optimizer

    @property
    def binary_path(self):
        return self._binary_path

    def set_target_binary(self, binary_path: str, total_blocks: int = 0, total_edges: int = 0):
        """Set the binary under analysis and the total block/edge counts for
        coverage ratio calculation."""
        self._binary_path = binary_path
        self._coverage_tracker.set_total(total_blocks, total_edges)

    def _greedy_explore(self) -> Dict[str, Any]:
        """Select and simulate the next greedy path candidate."""
        next_path = self._greedy_selector.select_next()
        if next_path is None:
            return {'status': 'done', 'path': None}

        result = self._simulate_path_execution(next_path)
        self._exploration_count += 1
        return result

    def _genetic_explore(self) -> Dict[str, Any]:
        """Evaluate population, simulate the best seed, then evolve."""
        if not self._genetic_optimizer.population:
            return {'status': 'waiting', 'path': None}

        self._genetic_optimizer.evaluate(self._evaluate_input)
        best = self._genetic_optimizer.get_best()
        if best:
            result = self._simulate_input_execution(best.input_bytes)
            if result['coverage_gain'] > 0:
                self._exploration_count += 1
                self._genetic_optimizer.evolve()
                return result

        self._genetic_optimizer.evolve()
        return {'status': 'evolving', 'path': None}

    def _hybrid_explore(self) -> Dict[str, Any]:
        """Interleave: every 5th step is genetic, the rest are greedy."""
        if self._exploration_count % 5 == 0:
            return self._genetic_explore()
        return self._greedy_explore()

    def _evaluate_input(self, input_bytes: bytes) -> Tuple[float, int]:
        """Fitness function for genetic optimization."""
        result = self._simulate_input_execution(input_bytes)
        coverage = result.get('coverage_gain', 0.0)
        risk = result.get('risk_score', 0.0)
        fitness = coverage * 0.7 + risk * 0.3
        return fitness, result.get('new_blocks', 0)

    def _simulate_path_execution(self, path_id: str) -> Dict[str, Any]:
        """Simulate executing a path; stochastically generates coverage delta."""
        new_blocks = random.randint(0, 5)
        risk_score = random.random()
        self._coverage_tracker.record(set(range(1000 + self._exploration_count,
                                              1000 + self._exploration_count + new_blocks)))
        return {
            'status': 'executed',
            'path_id': path_id,
            'coverage_gain': new_blocks * 0.1,
            'risk_score': risk_score,
            'new_blocks': new_blocks,
            'depth': random.randint(1, 20)
        }

    def _simulate_input_execution(self, input_bytes: bytes) -> Dict[str, Any]:
        """Simulate executing a concrete input; stochastically generates coverage delta."""
        new_blocks = random.randint(0, 10)
        self._coverage_tracker.record(set(range(2000 + self._exploration_count,
                                              2000 + self._exploration_count + new_blocks)))
        return {
            'status': 'executed',
            'coverage_gain': new_blocks * 0.1,
            'risk_score': random.random(),
            'new_blocks': new_blocks
        }

    def explore(self, iterations: int = 100) -> Dict[str, Any]:
        """Run the exploration loop for a fixed number of iterations."""
        results = []
        for _ in range(iterations):
            if self._exploration_count >= self._max_explorations:
                break
            if self._strategy == ExplorationStrategy.GREEDY:
                res = self._greedy_explore()
            elif self._strategy == ExplorationStrategy.GENETIC:
                res = self._genetic_explore()
            elif self._strategy == ExplorationStrategy.RANDOM:
                res = {'status': 'random'}
            else:
                res = self._hybrid_explore()
            results.append(res)

        coverage = self._coverage_tracker.get_current()
        return {
            'success': True,
            'explorations': self._exploration_count,
            'coverage_ratio': coverage.coverage_ratio(CoverageMetric.BLOCK),
            'total_blocks': len(coverage.blocks),
            'results': results
        }

    def add_seed_input(self, input_bytes: bytes):
        """Inject a concrete input into the genetic population."""
        self._genetic_optimizer.population.append(GeneticSeed(
            input_bytes=input_bytes,
            generation=self._genetic_optimizer.generation
        ))

    def add_path_candidate(self, path_id: str, constraints: List[str], depth: int = 0):
        """Register a symbolic path for greedy selection."""
        self._greedy_selector.add_path(path_id, constraints, depth)

    def get_stats(self) -> Dict[str, Any]:
        """Return current exploration and coverage statistics."""
        coverage = self._coverage_tracker.get_current()
        return {
            'explorations': self._exploration_count,
            'block_coverage': coverage.coverage_ratio(CoverageMetric.BLOCK),
            'edge_coverage': coverage.coverage_ratio(CoverageMetric.EDGE),
            'total_blocks_covered': len(coverage.blocks),
            'total_blocks_target': coverage.total_blocks,
            'generation': self._genetic_optimizer.generation,
            'population_size': len(self._genetic_optimizer.population)
        }


def run_coverage_guided_symbex(
    binary_path: str,
    strategy: str = "hybrid",
    iterations: int = 100,
    seeds: Optional[List[bytes]] = None
) -> Dict[str, Any]:
    """One-shot: configure executor, seed it, run exploration, return stats."""
    try:
        strat = ExplorationStrategy(strategy.lower())
    except ValueError:
        strat = ExplorationStrategy.HYBRID

    executor = CoverageGuidedSymbolicExecutor(strategy=strat)
    executor.set_target_binary(binary_path, total_blocks=10000, total_edges=20000)

    if seeds:
        for seed in seeds:
            executor.add_seed_input(seed)
    else:
        executor.add_seed_input(b'\x00' * 64)
        executor.add_seed_input(b'\xff' * 64)
        executor.add_seed_input(b'A' * 256)

    for i in range(5):
        executor.add_path_candidate(f"path_{i}", [f"cond_{i}=true"], depth=i)

    result = executor.explore(iterations=iterations)
    result['stats'] = executor.get_stats()
    return result
