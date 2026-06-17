"""
增量模糊测试种子进化模块

功能：
1. 基于遗传算法的种子变异
2. 覆盖率引导的种子选择
3. 自适应变异策略

核心组件：
- SeedPopulation: 种子种群
- GeneticMutator: 遗传变异器
- CoverageEvaluator: 覆盖率评估器
"""

import os
import random
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MutationType(Enum):
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    INSERT = "insert"
    DELETE = "delete"
    OVERWRITE = "overwrite"
    ARITHMETIC = "arithmetic"


class SelectionStrategy(Enum):
    ROULETTE = "roulette"
    TOURNAMENT = "tournament"
    ELITISM = "elitism"


@dataclass
class Seed:
    data: bytes
    coverage: int = 0
    fitness: float = 0.0
    age: int = 0
    mutations: int = 0


@dataclass
class GenerationResult:
    generation: int
    best_fitness: float
    average_fitness: float
    best_coverage: int
    population_size: int


class GeneticMutator:

    def __init__(self):
        self._mutation_rates = {
            MutationType.BIT_FLIP: 0.3,
            MutationType.BYTE_FLIP: 0.25,
            MutationType.INSERT: 0.15,
            MutationType.DELETE: 0.1,
            MutationType.OVERWRITE: 0.15,
            MutationType.ARITHMETIC: 0.05
        }

    def mutate(self, seed: bytes, mutation_rate: float = 0.01) -> bytes:
        data = bytearray(seed)
        mutated = False
        
        for i in range(len(data)):
            if random.random() < mutation_rate:
                mutation_type = self._select_mutation_type()
                data = self._apply_mutation(data, i, mutation_type)
                mutated = True
        
        return bytes(data)

    def _select_mutation_type(self) -> MutationType:
        r = random.random()
        cumulative = 0.0
        for mutation_type, rate in self._mutation_rates.items():
            cumulative += rate
            if r < cumulative:
                return mutation_type
        return MutationType.BIT_FLIP

    def _apply_mutation(self, data: bytearray, index: int, mutation_type: MutationType) -> bytearray:
        if mutation_type == MutationType.BIT_FLIP:
            data[index] ^= 1 << random.randint(0, 7)
        
        elif mutation_type == MutationType.BYTE_FLIP:
            data[index] = random.randint(0, 255)
        
        elif mutation_type == MutationType.INSERT:
            data.insert(index, random.randint(0, 255))
        
        elif mutation_type == MutationType.DELETE and len(data) > 1:
            del data[index]
        
        elif mutation_type == MutationType.OVERWRITE:
            if index + 4 <= len(data):
                data[index:index+4] = random.getrandbits(32).to_bytes(4, 'little')
        
        elif mutation_type == MutationType.ARITHMETIC:
            delta = random.randint(-16, 16)
            data[index] = (data[index] + delta) & 0xFF
        
        return data

    def crossover(self, parent1: bytes, parent2: bytes) -> bytes:
        if len(parent1) == 0 or len(parent2) == 0:
            return parent1 or parent2
        
        min_len = min(len(parent1), len(parent2))
        crossover_point = random.randint(0, min_len)
        
        child = parent1[:crossover_point] + parent2[crossover_point:]
        return child


class CoverageEvaluator:

    def __init__(self):
        self._coverage_map: Dict[int, int] = {}

    def evaluate(self, seed: bytes) -> int:
        coverage = 0
        
        for i in range(len(seed)):
            hash_val = hash((i, seed[i]))
            self._coverage_map[hash_val] = self._coverage_map.get(hash_val, 0) + 1
            coverage += 1
        
        return coverage

    def get_coverage(self) -> int:
        return len(self._coverage_map)

    def reset(self):
        self._coverage_map.clear()


class SeedPopulation:

    def __init__(self, size: int = 100):
        self._population: List[Seed] = []
        self._size = size
        self._mutator = GeneticMutator()
        self._evaluator = CoverageEvaluator()

    def initialize(self, initial_seeds: Optional[List[bytes]] = None):
        if initial_seeds:
            for data in initial_seeds:
                if len(self._population) >= self._size:
                    break
                self._population.append(Seed(data=data))
        else:
            for _ in range(self._size):
                data = self._generate_random_seed()
                self._population.append(Seed(data=data))

    def _generate_random_seed(self, min_len: int = 16, max_len: int = 256) -> bytes:
        length = random.randint(min_len, max_len)
        return bytes([random.randint(0, 255) for _ in range(length)])

    def evaluate_population(self):
        for seed in self._population:
            seed.coverage = self._evaluator.evaluate(seed.data)
            seed.fitness = self._calculate_fitness(seed)
            seed.age += 1

    def _calculate_fitness(self, seed: Seed) -> float:
        base_fitness = seed.coverage
        age_penalty = seed.age * 0.1
        mutation_bonus = seed.mutations * 0.05
        return base_fitness - age_penalty + mutation_bonus

    def select(self, strategy: SelectionStrategy = SelectionStrategy.TOURNAMENT) -> List[Seed]:
        if strategy == SelectionStrategy.TOURNAMENT:
            return self._tournament_selection()
        elif strategy == SelectionStrategy.ROULETTE:
            return self._roulette_selection()
        else:
            return self._elitism_selection()

    def _tournament_selection(self, tournament_size: int = 3) -> List[Seed]:
        selected = []
        for _ in range(self._size):
            tournament = random.sample(self._population, tournament_size)
            winner = max(tournament, key=lambda s: s.fitness)
            selected.append(winner)
        return selected

    def _roulette_selection(self) -> List[Seed]:
        total_fitness = sum(seed.fitness for seed in self._population)
        if total_fitness == 0:
            return random.sample(self._population, self._size)
        
        selected = []
        for _ in range(self._size):
            r = random.random() * total_fitness
            cumulative = 0.0
            for seed in self._population:
                cumulative += seed.fitness
                if cumulative >= r:
                    selected.append(seed)
                    break
        return selected

    def _elitism_selection(self) -> List[Seed]:
        sorted_seeds = sorted(self._population, key=lambda s: s.fitness, reverse=True)
        elites = sorted_seeds[:int(self._size * 0.2)]
        remaining = random.sample(sorted_seeds[int(self._size * 0.2):], 
                                self._size - len(elites))
        return elites + remaining

    def evolve(self, generations: int = 10) -> List[GenerationResult]:
        results = []
        
        for gen in range(generations):
            self.evaluate_population()
            
            best_seed = max(self._population, key=lambda s: s.fitness)
            avg_fitness = sum(s.fitness for s in self._population) / len(self._population)
            
            results.append(GenerationResult(
                generation=gen,
                best_fitness=best_seed.fitness,
                average_fitness=avg_fitness,
                best_coverage=best_seed.coverage,
                population_size=len(self._population)
            ))
            
            selected = self.select()
            
            new_population = []
            for i in range(0, len(selected), 2):
                parent1 = selected[i]
                parent2 = selected[i + 1] if i + 1 < len(selected) else selected[i]
                
                child1_data = self._mutator.crossover(parent1.data, parent2.data)
                child1_data = self._mutator.mutate(child1_data)
                new_population.append(Seed(data=child1_data, mutations=parent1.mutations + 1))
                
                child2_data = self._mutator.crossover(parent2.data, parent1.data)
                child2_data = self._mutator.mutate(child2_data)
                new_population.append(Seed(data=child2_data, mutations=parent2.mutations + 1))
            
            self._population = new_population[:self._size]
        
        return results

    def get_best_seeds(self, count: int = 10) -> List[Seed]:
        sorted_seeds = sorted(self._population, key=lambda s: s.fitness, reverse=True)
        return sorted_seeds[:count]


def evolve_seeds(initial_seeds: List[bytes], generations: int = 10) -> List[bytes]:
    population = SeedPopulation(size=100)
    population.initialize(initial_seeds)
    population.evolve(generations)
    
    best_seeds = population.get_best_seeds(count=20)
    return [seed.data for seed in best_seeds]