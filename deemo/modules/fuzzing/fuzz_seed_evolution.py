"""遗传算法种子进化引擎。

字节级遗传变异 + 结构感知交叉 + 适应度共享 + 熵引导瞄准 + 模拟退火调度。
核心循环以覆盖率增长驱动种子群体演化，维持探索阶段的种群多样性。
"""

import random
import math
import logging
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from collections import Counter

logger = logging.getLogger(__name__)


class MutationType(str, Enum):
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    INSERT = "insert"
    DELETE = "delete"
    OVERWRITE = "overwrite"
    ARITHMETIC = "arithmetic"
    # 结构感知变异操作
    BLOCK_SWAP = "block_swap"
    BLOCK_DUPLICATE = "block_duplicate"
    SPLICE = "splice"

class SelectionStrategy(str, Enum):
    """2026-08-02: 修正为str,Enum, 与MutationType风格统一。"""
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
    # 字节重要性权重 [0.0, 1.0], 高权重位置变异概率更高
    byte_weights: Optional[List[float]] = field(default=None, repr=False)
    # SHA-256 前16字符指纹, 用于去重与多样性计算
    fingerprint: str = ""
    # 成功触发新覆盖的次数, fitness sharing 使用
    novelty_bonus: int = 0


@dataclass
class GenerationResult:
    generation: int
    best_fitness: float
    average_fitness: float
    best_coverage: int
    population_size: int
    diversity_index: float = 0.0


# 变异操作

class GeneticMutator:

    def __init__(self):
        self._mutation_rates = {
            MutationType.BIT_FLIP: 0.3,
            MutationType.BYTE_FLIP: 0.25,
            MutationType.INSERT: 0.15,
            MutationType.DELETE: 0.1,
            MutationType.OVERWRITE: 0.15,
            MutationType.ARITHMETIC: 0.05,
        }

    def mutate(self, seed: bytes, mutation_rate: float = 0.01,
               byte_weights: Optional[List[float]] = None) -> bytes:
        """对种子逐字节概率变异。有权重时变异位置按权重偏置采样。"""
        data = bytearray(seed)
        mutated = False
        # 权重偏置: 高权重字节以更高有效概率被选中
        if byte_weights and len(byte_weights) == len(data):
            _n = len(data)
            for i in range(_n):
                if i >= len(data):
                    break  # 变异算子可能缩短序列
                bias = byte_weights[i] if i < len(byte_weights) else 0.5
                effective_rate = mutation_rate * (0.5 + bias)
                if random.random() < effective_rate:
                    mutation_type = self._select_mutation_type()
                    data = self._apply_mutation(data, i, mutation_type)
                    mutated = True
        else:
            _n = len(data)
            for i in range(_n):
                if i >= len(data):
                    break  # 变异算子可能缩短序列
                if random.random() < mutation_rate:
                    mutation_type = self._select_mutation_type()
                    data = self._apply_mutation(data, i, mutation_type)
                    mutated = True
        return bytes(data)

    def _select_mutation_type(self) -> MutationType:
        """按预设概率分布轮盘赌选择变异算子类别。"""
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

        elif mutation_type == MutationType.BLOCK_SWAP:
            if len(data) >= 4:
                blk_sz = random.randint(1, min(16, len(data) // 2))
                pos2 = random.randint(0, max(0, len(data) - blk_sz))
                data[index:index + blk_sz], data[pos2:pos2 + blk_sz] = (
                    data[pos2:pos2 + blk_sz], data[index:index + blk_sz]
                )

        elif mutation_type == MutationType.BLOCK_DUPLICATE:
            if index + 1 < len(data):
                blk_sz = random.randint(1, min(8, len(data) - index))
                chunk = data[index:index + blk_sz]
                data[index + blk_sz:index + blk_sz] = chunk

        return data

    def crossover(self, parent1: bytes, parent2: bytes) -> bytes:
        """单点交叉: 随机断点拼接两个父本。空输入直接返回非空一侧。"""
        if len(parent1) == 0 or len(parent2) == 0:
            return parent1 or parent2

        min_len = min(len(parent1), len(parent2))
        crossover_point = random.randint(0, min_len)

        child = parent1[:crossover_point] + parent2[crossover_point:]
        return child

# 结构感知交叉

    def structure_aware_crossover(
        self, parent1: bytes, parent2: bytes,
        chunk_size: int = 8
    ) -> bytes:
        """以chunk_size对齐边界交替拼接两个父本片段。

        适配结构敏感的协议输入。概念出自AFL++ splicing与语法引导变异器。
        """
        if len(parent1) == 0 or len(parent2) == 0:
            return parent1 or parent2
        p1_chunks = [
            parent1[i:i + chunk_size]
            for i in range(0, len(parent1), chunk_size)
        ]
        p2_chunks = [
            parent2[i:i + chunk_size]
            for i in range(0, len(parent2), chunk_size)
        ]
        result = bytearray()
        i = 0
        while i < max(len(p1_chunks), len(p2_chunks)):
            src = p1_chunks if random.random() < 0.5 else p2_chunks
            if i < len(src):
                result.extend(src[i])
            i += 1
        return bytes(result)


# 覆盖评估

class CoverageEvaluator:
    """哈希多样性引导评估器 (非真实覆盖率)。

    真实覆盖率需执行目标二进制并采集 edge/block hit map;
    本实现以 (位置, 字节值) 对的哈希去重计数近似多样性,
    适用于无法执行目标的降级场景。参见 AFL technical paper§4.1 effector map。
    """

    def __init__(self, target_binary: str = None, timeout: int = 5):
        # target_binary 非空时可走真实覆盖率; 当前仅哈希多样性
        self._coverage_map: Dict[int, int] = {}
        self._target_binary = target_binary
        self._timeout = timeout

    def evaluate(self, seed: bytes) -> int:
        """对每个(位置,字节值)对哈希计数, 累加多样性得分。

        目标可执行时, 优先返回真实 edge 覆盖率; 否则降级为哈希多样性引导。
        """
        if self._target_binary:
            try:
                return self._evaluate_real_coverage(seed)
            except Exception:
                pass  # 执行失败时降级为哈希多样性
        coverage = 0
        for i in range(len(seed)):
            hash_val = hash((i, seed[i]))
            self._coverage_map[hash_val] = self._coverage_map.get(hash_val, 0) + 1
            coverage += 1
        return coverage

    def _evaluate_real_coverage(self, seed: bytes) -> int:
        """执行目标二进制并采集 block 覆盖率。

        通过 subprocess 运行目标, 将 seed 经 stdin 注入;
        使用 core.exploit_executor 的 dry-run 通道做语法检查,
        实际覆盖率需 GDB/ptrace 或 AFL fork-server, 此处为降级后占位。
        """
        import subprocess
        import tempfile
        import os as _os
        # 将 seed 写入临时文件后执行目标, 捕获退出码
        with tempfile.NamedTemporaryFile(delete=False, suffix='.seed') as tf:
            tf.write(seed)
            seed_path = tf.name
        try:
            proc = subprocess.run(
                [self._target_binary],
                stdin=open(seed_path, 'rb'),
                capture_output=True,
                timeout=self._timeout,
            )
            # 以退出码非零且有 stderr 输出近似表示触发了新路径
            return len(proc.stderr) if proc.returncode != 0 else 0
        finally:
            _os.unlink(seed_path)

    def get_coverage(self) -> int:
        return len(self._coverage_map)

    def reset(self):
        self._coverage_map.clear()

# 字节级覆盖贡献权重

    def byte_importance_weights(
        self, seed: bytes, prev_seeds: List[bytes]
    ) -> List[float]:
        """按字节稀有度计算重要性权重。

        对每个字节位置i统计该值在历史种子中的出现频次,
        稀有值权重高, 因变异稀有字节更可能触发新执行路径。
        等价于AFL effector map的进化版本。
        """
        if not prev_seeds or not seed:
            return [0.5] * len(seed)
        freq: List[Counter] = [Counter() for _ in seed]
        for ps in prev_seeds:
            for idx, b in enumerate(ps):
                if idx < len(freq):
                    freq[idx][b] += 1
        weights = []
        total_samples = max(1, len(prev_seeds))
        for idx, b in enumerate(seed):
            cnt = freq[idx].get(b, 0)
            # 稀有度 = 1 - 出现频率
            rarity = 1.0 - (cnt / total_samples)
            weights.append(max(0.1, rarity))
        return weights


# 熵引导变异瞄准

class EntropyGuidedMutator:
    """基于局部字节熵的变异瞄准: 高熵区域倾向于数据字段, 命中新路径概率更高。"""

    @staticmethod
    def compute_entropy_profile(data: bytes, window: int = 8) -> List[float]:
        """滑动窗口计算每个字节位置的归一化熵分布 [0, 1]。"""
        if len(data) < window:
            return [0.5] * len(data)
        profile = []
        for i in range(len(data)):
            lo = max(0, i - window // 2)
            hi = min(len(data), i + window // 2)
            w = data[lo:hi]
            cnt = Counter(w)
            total = len(w)
            ent = 0.0
            log2 = math.log2
            for c in cnt.values():
                p = c / total
                ent -= p * log2(p)
            # 最大熵log2(256)=8, 以此为分母归一化
            profile.append(ent / 8.0)
        return profile


# 种子群体

class SeedPopulation:

    def __init__(self, size: int = 100):
        self._population: List[Seed] = []
        self._size = size
        self._mutator = GeneticMutator()
        self._evaluator = CoverageEvaluator()
        # 精英存档: 保存淘汰的高适应度个体供变异素材
        self._archive: List[Seed] = []
        self._entropy_mutator = EntropyGuidedMutator()

    @property
    def seeds(self) -> List[Seed]:
        """当前种群列表只读副本, 兼容外部测试代码引用。"""
        return list(self._population)

    def initialize(self, initial_seeds: Optional[List[bytes]] = None):
        """初始化: 有外部种子直接填充, 否则随机生成至size上限。"""
        if initial_seeds:
            for data in initial_seeds:
                if len(self._population) >= self._size:
                    break
                self._population.append(Seed(
                    data=data,
                    fingerprint=hashlib.sha256(data).hexdigest()[:16]
                ))
        else:
            for _ in range(self._size):
                data = self._generate_random_seed()
                self._population.append(Seed(
                    data=data,
                    fingerprint=hashlib.sha256(data).hexdigest()[:16]
                ))

    def _generate_random_seed(self, min_len: int = 16, max_len: int = 256) -> bytes:
        length = random.randint(min_len, max_len)
        return bytes([random.randint(0, 255) for _ in range(length)])

    def evaluate_population(self):
        """全体种子评估覆盖与适应度, 年龄递增。"""
        for seed in self._population:
            seed.coverage = self._evaluator.evaluate(seed.data)
            seed.fitness = self._calculate_fitness(seed)
            seed.age += 1

    def _calculate_fitness(self, seed: Seed) -> float:
        """适应度 = 覆盖基础分 - 年龄衰减 + 变异经验加成。"""
        base_fitness = seed.coverage
        age_penalty = seed.age * 0.1
        mutation_bonus = seed.mutations * 0.05
        return base_fitness - age_penalty + mutation_bonus

# 适应度共享

    def apply_fitness_sharing(self, sigma_share: float = 5.0):
        """适应度共享: 用Jaccard不相似度度量个体间距离。

        距离 < sigma_share 的两个体视为同生态位, 彼此惩罚。
        niche_count越大原始适应度削弱越多, 抑制快速收敛至局部最优。
        """
        n = len(self._population)
        if n < 2:
            return
        # 每个个体的覆盖哈希集合
        coverage_sets: List[Set[int]] = []
        for seed in self._population:
            cov_set: Set[int] = set()
            if seed.data:
                cov_set = set(hash((i, seed.data[i]))
                              for i in range(len(seed.data)))
            coverage_sets.append(cov_set)

        for i, seed_i in enumerate(self._population):
            niche_count = 0.0
            for j, seed_j in enumerate(self._population):
                if i == j:
                    continue
                si, sj = coverage_sets[i], coverage_sets[j]
                if not si or not sj:
                    distance = float(len(seed_i.data) or 1)
                else:
                    intersection = len(si & sj)
                    union = len(si | sj)
                    jaccard_sim = intersection / union if union > 0 else 0.0
                    distance = 1.0 - jaccard_sim
                if distance < sigma_share:
                    niche_count += max(0.0, 1.0 - distance / sigma_share)
            seed_i.fitness /= (1.0 + niche_count)

# 多样性指数

    def diversity_index(self) -> float:
        """唯一条指纹占群体比例。低于0.3触发精英回注。"""
        fps = {s.fingerprint for s in self._population}
        return len(fps) / max(1, len(self._population))

# 语料蒸馏

    def distill_corpus(self, target_size: int = 30) -> List[Seed]:
        """覆盖贪心语料蒸馏: 选出保持完整覆盖的最小子集。"""
        sorted_pop = sorted(
            self._population, key=lambda s: s.fitness, reverse=True
        )
        coverage_by_seed: List[Set[int]] = []
        for seed in sorted_pop:
            cov_set = set()
            if seed.data:
                for i in range(len(seed.data)):
                    cov_set.add(hash((i, seed.data[i])))
            coverage_by_seed.append(cov_set)
        all_covered: Set[int] = set()
        for cs in coverage_by_seed:
            all_covered.update(cs)
        if not all_covered:
            return sorted_pop[:target_size]
        selected: List[Seed] = []
        remaining = set(all_covered)
        idx = 0
        while remaining and idx < len(sorted_pop) and len(selected) < target_size:
            cs = coverage_by_seed[idx]
            if cs & remaining:
                selected.append(sorted_pop[idx])
                remaining -= cs
            idx += 1
        # 未满额按适应度补齐
        for s in sorted_pop:
            if len(selected) >= target_size:
                break
            if s not in selected:
                selected.append(s)
        return selected

# 选择

    def select(self, strategy: SelectionStrategy = SelectionStrategy.TOURNAMENT) -> List[Seed]:
        if strategy == SelectionStrategy.TOURNAMENT:
            return self._tournament_selection()
        elif strategy == SelectionStrategy.ROULETTE:
            return self._roulette_selection()
        else:
            return self._elitism_selection()

    def _tournament_selection(self, tournament_size: int = 3) -> List[Seed]:
        """锦标赛选择: 每组随机抽k个, 取适应度最高者, 重复至种群规模。"""
        selected = []
        for _ in range(self._size):
            tournament = random.sample(self._population, tournament_size)
            winner = max(tournament, key=lambda s: s.fitness)
            selected.append(winner)
        return selected

    def _roulette_selection(self) -> List[Seed]:
        """轮盘赌选择: 适应度比例抽样, 总适应度为0时均匀随机。"""
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
        """精英选择: 前20%直接保留, 其余均匀随机补齐。

        2025-04-17 fix: 使用实际种群规模n而非self._size, 防k > n的ValueError。
        """
        n = len(self._population)
        if n == 0:
            return []
        elite_count = max(1, n // 5)
        sorted_seeds = sorted(self._population, key=lambda s: s.fitness, reverse=True)
        elites = sorted_seeds[:elite_count]
        if elite_count >= n:
            return elites
        remaining = random.sample(
            sorted_seeds[elite_count:],
            min(n - elite_count, n - elite_count)
        ) if n > elite_count else []
        return elites + remaining

# 演化主循环

    def evolve(self, generations: int = 10,
               selection: SelectionStrategy = SelectionStrategy.TOURNAMENT,
               use_fitness_sharing: bool = True,
               use_entropy_guidance: bool = True,
               use_simulated_annealing: bool = True,
               ) -> List[GenerationResult]:
        """多代演化主循环。

        每代: 评估 -> 适应度共享 -> 选择 -> 交叉 -> 变异 -> 精英保留。
        模拟退火渐变降低变异率以收敛, 熵引导偏置变异位置。
        """
        results = []
        prev_seeds = [s.data for s in self._population]

        # 模拟退火参数
        initial_temperature = 2.0
        cooling_rate = 0.85
        temperature = initial_temperature

        for gen in range(generations):
            self.evaluate_population()

            if use_fitness_sharing and gen > 0:
                self.apply_fitness_sharing(sigma_share=5.0)

            best_seed = max(self._population, key=lambda s: s.fitness)
            avg_fitness = sum(s.fitness for s in self._population) / len(self._population)
            div_idx = self.diversity_index()

            results.append(GenerationResult(
                generation=gen,
                best_fitness=best_seed.fitness,
                average_fitness=avg_fitness,
                best_coverage=best_seed.coverage,
                population_size=len(self._population),
                diversity_index=div_idx
            ))

            # 多样性过低时从存档回注个体
            if div_idx < 0.3 and self._archive:
                inject_count = min(5, len(self._archive))
                for s in random.sample(self._archive, inject_count):
                    if s not in self._population:
                        self._population.append(s)
                self._population = self._population[:self._size]

            selected = self.select(selection)

            new_population = []
            for i in range(0, len(selected), 2):
                parent1 = selected[i]
                parent2 = selected[i + 1] if i + 1 < len(selected) else selected[i]

                # 50%概率使用结构感知交叉
                if random.random() < 0.5:
                    child1_data = self._mutator.structure_aware_crossover(
                        parent1.data, parent2.data
                    )
                else:
                    child1_data = self._mutator.crossover(parent1.data, parent2.data)

                # 字节重要性权重
                w1 = self._evaluator.byte_importance_weights(child1_data, prev_seeds)

                # 熵引导: 融合覆盖重要性与熵分布
                if use_entropy_guidance:
                    entropy_profile = self._entropy_mutator.compute_entropy_profile(
                        child1_data
                    )
                    w1 = [0.6 * w + 0.4 * e for w, e in zip(w1, entropy_profile)]

                # 退火温度调节变异率: 高温阶段更激进
                annealed_rate = min(0.1, max(0.005, 0.01 * temperature))

                child1_data = self._mutator.mutate(child1_data, mutation_rate=annealed_rate,
                                                    byte_weights=w1)
                new_population.append(Seed(
                    data=child1_data, mutations=parent1.mutations + 1,
                    fingerprint=hashlib.sha256(child1_data).hexdigest()[:16],
                    byte_weights=w1,
                ))

                child2_data = self._mutator.crossover(parent2.data, parent1.data)
                w2 = self._evaluator.byte_importance_weights(child2_data, prev_seeds)
                if use_entropy_guidance:
                    ep = self._entropy_mutator.compute_entropy_profile(child2_data)
                    w2 = [0.6 * w + 0.4 * e for w, e in zip(w2, ep)]
                child2_data = self._mutator.mutate(
                    child2_data, mutation_rate=annealed_rate, byte_weights=w2
                )
                new_population.append(Seed(
                    data=child2_data, mutations=parent2.mutations + 1,
                    fingerprint=hashlib.sha256(child2_data).hexdigest()[:16],
                    byte_weights=w2,
                ))

            # 精英保留: 前5%直接进入下一代
            elite_count = max(1, self._size // 20)
            sorted_old = sorted(self._population, key=lambda s: s.fitness, reverse=True)
            elites = sorted_old[:elite_count]
            for e in elites:
                if e not in self._archive:
                    self._archive.append(e)
            # 存档裁剪至2倍种群容量
            if len(self._archive) > self._size * 3:
                self._archive = sorted(
                    self._archive, key=lambda s: s.fitness, reverse=True
                )[:self._size * 2]

            self._population = elites + new_population[:(self._size - elite_count)]
            prev_seeds = [s.data for s in self._population]

            if use_simulated_annealing:
                temperature *= cooling_rate

        return results

    def get_best_seeds(self, count: int = 10) -> List[Seed]:
        """按适应度降序返回前count个种子。"""
        sorted_seeds = sorted(self._population, key=lambda s: s.fitness, reverse=True)
        return sorted_seeds[:count]

# 蒸馏后最优种子

    def get_distilled_best(self, count: int = 10) -> List[Seed]:
        """先蒸馏再按适应度降序截取, 兼顾覆盖与种子质量。"""
        distilled = self.distill_corpus(target_size=max(count * 2, 20))
        return sorted(distilled, key=lambda s: s.fitness, reverse=True)[:count]


def evolve_seeds(initial_seeds: List[bytes], generations: int = 10,
                 use_annealing: bool = True) -> List[bytes]:
    """顶层便捷入口: 基于初始种子执行进化并返回最佳种子数据。"""
    population = SeedPopulation(size=100)
    population.initialize(initial_seeds)
    population.evolve(
        generations,
        use_simulated_annealing=use_annealing,
        use_fitness_sharing=True,
        use_entropy_guidance=True,
    )

    best_seeds = population.get_best_seeds(count=20)
    return [seed.data for seed in best_seeds]
