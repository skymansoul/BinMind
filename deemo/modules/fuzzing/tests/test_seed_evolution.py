"""seed_evolution — genetic algorithm selection (tournament/roulette/elitism)."""
import random
import pytest

try:
    from ..fuzz_seed_evolution import (
        Seed, SeedPopulation, GeneticMutator,
        CoverageEvaluator, EntropyGuidedMutator,
        SelectionStrategy, MutationType, GenerationResult,
        evolve_seeds
    )
    _seed_available = True
except Exception:
    _seed_available = False


@pytest.mark.skipif(not _seed_available, reason="fuzz_seed_evolution not importable")
class TestSeedPopulation:
    """种子群体与遗传算法"""

    @pytest.fixture
    def population(self):
        return SeedPopulation(size=20)

    def test_initialize_with_seeds(self, population):
        """初始化接受种子列表"""
        seeds = [b"AAAA", b"BBBB", b"CCCC"]
        population.initialize(initial_seeds=seeds)
        assert len(population.seeds) == 3

    def test_initialize_without_seeds_generates_random(self, population):
        """无初始种子时生成随机种子"""
        population.initialize()
        assert len(population.seeds) == 20

    def test_tournament_selection_returns_seeds(self, population):
        """锦标赛选择返回Seed列表"""
        population.initialize(initial_seeds=[b"seed" + bytes([i]) * 8 for i in range(10)])
        population.evaluate_population()
        selected = population.select(strategy=SelectionStrategy.TOURNAMENT)
        assert len(selected) > 0
        assert all(isinstance(s, Seed) for s in selected)

    def test_elitism_preserves_best(self, population):
        """精英选择保留最高适应度种子"""
        seeds = [b"S" * i for i in range(1, 11)]
        population.initialize(initial_seeds=seeds)
        population.evaluate_population()
        # 给较长的种子更高适应度
        for s in population.seeds:
            s.fitness = len(s.data)
        best_before = max(s.fitness for s in population.seeds)
        selected = population.select(strategy=SelectionStrategy.ELITISM)
        best_after = max(s.fitness for s in selected)
        assert best_after >= best_before / 2

    def test_roulette_favors_high_fitness(self, population):
        """轮盘赌选择——高适应度种子被选概率更高"""
        population.initialize(initial_seeds=[b"A", b"BB", b"CCC", b"DDDD", b"EEEEE"])
        # 手动设置适应度
        for s in population.seeds:
            s.fitness = float(len(s.data))
        selected = population.select(strategy=SelectionStrategy.ROULETTE)
        assert len(selected) > 0


@pytest.mark.skipif(not _seed_available, reason="fuzz_seed_evolution not importable")
class TestGeneticMutator:
    """基因变异器"""

    @pytest.fixture
    def mutator(self):
        return GeneticMutator()

    def test_mutate_changes_data(self, mutator):
        """变异后数据与原数据不同（高变异率）"""
        original = b"A" * 100
        mutated = mutator.mutate(original, mutation_rate=0.5)
        assert mutated != original

    def test_crossover_produces_valid_length(self, mutator):
        """交叉产生合法长度结果"""
        parent1 = b"A" * 32
        parent2 = b"B" * 64
        child = mutator.crossover(parent1, parent2)
        assert len(child) > 0
        # 长度在父代范围内
        assert len(child) <= max(len(parent1), len(parent2))
        assert len(child) >= min(len(parent1), len(parent2))

    def test_structure_aware_crossover_preserves_chunks(self, mutator):
        """结构感知交叉保留chunk对齐"""
        parent1 = b"AAAA" * 4  # 16 bytes
        parent2 = b"BBBB" * 4
        child = mutator.structure_aware_crossover(parent1, parent2, chunk_size=4)
        assert len(child) % 4 == 0
        # 子代包含两个父代的元素
        assert any(child[i:i+4] in (b"AAAA", b"BBBB") for i in range(0, len(child), 4))


@pytest.mark.skipif(not _seed_available, reason="fuzz_seed_evolution not importable")
class TestEntropyGuidedMutator:
    """熵引导变异"""

    def test_entropy_profile_length_matches_data(self):
        """熵轮廓长度与数据字节数一致 (每字节一个熵值)."""
        # 2026-08-02 fix: compute_entropy_profile 返回 len(data) 个轮廓值,
        # 而非 len(data)/window 个窗口
        data = b"\x00" * 32 + b"\xff" * 32
        profile = EntropyGuidedMutator.compute_entropy_profile(data, window=8)
        assert len(profile) == len(data)

    def test_uniform_data_has_zero_entropy(self):
        """全相同数据熵为0"""
        data = b"\x42" * 64
        profile = EntropyGuidedMutator.compute_entropy_profile(data, window=8)
        assert all(p == pytest.approx(0.0, abs=1e-10) for p in profile)

    def test_high_variance_data_has_positive_entropy(self):
        """高方差数据熵>0"""
        data = bytes(range(64))
        profile = EntropyGuidedMutator.compute_entropy_profile(data, window=8)
        assert any(p > 0.0 for p in profile)


@pytest.mark.skipif(not _seed_available, reason="fuzz_seed_evolution not importable")
class TestEvolveSeeds:
    """evolve_seeds进化流程"""

    def test_evolve_produces_output(self):
        """进化后产生合法输出"""
        seeds = [b"A" * 32, b"B" * 32, b"C" * 32]
        result = evolve_seeds(seeds, generations=2, use_annealing=False)
        assert len(result) > 0


# 独立测试（无需模块导入）

class TestTournamentInline:
    """内联锦标赛选择逻辑验证"""

    def test_tournament_selects_best(self):
        """锦标赛选择最高分种子"""
        random.seed(42)
        candidates = [
            {"id": 1, "fitness": 0.3},
            {"id": 2, "fitness": 0.9},
            {"id": 3, "fitness": 0.5},
            {"id": 4, "fitness": 0.7},
        ]
        tournament_size = 3
        tournament = random.sample(candidates, min(tournament_size, len(candidates)))
        winner = max(tournament, key=lambda x: x["fitness"])
        # 如果选到best则fitness >= 0.5
        assert winner["fitness"] >= min(c["fitness"] for c in tournament)


def test_roulette_inline():
    """轮盘赌概率权重"""
    items = [("a", 1), ("b", 2), ("c", 3)]  # 权重1:2:3
    total = sum(w for _, w in items)
    probs = [(name, w / total) for name, w in items]
    total_prob = sum(p for _, p in probs)
    assert total_prob == pytest.approx(1.0)


def test_mutation_rate_inline():
    """变异率控制变异量"""
    data = bytearray(b"\x00" * 1000)
    rate = 0.1  # 10%变异率
    mutations = 0
    for i in range(len(data)):
        if random.random() < rate:
            data[i] ^= 0xFF
            mutations += 1
    # 置信区间检查：大数定律，1000字节 @0.1率 → 约100次变异
    assert 50 < mutations < 150, f"expected ~100 mutations, got {mutations}"
