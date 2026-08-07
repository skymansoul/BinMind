# 修改记录:
# 2025-08-05 09:33 — 初始实现：适应度导向的 bypass 发现引擎
# 2025-08-06 11:19 — 引入模拟退火调度：搜索能量随迭代衰减
# 2025-08-07 17:14 — 群体多样性退化检测 + 再播种机制

"""Adversarial Bypass Finder — 针对二进制补丁的对抗输入发现。

目标：找到能绕过二进制补丁安全检查的输入。这不是 Crash fuzzing——
目标是找到补丁未覆盖的边界情况。

算法：Adaptive Fitness-Guided Search (AFGS)
  1. 从种子池生成初始输入（SeedGenerator from diff_exec）
  2. 对每个输入在 patched binary 上执行，收集 ExecutionTrace
  3. 计算复合适应度 F(x) = α·proximity + β·boundary + γ·diversity
  4. 选取 top-k 进行约束导向变异
  5. 模拟退火能量衰减：迭代中降低随机性
  6. 检测群体多样性退化，触发再播种
  7. 返回疑似 bypass 的输入集合及其适应度评分

与 cozy 的差异：
  cozy 使用比较符号执行（angr）对比 pre/post binary 的语义差异。
  本模块使用 concrete execution + 补丁感知适应度，不需要符号执行环境。
  代价是路径覆盖不如符号执行完整，收益是在实际 binary 上可运行
  （不需要符号执行的条件：无反编译、无 source）。

与 AFL++ 的差异：
  AFL++ 的目标是最大化 edge coverage（crash 发现）。
  本模块的目标是最大化 patch boundary proximity（bypass 发现）。
  两者可以组合：AFL++ 做通用 fuzzing，本模块做 bypass 专项搜索。
"""

import os
import time
import logging
import hashlib
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable

from .bypass_fitness import (
    PatchSite, ExecutionTrace, BypassFitness, BypassFitnessEvaluator,
)
from .constraint_guided_mutator import (
    ConstraintGuidedMutator, ConstraintExtractor, ConstraintHint,
)
from .differential_executor import (
    SeedGenerator, InputMutator, ExecutionSnapshot,
)

_log = logging.getLogger(__name__)


@dataclass
class BypassCandidate:
    """单个 bypass 候选输入。"""
    input_data: bytes
    input_label: str
    fitness: BypassFitness
    trace: ExecutionTrace
    generation: int = 0
    parent_label: str = "seed"

    @property
    def is_high_risk(self) -> bool:
        """适应度 > 0.7 标记为高风险 bypass。"""
        return self.fitness.composite > 0.7


@dataclass
class BypassDiscoveryReport:
    """Bypass 发现完整报告。"""
    patch_id: str = ""
    patched_binary: str = ""
    total_iterations: int = 0
    total_inputs_tested: int = 0
    total_generations: int = 0
    candidates: List[BypassCandidate] = field(default_factory=list)
    high_risk_count: int = 0
    best_fitness: float = 0.0
    elapsed_seconds: float = 0.0
    population_diversity: float = 0.0  # 最终群体多样性
    restarts: int = 0                  # 再播种次数
    verdict: str = ""                  # "bypass_found" | "no_bypass_found" | "inconclusive"

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'binary': self.patched_binary,
            'iterations': self.total_iterations,
            'inputs_tested': self.total_inputs_tested,
            'generations': self.total_generations,
            'candidates': len(self.candidates),
            'high_risk': self.high_risk_count,
            'best_fitness': round(self.best_fitness, 4),
            'elapsed_seconds': round(self.elapsed_seconds, 1),
            'diversity': round(self.population_diversity, 4),
            'restarts': self.restarts,
            'verdict': self.verdict,
            'top_bypasses': [
                {
                    'label': c.input_label,
                    'fitness': c.fitness.to_dict(),
                    'generation': c.generation,
                    'hash': hashlib.sha256(c.input_data).hexdigest()[:16],
                }
                for c in self.candidates[:10]
            ],
        }


# 执行迹收集

class TraceCollector:
    """从 patched binary 执行中收集轻量 ExecutionTrace。

    通过动态插桩（pin / dynamorio / Frida）或静态插桩（重编译时插入）
    收集 hit 的基本块和指令地址。

    当前实现：通过子进程 + 调试器后端的简化收集。
    生产环境替换为 PIN tool 或 DynamoRIO client。
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def collect(self, binary_path: str, input_data: bytes) -> ExecutionTrace:
        """执行 binary 并收集 trace。
        当前为桩实现 — 生产环境替换为 PIN/DynamoRIO。
        """
        trace = ExecutionTrace()

        # 简化：通过 strace 收集 syscall 序列
        # 完整的 BB coverage 需通过 PIN tool 实现
        try:
            proc = subprocess.run(
                ['strace', '-f', '-e', 'trace=all', '-o', '/dev/stderr',
                 binary_path],
                input=input_data, capture_output=True,
                timeout=self.timeout_ms / 1000.0)
            trace.exit_code = proc.returncode

            # 从 strace 输出解析 syscall 序列（如果可用）
            if proc.stderr:
                for line in proc.stderr.decode('utf-8', errors='replace').split('\n')[:100]:
                    if '(' in line:
                        syscall_name = line.split('(')[0].strip()
                        if syscall_name and not syscall_name.startswith('['):
                            trace.syscall_sequence.append(syscall_name)

            # 通过 coverage 反馈机制可以收集 BB hits
            # 此处保留接口，实际集成通过 shared memory (AFL 式 bitmap) 完成

        except subprocess.TimeoutExpired:
            trace.exit_code = -2
        except FileNotFoundError:
            trace.exit_code = -3

        trace.coverage_bitmap_hash = hashlib.md5(
            str(trace.syscall_sequence).encode()).hexdigest()[:12]
        return trace


# AFGS 搜索引擎

class AdversarialBypassFinder:
    """Adaptive Fitness-Guided Search — 补丁绕过发现。

    用法:
        finder = AdversarialBypassFinder(binary_path, patch_sites)
        report = finder.search(max_iterations=100, population_size=20)
        for c in report.candidates:
            if c.is_high_risk:
                print(f"高危 bypass: {c.input_label}, fitness={c.fitness.composite:.3f}")
    """

    def __init__(self, binary_path: str,
                 patch_sites: List[PatchSite],
                 patch_id: str = ""):
        self._binary = binary_path
        self._patch_sites = patch_sites
        self._patch_id = patch_id or hashlib.sha256(binary_path.encode()).hexdigest()[:8]

        self._seed_gen = SeedGenerator(seed=42)
        self._legacy_mutator = InputMutator(seed=7)
        self._constraint_mutator = ConstraintGuidedMutator(seed=11)
        self._fitness_eval = BypassFitnessEvaluator(alpha=0.45, beta=0.40, gamma=0.15)
        self._trace_collector = TraceCollector(timeout_ms=5000)

        # 从补丁提取约束给约束变异器
        constraint_ext = ConstraintExtractor()
        hints = constraint_ext.extract(patch_sites)
        self._constraint_mutator.set_hints(self._patch_id, hints)

        self._population: List[BypassCandidate] = []
        self._best: Optional[BypassCandidate] = None
        self._generation = 0
        self._restarts = 0

# 主搜索循环

    def search(self, max_iterations: int = 100,
               population_size: int = 20,
               elite_size: int = 4,
               restart_threshold: float = 0.02,
               fitness_threshold: float = 0.7,
               progress_callback: Callable = None) -> BypassDiscoveryReport:
        """主搜索入口。

        restart_threshold: 群体多样性低于此值时触发再播种
        fitness_threshold: 适应度超过此值即可停止搜索（找到高可信 bypass）
        """
        t_start = time.monotonic()
        total_tested = 0

        # 阶段 1: 种子初始化
        seeds = self._seed_gen.generate(n_edge=8, n_random=population_size - 8)
        self._population = []
        for label, data in seeds:
            trace = self._trace_collector.collect(self._binary, data)
            fitness = self._fitness_eval.evaluate(data, label, trace, self._patch_sites)
            candidate = BypassCandidate(
                input_data=data, input_label=label,
                fitness=fitness, trace=trace, generation=0)
            self._population.append(candidate)
            total_tested += 1

        self._sort_population()
        self._best = self._population[0] if self._population else None

        # 阶段 2: 迭代搜索
        for iteration in range(max_iterations):
            self._generation = iteration + 1

            # 模拟退火能量衰减
            energy = max(0.05, 1.0 - (iteration / max_iterations))
            self._constraint_mutator.set_energy(energy)

            # 选择亲本（top-k 精英 + 抽样）
            parents = self._select_parents(elite_size, population_size // 2)

            # 生成子代
            offspring: List[BypassCandidate] = []
            for parent in parents:
                variants = self._constraint_mutator.mutate(
                    parent.input_data, self._patch_id, n_variants=4)
                for vlabel, vdata in variants:
                    trace = self._trace_collector.collect(self._binary, vdata)
                    fitness = self._fitness_eval.evaluate(
                        vdata, vlabel, trace, self._patch_sites)
                    child = BypassCandidate(
                        input_data=vdata, input_label=vlabel,
                        fitness=fitness, trace=trace,
                        generation=self._generation,
                        parent_label=parent.input_label)
                    offspring.append(child)
                    total_tested += 1

            # 合并 + 存活选择
            combined = self._population + offspring
            self._sort_population(combined)
            self._population = combined[:population_size]

            # 更新最佳
            if self._population and (not self._best or
                self._population[0].fitness.composite > self._best.fitness.composite):
                self._best = self._population[0]

            # 早停检查
            if self._best and self._best.fitness.composite >= fitness_threshold:
                _log.info("BypassFinder: 达到适应度阈值 %.3f，停止搜索",
                          self._best.fitness.composite)
                break

            # 多样性退化检测 → 再播种
            diversity = self._compute_diversity()
            if diversity < restart_threshold:
                self._restarts += 1
                fresh_seeds = self._seed_gen.generate(
                    n_edge=4, n_random=population_size // 3)
                fresh_candidates = []
                for label, data in fresh_seeds:
                    trace = self._trace_collector.collect(self._binary, data)
                    fitness = self._fitness_eval.evaluate(
                        data, label, trace, self._patch_sites)
                    fresh_candidates.append(BypassCandidate(
                        input_data=data, input_label=label,
                        fitness=fitness, trace=trace, generation=self._generation))
                # 替换种群中适应度最低的个体
                self._population = self._population[:-len(fresh_candidates)] + fresh_candidates
                self._sort_population()
                total_tested += len(fresh_candidates)
                _log.info("BypassFinder: 多样性退化 (%s%.4f)，再播种 %d 个体",
                          '<', diversity, len(fresh_candidates))

            if progress_callback:
                progress_callback(iteration + 1, max_iterations,
                                  self._best.fitness.composite if self._best else 0.0)

        # 生成报告
        elapsed = time.monotonic() - t_start
        high_risk = [c for c in self._population if c.is_high_risk]

        if len(high_risk) >= 3:
            verdict = "bypass_found"
        elif len(high_risk) >= 1:
            verdict = "potential_bypass"
        elif self._best and self._best.fitness.composite > 0.4:
            verdict = "inconclusive"
        else:
            verdict = "no_bypass_found"

        report = BypassDiscoveryReport(
            patch_id=self._patch_id,
            patched_binary=self._binary,
            total_iterations=min(self._generation, max_iterations),
            total_inputs_tested=total_tested,
            total_generations=self._generation,
            candidates=high_risk if high_risk else (
                self._population[:5] if self._population else []),
            high_risk_count=len(high_risk),
            best_fitness=self._best.fitness.composite if self._best else 0.0,
            elapsed_seconds=elapsed,
            population_diversity=self._compute_diversity(),
            restarts=self._restarts,
            verdict=verdict,
        )
        _log.info("BypassFinder: 搜索完成，verdict=%s, best=%.4f, 测试=%d",
                  verdict, report.best_fitness, total_tested)
        return report

    def quick_scan(self, n_seeds: int = 30) -> BypassDiscoveryReport:
        """快速扫描模式 — 仅在初始种子池中评估，不进行迭代搜索。"""
        t_start = time.monotonic()
        seeds = self._seed_gen.generate(n_edge=8, n_random=n_seeds - 8)
        for label, data in seeds:
            trace = self._trace_collector.collect(self._binary, data)
            fitness = self._fitness_eval.evaluate(data, label, trace, self._patch_sites)
            self._population.append(BypassCandidate(
                input_data=data, input_label=label,
                fitness=fitness, trace=trace, generation=0))

        self._sort_population()
        self._best = self._population[0] if self._population else None

        high_risk = [c for c in self._population if c.is_high_risk]
        elapsed = time.monotonic() - t_start

        return BypassDiscoveryReport(
            patch_id=self._patch_id,
            patched_binary=self._binary,
            total_iterations=1,
            total_inputs_tested=n_seeds,
            total_generations=0,
            candidates=high_risk if high_risk else self._population[:5],
            high_risk_count=len(high_risk),
            best_fitness=self._best.fitness.composite if self._best else 0.0,
            elapsed_seconds=elapsed,
            population_diversity=self._compute_diversity(),
            verdict="bypass_found" if high_risk else "inconclusive",
        )

# 内部方法

    def _select_parents(self, elite_size: int = 4,
                        extra_count: int = 8) -> List[BypassCandidate]:
        """精英选择 + 适应度比例抽样（轮盘赌）。"""
        if not self._population:
            return []

        sorted_pop = sorted(self._population,
                           key=lambda c: c.fitness.composite, reverse=True)
        elite = sorted_pop[:elite_size]

        # 适应度比例抽样
        remaining = sorted_pop[elite_size:]
        if len(remaining) <= extra_count:
            return elite + remaining

        fits = [c.fitness.composite + 0.01 for c in remaining]
        total_fit = sum(fits)
        if total_fit == 0:
            return elite + remaining[:extra_count]

        probs = [f / total_fit for f in fits]
        selected = []
        chosen_indices = set()
        import random as _random_module
        while len(selected) < extra_count and len(chosen_indices) < len(remaining):
            r = _random_module.random()
            cumulative = 0.0
            for i, p in enumerate(probs):
                cumulative += p
                if r <= cumulative and i not in chosen_indices:
                    selected.append(remaining[i])
                    chosen_indices.add(i)
                    break
        return elite + selected

    def _sort_population(self, pop=None):
        """按适应度降序排序。"""
        target = pop if pop is not None else self._population
        if target:
            target.sort(key=lambda c: c.fitness.composite, reverse=True)

    def _compute_diversity(self) -> float:
        """计算群体适应度的变异系数 (CV = σ/μ)。

        CV 越低 → 群体越同质 → 需要再播种。
        """
        if len(self._population) < 3:
            return 1.0
        fits = [c.fitness.composite for c in self._population]
        mu = sum(fits) / len(fits)
        if mu == 0:
            return 0.0
        variance = sum((f - mu) ** 2 for f in fits) / len(fits)
        return (variance ** 0.5) / mu


# 便捷函数

def find_patch_bypasses(binary_path: str,
                        patch_sites: List[PatchSite],
                        max_iterations: int = 100,
                        quick: bool = False) -> BypassDiscoveryReport:
    """一键 bypass 搜索。"""
    finder = AdversarialBypassFinder(binary_path, patch_sites)
    if quick:
        return finder.quick_scan()
    return finder.search(max_iterations=max_iterations)
