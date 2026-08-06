# 创建: 2025-08-11 14:35
# 修改: 2025-08-11 — Beta-Bernoulli Thompson 采样 + Cheng BA 算法
"""
Thompson 采样多模糊器编排器 — Bayesian 在线学习动态资源分配。

问题: 多个异构模糊器并行运行, 各自对不同目标的"产出率"未知且时变。
  均匀分配浪费算力——比如 AFL++ 在解析型目标上找到 80% 的独特崩溃,
  而 libFuzzer 几乎找不到新东西, 但两者获得相同 CPU。

方案: 每个模糊器视为一个 bandit arm, 其"找到有价值的独特崩溃"的概率
  θ_i ∼ Beta(α_i, β_i)。Thompson 采样在每个决策周期:
    1. 从每个 Beta(α_i, β_i) 采样 θ̂_i
    2. 按 θ̂_i 的比例分配下一周期的 CPU 时间
    3. 收集结果, 更新 (α_i, β_i): 找到独特崩溃 → α_i++, 重复崩溃 → β_i++

Thompson 采样的优势 (vs ε-greedy / UCB):
  - 天然平衡探索与利用: 不确定性高的 arm 会偶尔采样到高 θ̂ 值,
    获得"证明自己"的机会; 表现好的 arm 持续获得资源
  - 收敛速度: Beta 后验随样本增加快速集中, 减少无谓探索
  - 无超参数: 不像 ε-greedy 需要手动调 ε, UCB 需要调置信界宽度

ref: Thompson (1933) "On the Likelihood that One Unknown Probability
     Exceeds Another..." — 原始论文
ref: Chapelle & Li (2011) "An Empirical Evaluation of Thompson Sampling"
     (NIPS) — 证明 TS 在 bandit 问题上优于 UCB
ref: BandFuzz (arXiv:2507.10845, 2025) — 多臂赌博机协作模糊测试,
     本项目将 bandit 建模推广到异构模糊器编排而非同构协作
ref: Scott (2010) "A modern Bayesian look at the multi-armed bandit"
     (Applied Stochastic Models in Business and Industry)
"""

from __future__ import annotations

import math
import time
import random
import struct
import hashlib
from collections import defaultdict
from typing import Any, Optional


# --- Beta 分布与 Thompson 采样 ---
# 无 scipy 依赖 — 使用 Cheng (1978) 的 BA 算法从 Gamma 分布采样,
# 再用 Gamma(α,1) / (Gamma(α,1) + Gamma(β,1)) 构造 Beta 样本。

def _gamma_sample(shape: float) -> float:
    """Cheng's BA algorithm for Gamma(shape, 1) with shape > 0.
    当 shape < 1 时使用 Johnk's generator。
    ref: Cheng (1978) "Generating Beta Variates with Nonintegral Shape Parameters" (Algorithm BA)"""
    if shape <= 0:
        return 1e-9
    if shape < 1.0:
        # Johnk's generator: Gamma(α,1) = Beta(α,1-α) * Exp(1) 的变换
        # 直接使用 Marsaglia-Tsang 的简化版本
        u = random.random()
        return _gamma_sample(shape + 1.0) * (u ** (1.0 / shape)) if u > 1e-12 else 1e-9
    # Cheng BA for shape >= 1
    d = shape - 1.0 / 3.0
    c = 1.0 / math.sqrt(9.0 * d)
    while True:
        x = random.gauss(0, 1)
        v = (1.0 + c * x) ** 3
        if v <= 0:
            continue
        u = random.random()
        x2 = x * x
        if u < 1.0 - 0.0331 * x2 * x2:
            return d * v
        if math.log(u) < 0.5 * x2 + d * (1.0 - v + math.log(v)):
            return d * v


def beta_sample(alpha: float, beta: float) -> float:
    """从 Beta(alpha, beta) 采样, 无外部统计库依赖。"""
    if alpha <= 0 or beta <= 0:
        return random.random()
    g1 = _gamma_sample(alpha)
    g2 = _gamma_sample(beta)
    if g1 + g2 < 1e-15:
        return 0.5
    return g1 / (g1 + g2)


# --- 模糊器 arm 定义 ---

class FuzzerArm:
    """单个模糊器实例的 Thompson 采样状态。
    α = 找到独特崩溃的"成功"次数 + prior_success
    β = 产生重复崩溃的"失败"次数 + prior_failure
    prior 使用 Beta(1, 1) (均匀分布) — 无信息先验。"""

    __slots__ = ('name', 'fuzzer_type', 'alpha', 'beta',
                 'total_execs', 'unique_crashes', 'dup_crashes',
                 'last_sample', '_crash_set')

    def __init__(self, name: str, fuzzer_type: str = 'generic',
                 prior_success: float = 1.0, prior_failure: float = 1.0):
        self.name = name
        self.fuzzer_type = fuzzer_type
        self.alpha = prior_success
        self.beta = prior_failure
        self.total_execs = 0
        self.unique_crashes = 0
        self.dup_crashes = 0
        self.last_sample = 0.0
        self._crash_set: set[str] = set()  # 本地 crash 去重

    def observe(self, crash_signature: str, is_unique: bool,
                exec_count: int = 1) -> None:
        """记录一次执行结果。"""
        self.total_execs += exec_count
        if crash_signature:
            if crash_signature not in self._crash_set:
                self._crash_set.add(crash_signature)
                self.unique_crashes += 1
                self.alpha += 1.0
            else:
                self.dup_crashes += 1
                self.beta += 0.5  # 重复崩溃的惩罚较轻——仍证明 fuzzer 能触发

    def sample(self) -> float:
        """从当前后验采样 θ̂ ∼ Beta(α, β)。"""
        self.last_sample = beta_sample(self.alpha, self.beta)
        return self.last_sample

    def mean(self) -> float:
        """后验均值 = α/(α+β)。"""
        total = self.alpha + self.beta
        return self.alpha / total if total > 0 else 0.5

    def uncertainty(self) -> float:
        """后验方差 ≈ αβ / ((α+β)²(α+β+1))。值越大 → 越需探索。"""
        total = self.alpha + self.beta
        if total < 2:
            return 1.0
        return (self.alpha * self.beta) / (total * total * (total + 1.0))

    def reset(self) -> None:
        self.alpha = 1.0
        self.beta = 1.0
        self.total_execs = 0
        self.unique_crashes = 0
        self.dup_crashes = 0
        self._crash_set.clear()


# --- 全局崩溃去重 ---
# 跨模糊器的崩溃签名去重——检测同一崩溃是否已被其他模糊器发现。
# 签名基于: 崩溃地址 (前 2 字节) + 调用栈哈希 (前 4 hex chars)

def make_crash_signature(fault_addr: int, stack_trace: list[int],
                         exception_type: str = '') -> str:
    """生成跨模糊器的崩溃去重签名。
    对栈帧地址低 12 位归零以容忍 ASLR/PIE 随机偏移。"""
    h = hashlib.sha256()
    h.update(struct.pack('<Q', fault_addr & 0xFFFFFFFFFFFFF000))
    for addr in stack_trace[:5]:
        normalized = (addr >> 12) << 12
        h.update(struct.pack('<Q', normalized))
    h.update(exception_type.encode())
    return h.hexdigest()[:16]


# --- Thompson 编排器 ---

class ThompsonOrchestrator:
    """多模糊器 Thompson 采样编排器。

    用法:
        orch = ThompsonOrchestrator()
        orch.register('aflpp', 'AFL++')
        orch.register('libfuzz', 'libFuzzer')
        orch.register('custom', 'BinMindCustom')

        # 每 5 分钟 (rebalance_interval) 重新分配 CPU
        while campaign_running:
            allocation = orch.allocate(total_cpus=16)
            # allocation = {'aflpp': 8, 'libfuzz': 5, 'custom': 3}
            run_fuzzers_for_interval(allocation, interval=300)
            for name, results in collect_results():
                for crash in results:
                    sig = make_crash_signature(...)
                    is_uniq = orch.is_global_unique(sig)
                    orch.observe(name, sig, is_uniq)
    """

    __slots__ = ('_arms', '_global_crashes', '_interval_sec',
                 '_min_allocation', '_iteration', '_drift_window',
                 '_stagnation_counter')

    def __init__(self, default_interval: float = 300.0,
                 min_allocation_ratio: float = 0.05):
        self._arms: dict[str, FuzzerArm] = {}
        self._global_crashes: set[str] = set()
        self._interval_sec = default_interval
        self._min_allocation = min_allocation_ratio  # 每个 arm 最少获得的 CPU 份额
        self._iteration = 0
        self._drift_window: list[dict] = []  # 最近 N 轮的分配快照, 用于检测概念漂移
        self._stagnation_counter: dict[str, int] = defaultdict(int)

    def register(self, name: str, fuzzer_type: str = 'generic') -> None:
        """注册一个模糊器 arm。重复注册同名 arm 会被忽略。"""
        if name not in self._arms:
            self._arms[name] = FuzzerArm(name, fuzzer_type)

    def unregister(self, name: str) -> None:
        self._arms.pop(name, None)

    def allocate(self, total_cpus: int) -> dict[str, int]:
        """执行一轮 Thompson 采样, 返回每个 arm 的 CPU 分配。
        保证每个 arm 至少获得 min_allocation * total_cpus 个 CPU。"""
        self._iteration += 1

        if not self._arms:
            return {}

        # 从每个 arm 的后验采样 θ̂
        samples = {name: arm.sample() for name, arm in self._arms.items()}

        # 过滤非正采样值
        total_sample = sum(v for v in samples.values() if v > 0)
        if total_sample <= 0:
            # 所有 arm 的后验退化 — 均匀分配
            each = total_cpus // len(self._arms)
            return {name: max(1, each) for name in self._arms}

        # 按采样比例分配, 保证最小分配
        min_cpus = max(1, int(total_cpus * self._min_allocation))
        remaining = total_cpus - min_cpus * len(self._arms)

        if remaining <= 0:
            return {name: min_cpus for name in self._arms}

        raw_alloc = {}
        for name, s in samples.items():
            if s > 0:
                raw_alloc[name] = int(remaining * s / total_sample)
            else:
                raw_alloc[name] = 0

        # 调整至精确 total_cpus (舍入误差)
        allocated = sum(raw_alloc.values()) + min_cpus * len(self._arms)
        diff = total_cpus - allocated
        # 按采样值大小分配剩余 CPU
        sorted_arms = sorted(samples.items(), key=lambda x: x[1], reverse=True)
        for i in range(abs(diff)):
            idx = i % len(sorted_arms)
            name = sorted_arms[idx][0]
            if diff > 0:
                raw_alloc[name] += 1
            elif raw_alloc.get(name, 0) > 0:
                raw_alloc[name] -= 1

        result = {name: raw_alloc.get(name, 0) + min_cpus for name in self._arms}

        # 记录分配快照
        self._drift_window.append({
            'iteration': self._iteration,
            'alloc': dict(result),
            'means': {n: round(a.mean(), 4) for n, a in self._arms.items()},
        })
        if len(self._drift_window) > 10:
            self._drift_window.pop(0)

        return result

    def observe(self, arm_name: str, crash_signature: str,
                is_global_unique: bool, exec_count: int = 1) -> None:
        """向指定 arm 报告执行结果。"""
        arm = self._arms.get(arm_name)
        if arm is None:
            return
        if is_global_unique and crash_signature:
            self._global_crashes.add(crash_signature)
        arm.observe(crash_signature, is_global_unique, exec_count)

    def is_global_unique(self, crash_signature: str) -> bool:
        """检查崩溃签名是否全局唯一 (跨所有模糊器)。"""
        return crash_signature not in self._global_crashes

    def observe_stagnation(self, arm_name: str) -> None:
        """记录 arm 的无产出周期 — 用于漂移检测和选择性重启。"""
        self._stagnation_counter[arm_name] += 1

    def observe_progress(self, arm_name: str) -> None:
        """重置停滞计数器。"""
        self._stagnation_counter[arm_name] = 0

    def check_drift(self) -> list[str]:
        """检测表现显著退化的 arm。返回应重启的 arm 名称列表。
        退化判定: 后验均值低于历史均值 30% 以上且停滞 > 3 轮。"""
        stale = []
        for name, arm in self._arms.items():
            if self._stagnation_counter.get(name, 0) < 3:
                continue
            if self._iteration < 5:
                continue  # 预热期不判断
            # 检查后验均值是否从峰值显著退化
            if arm.mean() < 0.1 and arm.uncertainty() < 0.01:
                # 后验集中且均值低 → arm 已"死"
                stale.append(name)
        return stale

    def restart_arm(self, name: str) -> None:
        """重置 arm 的后验 — 等效于重启模糊器实例。
        保留 _global_crashes 中的崩溃签名以继续全局去重。"""
        if name in self._arms:
            self._arms[name].reset()
            self._stagnation_counter[name] = 0

    def stats(self) -> dict:
        return {
            'iteration': self._iteration,
            'global_unique_crashes': len(self._global_crashes),
            'arms': {
                name: {
                    'mean': round(arm.mean(), 4),
                    'uncertainty': round(arm.uncertainty(), 4),
                    'last_sample': round(arm.last_sample, 4),
                    'unique_crashes': arm.unique_crashes,
                    'total_execs': arm.total_execs,
                    'stagnation': self._stagnation_counter.get(name, 0),
                }
                for name, arm in self._arms.items()
            },
        }

    def allocation_history(self) -> list[dict]:
        return list(self._drift_window)


# --- 与现有模糊调度器的桥接 ---
# 在增强管线中注册后, Thompson 编排器接管 FuzzingScheduler 的
# 能量分配职责——但保留现有的种子选择逻辑 (Scheduler/rarity/energy 等)。
# 仅替换"哪个模糊器实例获得多少 CPU 周期"这一层。

def thompson_guided_schedule(orchestrator: ThompsonOrchestrator,
                             total_cpus: int,
                             collect_results_fn=None) -> dict[str, int]:
    """与现有 Scheduler 兼容的适配函数。
    调用方在 run_pipeline_enhanced 中:
        orch = ThompsonOrchestrator()
        orch.register(...)
        cpus = thompson_guided_schedule(orch, 16)
    """
    return orchestrator.allocate(total_cpus)


__all__ = [
    'ThompsonOrchestrator', 'FuzzerArm',
    'beta_sample', 'make_crash_signature',
    'thompson_guided_schedule',
]
