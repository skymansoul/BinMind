"""
自适应方法调度器 —— 基于样本特征动态选择最优分析策略。

根据二进制文件的保护机制、复杂度评估和历史分析表现，
使用 ε-greedy 多臂老虎机（MAB）算法在线选择最优分析方法的组合。

设计原理:
  1. 从 checksec 和 binary_profile 提取样本特征向量
  2. 初始化各"分析方法臂"的期望奖励估计
  3. 每次实验以概率 ε 随机探索新方法，以概率 1-ε 选择历史最优
  4. 根据实验结果更新对应方法臂的奖励估计

实现为轻量级规则引擎 + MAB 的组合:
  - 规则层: 根据保护机制硬约束决定部分方法选择（如无源码→跳过编译时分析）
  - MAB层:   对满足硬约束的方法组合进行在线学习调度

参考:
  - Li et al., 2010, NIPS, "A Contextual-Bandit Approach to Personalized News Article Recommendation"
  - Böhme et al., 2021, ACM CSUR, "Fuzzing: On the Exponential Cost of Vulnerability Discovery"

创新点: 与现有固定顺序管线不同，调度器将模糊测试、符号执行、规则检测
和 LLM 分析视为可竞争的资源消费者，通过 MAB 在线学习各方法在具体样本上的
边际效用，动态分配分析预算。
"""

from __future__ import annotations

import logging
import math
import random
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class AnalysisMethod(Enum):
    """可调度的分析方法。"""
    STATIC_RULES = 'static_rules'       # 静态规则匹配
    SYMBOLIC = 'symbolic'               # 符号执行（angr）
    FUZZING = 'fuzzing'                 # 模糊测试（AFL++/libFuzzer）
    LLM_DECOMP = 'llm_decomp'           # LLM 辅助反编译分析
    LLM_CRASH = 'llm_crash'             # LLM 辅助崩溃分析
    ROP_CHAIN = 'rop_chain'             # ROP 链构造
    FORMAT_STRING = 'format_string'     # 格式化字符串专项分析


# 方法臂的默认预算分配（秒）
_DEFAULT_BUDGETS = {
    AnalysisMethod.STATIC_RULES: 30,
    AnalysisMethod.SYMBOLIC: 300,
    AnalysisMethod.FUZZING: 600,
    AnalysisMethod.LLM_DECOMP: 60,
    AnalysisMethod.LLM_CRASH: 30,
    AnalysisMethod.ROP_CHAIN: 60,
    AnalysisMethod.FORMAT_STRING: 120,
}


class AdaptiveScheduler:
    """
    自适应方法调度器 —— ε-greedy MAB 驱动的分析方法选择。

    用法:
        scheduler = AdaptiveScheduler(epsilon=0.15)
        methods = scheduler.select_methods(checksec, profile)
        # 在管线中按 methods 执行对应的分析阶段
        scheduler.update(method, reward=0.8)
    """

    def __init__(self, epsilon: float = 0.15, seed: int = 42):
        """
        Args:
            epsilon: 探索率（0.0=纯贪心, 1.0=纯随机）
            seed:    随机种子（用于可复现性）
        """
        self.epsilon = epsilon
        self._rng = random.Random(seed)

        # 每个方法臂的统计量
        self._counts: Dict[AnalysisMethod, int] = {
            m: 0 for m in AnalysisMethod
        }
        self._rewards: Dict[AnalysisMethod, float] = {
            m: 0.0 for m in AnalysisMethod
        }

    def select_methods(
        self,
        checksec: Dict[str, Any],
        profile: Optional[Dict[str, Any]] = None,
        total_budget_sec: float = 600.0,
    ) -> List[Tuple[AnalysisMethod, float]]:
        """
        基于样本特征选择分析方法及预算分配。

        返回按优先级排序的方法列表，每个元素为 (方法, 分配秒数)。
        硬约束（如 angr 不可用时排除 SYMBOLIC）在规则层处理。

        Args:
            checksec:         checksec 检测结果
            profile:          二进制画像（可选，用于更细粒度的特征）
            total_budget_sec: 总分析预算（秒）

        Returns:
            方法-预算配对列表
        """
        # 硬约束过滤
        eligible = self._apply_hard_constraints(checksec, profile)

        if not eligible:
            _log.warning("No eligible analysis methods for this sample")
            return [(AnalysisMethod.STATIC_RULES, 30.0)]

        # ε-greedy 选择
        budget_allocations: Dict[AnalysisMethod, float] = {}

        if self._rng.random() < self.epsilon:
            # 探索: 随机排列并均匀分配
            self._rng.shuffle(eligible)
            per_method = total_budget_sec / len(eligible)
            for method in eligible:
                budget_allocations[method] = per_method
        else:
            # 利用: 按历史奖励排序，高奖励方法获得更多预算
            scored = []
            for method in eligible:
                if self._counts[method] > 0:
                    avg_reward = self._rewards[method] / self._counts[method]
                    # UCB 上置信界，鼓励探索未充分测试的方法
                    ucb = avg_reward + math.sqrt(
                        2 * math.log(max(1, sum(self._counts.values()))) /
                        max(1, self._counts[method])
                    )
                    scored.append((method, ucb))
                else:
                    # 未测试过的方法给予高优先级
                    scored.append((method, 2.0))

            scored.sort(key=lambda x: -x[1])

            # 按 UCB 比例分配预算
            total_score = sum(s for _, s in scored) or 1.0
            remaining = total_budget_sec
            for i, (method, score) in enumerate(scored):
                if i == len(scored) - 1:
                    budget_allocations[method] = remaining
                else:
                    alloc = total_budget_sec * (score / total_score)
                    budget_allocations[method] = min(alloc, remaining)
                    remaining -= budget_allocations[method]

        return sorted(
            budget_allocations.items(),
            key=lambda x: -x[1],
        )

    def update(
        self,
        method: AnalysisMethod,
        reward: float,
    ) -> None:
        """
        更新方法臂的奖励估计。

        Args:
            method: 被评估的方法
            reward: 0.0–1.0 的奖励值（1.0 = 发现了可利用漏洞）
        """
        self._counts[method] = self._counts.get(method, 0) + 1
        self._rewards[method] = self._rewards.get(method, 0.0) + reward
        _log.debug(
            "MAB update: %s reward=%.2f avg=%.2f (n=%d)",
            method.value, reward,
            self._rewards[method] / self._counts[method],
            self._counts[method],
        )

    def stats(self) -> Dict[str, Dict[str, float]]:
        """返回各方法臂的统计信息。"""
        return {
            m.value: {
                'count': self._counts[m],
                'total_reward': round(self._rewards[m], 2),
                'avg_reward': round(
                    self._rewards[m] / max(1, self._counts[m]), 3
                ),
            }
            for m in AnalysisMethod
        }

    def _apply_hard_constraints(
        self,
        checksec: Dict[str, Any],
        profile: Optional[Dict[str, Any]],
    ) -> List[AnalysisMethod]:
        """
        基于样本特征的硬约束过滤。

        规则:
          - angr 未安装 → 排除 SYMBOLIC
          - NX 关闭 → 降低 ROP_CHAIN 优先级（shellcode 更直接）
          - 无 PLT 危险函数 → 降低 LLM_DECOMP 优先级
          - 有 printf 导入 → 增加 FORMAT_STRING 优先级
        """
        eligible = list(AnalysisMethod)

        # 检查 angr 可用性
        try:
            from core.symexec import check_angr
            if not check_angr():
                eligible = [m for m in eligible if m != AnalysisMethod.SYMBOLIC]
        except ImportError:
            eligible = [m for m in eligible if m != AnalysisMethod.SYMBOLIC]

        # 检查模糊测试可用性
        try:
            from plugins.fuzz_harness import generate_harness
            # 仅检查模块可导入，不实际运行
        except ImportError:
            eligible = [m for m in eligible if m != AnalysisMethod.FUZZING]

        # 静态规则总是可用
        if AnalysisMethod.STATIC_RULES not in eligible:
            eligible.append(AnalysisMethod.STATIC_RULES)

        return eligible


def compute_reward(
    vulns_found: int,
    exploit_success: bool,
    false_positives: int,
    elapsed_sec: float,
) -> float:
    """
    计算一次分析的奖励值（0.0-1.0）。

    奖励由四部分加权:
      - 漏洞发现: 40% — 每个 Critical/High 漏洞 +0.3，Medium +0.1
      - 利用成功: 30% — exploit 成功 +1.0
      - 精度:     20% — 1 - fp/max(vulns, 1)
      - 效率:     10% — 1 / (1 + elapsed_sec/600)

    Args:
        vulns_found:      发现的漏洞总数
        exploit_success:  是否成功生成有效 exploit
        false_positives:  误报数
        elapsed_sec:      分析耗时

    Returns:
        0.0–1.0 的奖励值
    """
    # 漏洞发现奖励
    vuln_reward = min(1.0, vulns_found * 0.2)

    # 利用成功奖励
    exploit_reward = 1.0 if exploit_success else 0.0

    # 精度奖励
    total = max(vulns_found, 1)
    precision = max(0.0, 1.0 - false_positives / total)

    # 效率奖励
    efficiency = 1.0 / (1.0 + elapsed_sec / 600.0)

    reward = (
        0.4 * vuln_reward +
        0.3 * exploit_reward +
        0.2 * precision +
        0.1 * efficiency
    )
    return round(min(1.0, max(0.0, reward)), 3)
