"""
自适应方法调度器: 依据 checksec 与 binary_profile 特征, 用 ε-greedy 多臂老虎机
在线学习模糊测试、符号执行、规则检测与 LLM 分析各方法的边际效用, 动态分配分析预算。
"""

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
    """ε-greedy MAB 驱动的分析方法选择器。select_methods 选出方法及预算, update 反馈奖励, stats 输出统计。"""

    def __init__(self, epsilon: float = 0.15, seed: int = 42):
        """epsilon 为探索率 (0.0 纯贪心, 1.0 纯随机), seed 为随机种子 (用于复现)。"""
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
        """基于样本特征选择分析方法及预算分配。返回按优先级排序的 (方法, 分配秒数) 列表, 硬约束在规则层处理。"""
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
        """更新方法臂的奖励估计。reward 取 0.0–1.0 (1.0 表示发现可利用漏洞)。"""
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
        """基于样本特征做硬约束过滤: angr 不可用则排除 SYMBOLIC, 模糊测试不可用则排除 FUZZING, 静态规则始终可用。"""
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
    计算一次分析的奖励值 (0.0-1.0), 加权为: 漏洞发现 40%、利用成功 30%、精度 20%、效率 10%。
    参数: vulns_found 漏洞总数, exploit_success 是否成功生成有效 exploit, false_positives 误报数, elapsed_sec 分析耗时。
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
