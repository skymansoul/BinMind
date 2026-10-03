# 统计协议模型检验 —— SPRT序贯假设检验替代穷举CTL验证。
#
# 现有protocol_model_checker做CTL风格穷举状态空间探索,
# 状态爆炸使其对>50状态的状态机不实用。
#
# 本模块使用Wald序贯概率比检验(SPRT):
#   H0: 属性P在协议中成立(θ≤θ₀)
#   H1: 属性P不成立(θ≥θ₁)
#   每采样一条执行路径→计算似然比Λ=Π P(xᵢ|H1)/P(xᵢ|H0)
#   Λ≥B→接受H1(属性违反); Λ≤A→接受H0(属性成立)
#   A=β/(1-α), B=(1-β)/α, α=第I类错误, β=第II类错误
#
# 优势: 采样复杂度独立于状态空间大小, 仅取决于(α,β,θ₀,θ₁);
# 对大规模协议状态机的验证可行。
#
# 与protocol_model_checker互补: CTL做精确验证(小状态机),
# SPRT做统计验证(大状态机+容忍错误边界)。
#
# 未见2024-2025文献涉及SPRT用于网络协议状态机统计验证。

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class SprtConfig:
    """SPRT检验配置"""
    alpha: float = 0.05       # 第I类错误: H0真但拒绝H0
    beta: float = 0.10        # 第II类错误: H1真但接受H0
    theta_0: float = 0.05     # H0: 属性违反率 ≤ θ₀
    theta_1: float = 0.20     # H1: 属性违反率 ≥ θ₁ (θ₁>θ₀)
    max_samples: int = 10000  # 采样上限(防止不收敛)
    # A = β/(1-α), B = (1-β)/α (Wald边界)


@dataclass
class SprtResult:
    """SPRT检验结果"""
    property_name: str
    verdict: str              # "PASS" / "FAIL" / "INCONCLUSIVE"
    samples_taken: int
    log_likelihood_ratio: float
    violation_rate: float     # 观测违反率
    bound_a: float            # 接受H0下界
    bound_b: float            # 拒绝H0上界
    early_terminated: bool    # 是否提前终止
    evidence: str = ""


@dataclass
class StatisticalCheckReport:
    """统计检验完整报告"""
    total_properties: int
    passed: int
    failed: int
    inconclusive: int
    results: List[SprtResult]
    total_samples_used: int


class StatisticalProtocolChecker:
    """统计协议模型检验器 —— SPRT+随机路径采样。

    对每条待验证属性, 采样随机执行路径→检查属性是否在该路径上成立→
    更新似然比→达到边界时终止。
    """

    def __init__(self, config: Optional[SprtConfig] = None):
        self._cfg = config or SprtConfig()
        self._a = math.log(self._cfg.beta / (1 - self._cfg.alpha))
        self._b = math.log((1 - self._cfg.beta) / self._cfg.alpha)

    def check_property(self, name: str,
                        path_sampler: Callable[[], List[Any]],
                        property_check: Callable[[List[Any]], bool]
                        ) -> SprtResult:
        """对单条属性执行SPRT检验。

        path_sampler: () → 随机执行路径(状态序列)
        property_check: (路径) → bool, 属性在该路径上是否违反
        """
        log_lr = 0.0          # log(Λ), 对数似然比
        violations = 0
        n = 0

        for n in range(1, self._cfg.max_samples + 1):
            path = path_sampler()
            violated = property_check(path)
            if violated:
                violations += 1
                # 似然比更新: P(violation|H1)/P(violation|H0) = θ₁/θ₀
                log_lr += math.log(self._cfg.theta_1 / self._cfg.theta_0)
            else:
                log_lr += math.log(
                    (1 - self._cfg.theta_1) / (1 - self._cfg.theta_0))

            # 边界检查
            if log_lr <= self._a:
                return SprtResult(
                    property_name=name, verdict="PASS",
                    samples_taken=n,
                    log_likelihood_ratio=round(log_lr, 4),
                    violation_rate=round(violations / n, 4),
                    bound_a=round(self._a, 4),
                    bound_b=round(self._b, 4),
                    early_terminated=True,
                    evidence=f"H0接受: {violations}/{n}次违反, θ_obs={violations/n:.3f}≤θ₀={self._cfg.theta_0}",
                )
            elif log_lr >= self._b:
                return SprtResult(
                    property_name=name, verdict="FAIL",
                    samples_taken=n,
                    log_likelihood_ratio=round(log_lr, 4),
                    violation_rate=round(violations / n, 4),
                    bound_a=round(self._a, 4),
                    bound_b=round(self._b, 4),
                    early_terminated=True,
                    evidence=f"H1接受: {violations}/{n}次违反, θ_obs={violations/n:.3f}≥θ₁={self._cfg.theta_1}",
                )

        # 达到max_samples仍未终止→无结论
        return SprtResult(
            property_name=name, verdict="INCONCLUSIVE",
            samples_taken=n,
            log_likelihood_ratio=round(log_lr, 4),
            violation_rate=round(violations / max(n, 1), 4),
            bound_a=round(self._a, 4),
            bound_b=round(self._b, 4),
            early_terminated=False,
            evidence=f"采样{n}次未达边界, Λ={math.exp(log_lr):.1f}",
        )

    def check_properties(self,
                          properties: Dict[str, Tuple[Callable, Callable]]
                          ) -> StatisticalCheckReport:
        """批量检验: {属性名 → (path_sampler, property_check)}。"""
        results: List[SprtResult] = []
        passed = failed = inconclusive = 0
        total_samples = 0

        for name, (sampler, checker) in properties.items():
            r = self.check_property(name, sampler, checker)
            results.append(r)
            total_samples += r.samples_taken
            if r.verdict == "PASS":
                passed += 1
            elif r.verdict == "FAIL":
                failed += 1
            else:
                inconclusive += 1

        return StatisticalCheckReport(
            total_properties=len(properties),
            passed=passed, failed=failed,
            inconclusive=inconclusive,
            results=results,
            total_samples_used=total_samples,
        )


def make_random_path_sampler(
    states: List[str],
    transitions: Dict[str, List[str]],
    initial_state: str,
    max_steps: int = 100,
) -> Callable[[], List[str]]:
    """工厂函数: 从状态机定义创建随机路径采样器。

    transitions: {state → [next_states]}, 随机选择下一状态。
    """
    def sampler() -> List[str]:
        path = [initial_state]
        current = initial_state
        for _ in range(max_steps):
            next_states = transitions.get(current, [])
            if not next_states:
                break
            current = random.choice(next_states)
            path.append(current)
        return path
    return sampler


def make_deadlock_checker(terminal_states: List[str] = None,
                           transition_map: Dict[str, List[str]] = None
                           ) -> Callable[[List[str]], bool]:
    """工厂函数: 检测死锁的属性检查器。

    死锁定义: 路径终止于非终端状态且该状态无出边。
    若提供terminal_states和transition_map则做精确判定,
    否则回退到启发式: 路径最后状态重复出现3次以上→可能的活锁/死锁。
    """
    terminals = set(terminal_states or [])
    trans = transition_map or {}

    def checker(path: List[str]) -> bool:
        if len(path) < 2:
            return False
        last = path[-1]
        if terminals and trans:
            # 精确判定: 终止于非终端且无出边
            if last not in terminals and not trans.get(last, []):
                return True
            return False
        # 启发式: 最后状态在路径尾部反复出现
        tail = path[-10:] if len(path) >= 10 else path
        last_count = sum(1 for s in tail if s == last)
        return last_count >= 3 and last not in terminals
    return checker


__all__ = [
    "SprtConfig", "SprtResult", "StatisticalCheckReport",
    "StatisticalProtocolChecker", "make_random_path_sampler",
]
