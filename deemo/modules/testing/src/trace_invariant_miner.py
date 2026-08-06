# 执行轨迹不变量挖掘器 — 从非崩溃执行中自动推断程序行为不变量
#
# 核心问题:
#   property_based.py 需要人工编写属性 (forall + prop), 这要求对程序行为
#   有先验知识——在二进制分析场景中通常不具备。
#   statistical_oracle.py 比较两个实现的度量分布, 不捕获单实现的内部不变量。
#   崩溃驱动的fuzzing完全忽视了"行为异常但未崩溃"的输入。
#
#   FuzzSight (Charoenwet et al. 2025) 证明: 从非崩溃fuzzing输入中推断的
#   "likely invariants" 可检测到 75% 的回归bug和 80% 的漏洞——无需崩溃。
#   但FuzzSight工作在源码级 (Java/Python), 本模块工作在二进制执行trace级。
#
# 本模块的方法 — 二进制执行trace不变量挖掘:
#   1. 在关键观测点 (函数入口/出口、循环头、比较指令后) 采集程序状态
#   2. 对每个观测点, 从多轮执行中学习变量的值域和关系
#   3. 推断三类不变量:
#      a) 值域不变量: x ∈ [min, max], x % align == 0
#      b) 关系不变量: x > y, x + y ≈ constant (容差 ±δ)
#      c) 模式不变量: x 总是指向堆/栈/代码段
#   4. 对每个新输入, 计算不变量违反分数 → 反馈给fuzzer种子能量
#
# 为什么从二进制trace推断:
#   - 不需要源码、不需要调试符号
#   - 利用现有 subreg_taint.py 提供寄存器值的精确语义
#   - 观测点 = 指令地址, 比源码行号更细粒度
#
# 参考文献:
#   FuzzSight (Charoenwet et al. 2025, arXiv:2510.15512)
#     — likely invariants + fuzzing 做代码审查; 本项目取其不变量推断思想
#       但适配到二进制trace级别
#   Daikon (Ernst et al. 2001, IEEE TSE) — 动态不变量检测的奠基性工作;
#     本项目取其观测点+不变量模板概念但简化模板集以降低计算开销
#   QuickInv (Nilsson & Norozi 2025) — theory exploration做不变量发现;
#     本项目取其"从执行trace发现"的思想但以统计频率替代形式验证

from __future__ import annotations

import math
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class InvariantKind(str, Enum):
    """不变量类别"""
    RANGE = "range"            # x ∈ [min, max]
    ALIGNMENT = "alignment"    # x % k == 0
    RELATION = "relation"      # x > y, x < y, x == y
    CONSTANT_SUM = "const_sum" # x + y ≈ C
    NON_ZERO = "non_zero"      # x ≠ 0
    POWER_OF_TWO = "pow2"      # x 是2的幂
    POINTER_DOMAIN = "ptr_domain"  # x 属于堆/栈/代码段


@dataclass
class ObservationPoint:
    """一个观测点的状态——特定指令地址处的寄存器和内存快照"""
    addr: int                          # 指令地址
    context: str = ""                  # 观测上下文 (如 "func_entry", "cmp_after")
    # 寄存器值: register_name → value
    reg_values: Dict[str, int] = field(default_factory=dict)
    # 输入字节偏移 (来自 subreg_taint)
    tainted_input_offsets: Set[int] = field(default_factory=set)


@dataclass
class Invariant:
    """单条推断的不变量"""
    obs_addr: int                      # 观测点地址
    kind: InvariantKind
    description: str                   # 人类可读描述
    # 值域不变量参数
    reg_name: str = ""                 # 涉及的寄存器
    min_val: int = 0
    max_val: int = 0
    alignment: int = 1
    # 关系不变量参数
    lhs_reg: str = ""
    rhs_reg: str = ""
    relation: str = ""                 # "gt" | "lt" | "eq"
    const_sum_value: int = 0
    # 统计
    observation_count: int = 0         # 总观测次数
    hold_count: int = 0                # 不变量成立的次数
    confidence: float = 0.0            # hold_count / observation_count


@dataclass
class InvariantViolation:
    """单条不变量违反——输入触发了与已学不变量矛盾的行为"""
    invariant: Invariant
    obs_addr: int
    actual_values: Dict[str, int]      # 实际观测值
    violation_severity: float           # [0, 1]
    description: str = ""


@dataclass
class InvariantMiningReport:
    """不变量挖掘的完整报告"""
    total_observation_points: int
    total_invariants_mined: int
    by_kind: Dict[str, int] = field(default_factory=dict)
    # 本轮执行的不变量违反
    violations: List[InvariantViolation] = field(default_factory=list)
    # 给fuzzer的反常分数 [0, 1]
    anomaly_score: float = 0.0
    execution_time_s: float = 0.0
    summary: str = ""


class TraceInvariantMiner:
    """从二进制执行trace中挖掘likely invariants。

    典型用法:
        miner = TraceInvariantMiner()
        # 学习阶段: 对多个"正常"输入采集观测点
        for obs_points in normal_executions:
            miner.observe(obs_points)
        miner.mine_invariants(min_support=0.95)
        # 检测阶段: 对新输入检查不变量违反
        violations = miner.check(new_obs_points)
        anomaly = miner.anomaly_score(violations)
    """

    def __init__(self, min_observations: int = 10):
        """
        min_observations: 一个观测点至少被观测多少次才开始推断不变量。
        """
        self._min_obs = min_observations
        # addr → reg_name → list of values
        self._value_history: Dict[int, Dict[str, List[int]]] = defaultdict(
            lambda: defaultdict(list))
        # 已挖掘的不变量
        self._invariants: List[Invariant] = []
        # 总观测轮次
        self._total_observations = 0

    def observe(self, obs_points: List[ObservationPoint]) -> None:
        """记录一轮执行的所有观测点数据"""
        self._total_observations += 1
        for op in obs_points:
            for reg, val in op.reg_values.items():
                self._value_history[op.addr][reg].append(val)
                # 限制每个寄存器在每个地址的历史长度
                hist = self._value_history[op.addr][reg]
                if len(hist) > 1024:
                    self._value_history[op.addr][reg] = hist[-1024:]

    def mine_invariants(self, min_support: float = 0.95) -> int:
        """从累积的观测历史中挖掘不变量。

        min_support: 不变量至少在此比例的观测中成立才被接受。
        """
        self._invariants = []

        for addr, reg_history in self._value_history.items():
            for reg_name, values in reg_history.items():
                if len(values) < self._min_obs:
                    continue

                n = len(values)
                # 转换为Python int列表
                vals = [int(v) for v in values]

                # 1. 值域不变量
                lo, hi = min(vals), max(vals)
                if lo < hi:
                    self._invariants.append(Invariant(
                        obs_addr=addr, kind=InvariantKind.RANGE,
                        reg_name=reg_name, min_val=lo, max_val=hi,
                        observation_count=n, hold_count=n,
                        confidence=1.0,
                        description=f"{reg_name} ∈ [{lo:#x}, {hi:#x}]",
                    ))

                # 2. 对齐不变量
                if len(vals) >= 4:
                    gcd = self._compute_gcd_alignment(vals)
                    if gcd >= 2:
                        support = sum(1 for v in vals if v % gcd == 0) / n
                        if support >= min_support:
                            self._invariants.append(Invariant(
                                obs_addr=addr, kind=InvariantKind.ALIGNMENT,
                                reg_name=reg_name, alignment=gcd,
                                observation_count=n,
                                hold_count=int(support * n),
                                confidence=support,
                                description=f"{reg_name} % {gcd} == 0",
                            ))

                # 3. 非零不变量
                if all(v != 0 for v in vals):
                    self._invariants.append(Invariant(
                        obs_addr=addr, kind=InvariantKind.NON_ZERO,
                        reg_name=reg_name,
                        observation_count=n, hold_count=n,
                        confidence=1.0,
                        description=f"{reg_name} ≠ 0",
                    ))

                # 4. 2的幂不变量
                pow2_count = sum(1 for v in vals
                                  if v > 0 and (v & (v - 1)) == 0)
                if pow2_count / n >= min_support:
                    self._invariants.append(Invariant(
                        obs_addr=addr, kind=InvariantKind.POWER_OF_TWO,
                        reg_name=reg_name,
                        observation_count=n, hold_count=pow2_count,
                        confidence=pow2_count / n,
                        description=f"{reg_name} is power of 2",
                    ))

        # 5. 跨寄存器关系不变量
        self._mine_relations(min_support)

        return len(self._invariants)

    def _mine_relations(self, min_support: float) -> None:
        """挖掘同一观测点的跨寄存器关系"""
        for addr, reg_history in self._value_history.items():
            regs = list(reg_history.keys())
            for i in range(len(regs)):
                for j in range(i + 1, len(regs)):
                    ra, rb = regs[i], regs[j]
                    vals_a = reg_history[ra]
                    vals_b = reg_history[rb]
                    n = min(len(vals_a), len(vals_b))
                    if n < self._min_obs:
                        continue

                    # 关系: a > b / a < b / a == b
                    gt_count = sum(1 for k in range(n)
                                    if vals_a[k] > vals_b[k])
                    lt_count = sum(1 for k in range(n)
                                    if vals_a[k] < vals_b[k])
                    eq_count = sum(1 for k in range(n)
                                    if vals_a[k] == vals_b[k])

                    best = max(gt_count, lt_count, eq_count)
                    if best / n >= min_support:
                        if best == gt_count:
                            rel, conf = "gt", gt_count / n
                        elif best == lt_count:
                            rel, conf = "lt", lt_count / n
                        else:
                            rel, conf = "eq", eq_count / n
                        self._invariants.append(Invariant(
                            obs_addr=addr, kind=InvariantKind.RELATION,
                            lhs_reg=ra, rhs_reg=rb, relation=rel,
                            observation_count=n, hold_count=best,
                            confidence=conf,
                            description=f"{ra} {rel} {rb}",
                        ))

                    # 和恒定: a + b ≈ constant
                    sums = [vals_a[k] + vals_b[k] for k in range(n)]
                    median_sum = sorted(sums)[n // 2]
                    tolerance = max(1, abs(median_sum) // 100)
                    const_count = sum(
                        1 for s in sums
                        if abs(s - median_sum) <= tolerance)
                    if const_count / n >= min_support:
                        self._invariants.append(Invariant(
                            obs_addr=addr, kind=InvariantKind.CONSTANT_SUM,
                            lhs_reg=ra, rhs_reg=rb,
                            const_sum_value=median_sum,
                            observation_count=n, hold_count=const_count,
                            confidence=const_count / n,
                            description=f"{ra} + {rb} ≈ {median_sum:#x}",
                        ))

    def check(self, obs_points: List[ObservationPoint]
               ) -> List[InvariantViolation]:
        """检查新观测点是否违反已知不变量"""
        violations: List[InvariantViolation] = []

        # 构建快速查找: addr → reg → value
        obs_map: Dict[int, Dict[str, int]] = {}
        for op in obs_points:
            obs_map[op.addr] = dict(op.reg_values)

        for inv in self._invariants:
            reg_vals = obs_map.get(inv.obs_addr, {})
            if not reg_vals:
                continue

            severity = 0.0
            actual: Dict[str, int] = {}

            if inv.kind == InvariantKind.RANGE:
                v = reg_vals.get(inv.reg_name)
                if v is not None and (v < inv.min_val or v > inv.max_val):
                    severity = min(1.0, (abs(v - (inv.min_val + inv.max_val) // 2)
                                         / max(1, inv.max_val - inv.min_val)))
                    actual[inv.reg_name] = v

            elif inv.kind == InvariantKind.ALIGNMENT:
                v = reg_vals.get(inv.reg_name)
                if v is not None and v % inv.alignment != 0:
                    severity = 0.5
                    actual[inv.reg_name] = v

            elif inv.kind == InvariantKind.NON_ZERO:
                v = reg_vals.get(inv.reg_name)
                if v is not None and v == 0:
                    severity = 0.7
                    actual[inv.reg_name] = 0

            elif inv.kind == InvariantKind.RELATION:
                va = reg_vals.get(inv.lhs_reg)
                vb = reg_vals.get(inv.rhs_reg)
                if va is not None and vb is not None:
                    violated = False
                    if inv.relation == "gt" and not (va > vb):
                        violated = True
                    elif inv.relation == "lt" and not (va < vb):
                        violated = True
                    elif inv.relation == "eq" and not (va == vb):
                        violated = True
                    if violated:
                        severity = 0.6
                        actual[inv.lhs_reg] = va
                        actual[inv.rhs_reg] = vb

            if severity > 0:
                violations.append(InvariantViolation(
                    invariant=inv, obs_addr=inv.obs_addr,
                    actual_values=actual, violation_severity=severity,
                    description=f"{inv.description} 违反: {actual}",
                ))

        return violations

    def anomaly_score(self,
                       violations: Optional[List[InvariantViolation]] = None,
                       obs_points: Optional[List[ObservationPoint]] = None,
                       ) -> float:
        """计算反常分数 [0, 1]——给fuzzer作为种子能量信号。

        若提供 obs_points (未预先check), 则先执行check。
        """
        if violations is None:
            if obs_points is None:
                return 0.0
            violations = self.check(obs_points)

        if not violations or not self._invariants:
            return 0.0

        # 调和: 违反数 × 平均严重度 / (1 + 总不变量数的对数)
        avg_sev = sum(v.violation_severity for v in violations) / len(violations)
        raw = len(violations) * avg_sev / (1.0 + math.log1p(len(self._invariants)))
        return min(1.0, raw)

    @staticmethod
    def _compute_gcd_alignment(values: List[int]) -> int:
        """计算一组值的最大公约对齐——渐进式GCD"""
        if len(values) < 2:
            return 1
        result = values[0]
        for v in values[1:16]:  # 只检查前16个值
            if v == 0:
                continue
            result = math.gcd(result, abs(v))
            if result == 1:
                break
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "observation_points": len(self._value_history),
            "total_observations": self._total_observations,
            "invariants_mined": len(self._invariants),
            "by_kind": {
                k.value: sum(1 for inv in self._invariants if inv.kind == k)
                for k in InvariantKind
            },
        }

    def reset(self) -> None:
        self._value_history.clear()
        self._invariants.clear()
        self._total_observations = 0


def mine_and_check(train_traces: List[List[ObservationPoint]],
                    test_trace: List[ObservationPoint],
                    min_support: float = 0.9,
                    ) -> Tuple[List[Invariant], List[InvariantViolation], float]:
    """便捷入口: 学习→检查→评分 一条龙"""
    miner = TraceInvariantMiner()
    for trace in train_traces:
        miner.observe(trace)
    miner.mine_invariants(min_support)
    violations = miner.check(test_trace)
    score = miner.anomaly_score(violations)
    return miner._invariants, violations, score
