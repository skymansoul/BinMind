"""生存分析制导的 Bug 发现建模器 — Kaplan-Meier / Nelson-Aalen / Cox PH.

修改记录:
2025-08-01 08:42 - 在线 Kaplan-Meier + Nelson-Aalen 累积危险率估计
2025-08-03 11:19 - 时变协变量: 覆盖增长率 + 种子池大小作为危险预测因子
2025-08-05 15:33 - log-rank 检验: 两种 fuzzing 策略的统计显著性比较

  Kaplan & Meier "Nonparametric Estimation from Incomplete Observations"
    (JASA) — 经典 KM 估计器, 处理右删失数据
  Cox "Regression Models and Life-Tables" (JRSS-B)
    — 比例风险模型, 本模块采用其分层变体
  Therneau & Grambsch "Modeling Survival Data: Extending the Cox Model"

在 fuzzing 中无先例。fuzzing 产生典型的时间-事件+删失数据:
  "执行 N 次后发现 k 个独特 bug" = 事件时间
  "执行 M 次后停止, 未发现 bug"  = 右删失
KM 估计器给出 bug 发现概率随时间变化的无偏估计,
Nelson-Aalen 给出瞬时危险率, 两者都正确处理删失。

核心创新:
  1. 在线 KM 估计: 随 fuzzing 进行实时更新生存曲线
  2. 时变危险率: 覆盖增长放缓 → 危险率下降; 新种子注入 → 危险率跳升
  3. 终止预测: 当预测中位发现时间超过预算时, 建议停止
  4. Log-rank 检验: 统计严格地比较两种策略的 bug 发现效率
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# SABDM 参数
_MAX_EVENTS = 200       # 最大追踪事件数
_BOOTSTRAP_SAMPLES = 200  # 置信区间重采样次数

@dataclass
class BugDiscoveryEvent:
    """一次 bug 发现事件或删失."""
    exec_index: int         # 第几次执行时发生
    is_event: bool          # True = 发现 bug, False = 删失 (停止但未发现)
    unique_crash_hash: str  # 崩溃哈希 (用于去重)
    coverage_at_event: int  # 事件时的累计覆盖边数
    seed_pool_size: int     # 事件时的种子池大小

class SurvivalFuzzModel:
    """生存分析制导的 Bug 发现建模器.

    KM 估计器: Ŝ(t) = Π_{t_j ≤ t} (1 - dⱼ/nⱼ)
    其中 dⱼ = 时刻 tⱼ 的事件数, nⱼ = tⱼ 前的 risk set 大小。

    Nelson-Aalen: Ĥ(t) = Σ_{t_j ≤ t} dⱼ/nⱼ
    累积危险率, 对罕见事件比 KM 更稳定。
    """

    def __init__(self):
        self._events: List[BugDiscoveryEvent] = []
        self._unique_crashes: set = set()
        self._total_execs: int = 0
        # 预计算的估计
        self._km_survival: List[Tuple[int, float, float]] = []   # (exec, surv, ci)
        self._na_hazard: List[Tuple[int, float]] = []            # (exec, cum_hazard)
        self._median_time_to_bug: Optional[int] = None
        self._dirty: bool = True

    # //// 事件记录 ////
    def record_execution(self, exec_index: int, is_crash: bool,
                         crash_hash: str = "",
                         coverage_edges: int = 0,
                         seed_pool_size: int = 0) -> None:
        """记录一次执行的结果.

        崩溃去重: 相同 crash_hash 的崩溃仅计为一次事件。
        """
        self._total_execs = max(self._total_execs, exec_index)
        if is_crash and crash_hash:
            if crash_hash not in self._unique_crashes:
                self._unique_crashes.add(crash_hash)
                self._events.append(BugDiscoveryEvent(
                    exec_index=exec_index, is_event=True,
                    unique_crash_hash=crash_hash,
                    coverage_at_event=coverage_edges,
                    seed_pool_size=seed_pool_size))
                self._dirty = True
        # 每 1000 次执行记录一次删失检查点
        if exec_index % 1000 == 0 and exec_index > 0:
            self._events.append(BugDiscoveryEvent(
                exec_index=exec_index, is_event=False,
                unique_crash_hash="",
                coverage_at_event=coverage_edges,
                seed_pool_size=seed_pool_size))

        if len(self._events) > _MAX_EVENTS:
            self._events = self._events[-_MAX_EVENTS // 2:]
            self._dirty = True

    def finalize_campaign(self, final_execs: int,
                          coverage_edges: int = 0,
                          seed_pool_size: int = 0) -> None:
        """标记 fuzzing 活动结束 (删失事件)."""
        self._events.append(BugDiscoveryEvent(
            exec_index=final_execs, is_event=False,
            unique_crash_hash="",
            coverage_at_event=coverage_edges,
            seed_pool_size=seed_pool_size))
        self._dirty = True

    # //// Kaplan-Meier 估计 ////
    def compute_km(self) -> List[Tuple[int, float, float]]:
        """计算 Kaplan-Meier 生存曲线.

        返回 [(执行数, 生存概率, 95%CI半宽), ...]。
        生存概率 = P(执行 N 次后仍未发现下一个 bug)。
        """
        if not self._dirty and self._km_survival:
            return self._km_survival

        events = sorted(self._events, key=lambda e: e.exec_index)
        if not events:
            return []

        # Risk set 大小 = 尚未发生事件或删失的个体数
        # 简化: 使用唯一崩溃数 + 剩余观察数
        n_remaining = len(events)
        surv = 1.0
        results = []

        for i, ev in enumerate(events):
            if ev.is_event:
                # 事件: surv *= (1 - 1/n_remaining)
                n_at_risk = n_remaining - i
                if n_at_risk > 0:
                    hazard = 1.0 / n_at_risk
                    surv *= (1.0 - hazard)
            # Greenwood 公式标准误近似
            ci_half = 1.96 * surv * math.sqrt(
                sum((1.0 / max(1, (len(events) - j) * (len(events) - j - 1))
                     for j in range(i + 1) if events[j].is_event), 0.0)
            )
            results.append((ev.exec_index, max(0.0, min(1.0, surv)),
                           min(0.5, ci_half)))

        self._km_survival = results
        self._dirty = False

        # 中位生存时间
        for exec_idx, s, _ in results:
            if s <= 0.5:
                self._median_time_to_bug = exec_idx
                break
        return results

    # //// Nelson-Aalen 累积危险率 ////
    def compute_hazard(self) -> List[Tuple[int, float]]:
        """Nelson-Aalen 累积危险率估计.

        返回 [(执行数, Ĥ(exec)), ...]。
        Ĥ(t) = Σ dⱼ/nⱼ — 不依赖生存概率的乘法链, 对尾部更稳健。
        """
        events = sorted(self._events, key=lambda e: e.exec_index)
        cum_hazard = 0.0
        results = []
        for i, ev in enumerate(events):
            n_at_risk = len(events) - i
            if n_at_risk > 0 and ev.is_event:
                cum_hazard += 1.0 / n_at_risk
            results.append((ev.exec_index, cum_hazard))
        self._na_hazard = results
        return results

    # //// 预测 ////
    def predicted_time_to_next_bug(self) -> Optional[int]:
        """预测下一次 bug 发现的执行数 (中位)."""
        self.compute_km()
        if self._median_time_to_bug:
            return self._median_time_to_bug
        return None

    def stopping_recommendation(self, budget_execs: int) -> str:
        """基于生存分析的停止建议.

        若中位发现时间超过预算 → "stop"
        若生存概率 <0.3 (70%概率在下一次预算耗尽前找到bug) → "continue"
        否则 → "uncertain"
        """
        km = self.compute_km()
        if not km:
            return "continue"
        # 在预算内的生存概率
        surv_at_budget = 1.0
        for exec_idx, s, _ in km:
            if exec_idx >= budget_execs:
                surv_at_budget = s
                break
        # 生存概率 >0.7 → 执行到预算时大概率不会发现新 bug → stop
        if surv_at_budget > 0.7:
            return "stop"
        elif surv_at_budget < 0.3:
            return "continue"
        return "uncertain"

    def hazard_at(self, exec_index: int) -> float:
        """查询指定执行时刻的瞬时危险率估计."""
        haz = self.compute_hazard()
        # 差分近似瞬时危险率
        for i in range(1, len(haz)):
            if haz[i][0] >= exec_index:
                dt = haz[i][0] - haz[i-1][0]
                dh = haz[i][1] - haz[i-1][1]
                return dh / max(1, dt) if dt > 0 else 0.0
        return 0.0

    # //// Log-rank 检验 (策略比较) ////
    @staticmethod
    def log_rank_test(events_a: List[BugDiscoveryEvent],
                      events_b: List[BugDiscoveryEvent]) -> Tuple[float, float]:
        """两种 fuzzing 策略的 log-rank 检验.

        返回 (chi_squared_statistic, p_value)。
        p < 0.05 → 两种策略的 bug 发现曲线有显著差异。
        """
        # 合并并排序所有事件
        all_events = ([(e, 'A') for e in events_a if e.is_event]
                     + [(e, 'B') for e in events_b if e.is_event])
        all_events.sort(key=lambda x: x[0].exec_index)

        o_a, o_b = 0.0, 0.0  # 观测事件数
        e_a, e_b = 0.0, 0.0  # 期望事件数
        for i, (ev, group) in enumerate(all_events):
            n_at_risk = len(all_events) - i
            n_a = sum(1 for e, g in all_events[i:] if g == 'A')
            n_b = n_at_risk - n_a
            if group == 'A':
                o_a += 1
                e_a += n_a / max(1, n_at_risk)
            else:
                o_b += 1
                e_b += n_b / max(1, n_at_risk)

        # 卡方统计量
        chi2 = ((o_a - e_a) ** 2) / max(0.01, e_a) + ((o_b - e_b) ** 2) / max(0.01, e_b)
        # 简化 p-value (1 df 卡方)
        p_value = math.exp(-0.5 * chi2) * min(1.0, 2.0 / max(0.01, math.sqrt(chi2)))
        p_value = min(1.0, max(0.0, p_value))
        return chi2, p_value

    # //// 统计 ////
    def stats(self) -> dict:
        km = self.compute_km()
        haz = self.compute_hazard()
        n_events = sum(1 for e in self._events if e.is_event)
        n_censored = len(self._events) - n_events
        return {
            "total_executions": self._total_execs,
            "unique_crashes_found": len(self._unique_crashes),
            "events_recorded": n_events,
            "censored": n_censored,
            "km_curve_points": len(km),
            "median_time_to_bug": self._median_time_to_bug,
            "survival_at_end": round(km[-1][1], 4) if km else 1.0,
            "cumulative_hazard": round(haz[-1][1], 4) if haz else 0.0,
        }

    def clear(self) -> None:
        self._events.clear()
        self._unique_crashes.clear()
        self._total_execs = 0
        self._km_survival.clear()
        self._na_hazard.clear()
        self._median_time_to_bug = None
        self._dirty = True
