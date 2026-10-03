# stub_ghost_detector.py — 基于生存分析的幽灵桩检测
# 结合静态依赖图、compat状态与 Kaplan-Meier 生存分析，
# 识别"存在于文件系统但可能已死亡"的桩模块。
# 输出带置信区间的连续风险评分。
#
# 方法:
#   1. 静态信号（依赖图+compat）: 三维交叉验证
#   2. 运行时信号: 对每个桩的调用间隔拟合 Kaplan-Meier 生存曲线
#      S(t) = P(下一次调用间隔 > t)
#   3. 幽灵风险 = 1 - S(当前距末次调用的时间)；
#      若从未被调用: ghost_risk = 1 - S(模块存在时长)
#   4. 综合评分: 0.3×静态评分 + 0.5×生存分析评分 + 0.2×状态评分
#   5. 输出: 连续风险分 + 中位剩余寿命估计 + 90%置信下界
#
# 说明: K-M 估计器天然处理右删失（"30天未被调用"是删失观测），
# 置信区间在样本少时变宽，避免误判。
import math as _math
import time as _time
import os as _os
from dataclasses import dataclass as _dc, field as _field

from modules.stubs.stub_contract import (
    StubContractor as _StubContractor,
    ImplementationStatus as _Status,
)


@_dc
class SurvivalEstimate:
    """Kaplan-Meier生存分析结果。"""
    survival_prob: float = 1.0       # S(t) at current time
    ghost_risk: float = 0.0          # 1 - S(t)
    median_remaining_life_days: float = -1  # -1=无法估计
    ci_lower_90: float = 0.0         # 90%置信下界
    ci_upper_90: float = 0.0
    event_count: int = 0             # 观测到的调用事件数
    censored: bool = True            # 当前观测是否为删失


@_dc
class GhostReport:
    """单个模块的幽灵检测结论。"""
    module_name: str
    ghost_score: float = 0.0
    is_ghost: bool = False
    # 分层信号
    static_score: float = 0.0
    survival_score: float = 0.0
    status_score: float = 0.0
    # 生存分析
    survival: SurvivalEstimate = None
    # 元数据
    has_dependents: bool = True
    has_call_records: bool = True
    has_valid_compat: bool = True
    status: str = ''
    days_since_last_call: float = -1
    recommended_action: str = 'keep'
    reason: str = ''


class GhostDetector:
    """基于生存分析的幽灵桩检测器。

    用K-M估计器建模"距下次调用的等待时间"。
    一个创建了300天但从未被调用的模块与一个创建了3天未被调用的模块，
    在二值判定中都是"无调用"，但生存分析给出截然不同的风险评分。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def detect(self) -> list[GhostReport]:
        contracts = self.contractor.scan_all()
        dep_graph = self._build_dep_graph()
        health_data = self._load_health_data()
        now = _time.time()

        reports = []
        for name, contract in contracts.items():
            if name.startswith('stub_'):
                continue

            dep_info = dep_graph.get(name, {})
            health_info = health_data.get(name, {})

            has_deps = len(dep_info.get('depended_by', [])) > 0
            call_count = health_info.get('call_count', 0)
            has_calls = call_count > 0
            has_compat = contract.has_compat_target
            last_seen = health_info.get('last_seen', 0)
            first_seen = health_info.get('first_seen', 0)

            # 静态评分: 依赖图+compat（不变）
            static = self._static_score(has_deps, has_compat)

            # 生存分析评分: K-M估计器
            intervals = self._extract_intervals(health_info, now)
            survival = self._kaplan_meier(intervals, last_seen, first_seen, now)
            surv_score = survival.ghost_risk if survival else 0.5

            # 状态评分
            status_s = self._status_score(contract.status)

            # 综合: 生存分析权重最高
            composite = 0.3 * static + 0.5 * surv_score + 0.2 * status_s

            days_since = ((now - last_seen) / 86400.0) if last_seen > 0 else -1

            action = self._recommend(composite, has_deps, has_calls, contract.status)
            reasons = self._compose_reason(static, surv_score, status_s,
                                          survival, days_since)

            reports.append(GhostReport(
                module_name=name,
                ghost_score=round(composite, 3),
                is_ghost=composite >= 0.6,
                static_score=round(static, 3),
                survival_score=round(surv_score, 3),
                status_score=round(status_s, 3),
                survival=survival,
                has_dependents=has_deps,
                has_call_records=has_calls,
                has_valid_compat=has_compat,
                status=contract.status,
                days_since_last_call=round(days_since, 1) if days_since > 0 else -1,
                recommended_action=action,
                reason=reasons,
            ))

        reports.sort(key=lambda r: -r.ghost_score)
        return reports

    def ghost_candidates(self, min_score: float = 0.4) -> list[GhostReport]:
        return [r for r in self.detect() if r.ghost_score >= min_score]

    @staticmethod
    def _extract_intervals(health_info: dict, now: float) -> list[float]:
        """从健康数据提取调用间隔序列（秒）。

        优先使用 _type_observations 中的精确时间戳；
        降级使用 first_seen/last_seen/call_count 估算平均间隔。
        """
        timestamps = health_info.get('timestamps', [])
        if timestamps and len(timestamps) >= 2:
            sorted_ts = sorted(timestamps)
            return [sorted_ts[i+1] - sorted_ts[i]
                   for i in range(len(sorted_ts) - 1)]

        first = health_info.get('first_seen', 0)
        last = health_info.get('last_seen', 0)
        count = health_info.get('call_count', 0)
        if first > 0 and last > 0 and count >= 2:
            avg_interval = (last - first) / (count - 1)
            return [avg_interval] * (count - 1)

        return []

    @staticmethod
    def _kaplan_meier(intervals: list[float], last_seen: float,
                      first_seen: float, now: float) -> SurvivalEstimate:
        """Kaplan-Meier生存函数估计。

        intervals: 观测到的调用间隔（秒）
        last_seen: 末次调用时间戳
        first_seen: 首次调用时间戳
        now: 当前时间

        返回 SurvivalEstimate，其中:
          - survival_prob = P(距上次调用的等待 > current_gap)
          - ghost_risk = 1 - survival_prob
        """
        est = SurvivalEstimate()

        if not intervals:
            # 无调用记录: 当前距首次观测的时间作为删失观测
            if first_seen > 0:
                gap = now - first_seen
                est.survival_prob = 0.15  # 从未被调用 → 高幽灵风险
                est.ghost_risk = 0.85
                est.censored = True
            else:
                est.survival_prob = 0.10
                est.ghost_risk = 0.90
                est.censored = True
            return est

        est.event_count = len(intervals)

        # 排序间隔并计算K-M
        sorted_intervals = sorted(intervals)
        n = len(sorted_intervals)
        unique_times = []
        for t in sorted_intervals:
            if not unique_times or t - unique_times[-1] > 1e-9:
                unique_times.append(t)

        # K-M: S(t) = product(1 - d_i/n_i)
        surv = 1.0
        km_curve = [(0.0, 1.0)]  # (time, survival)
        i = 0
        for t in unique_times:
            while i < n and sorted_intervals[i] <= t:
                i += 1
            d = 1  # 每事件计数为1（精确数据）
            n_risk = n - i + 1
            if n_risk > 0:
                surv *= (1.0 - d / n_risk)
            km_curve.append((t, surv))

        # 当前距末次调用的时间
        if last_seen > 0:
            current_gap = now - last_seen
        else:
            current_gap = now - first_seen if first_seen > 0 else 86400 * 365

        # 在K-M曲线上插值 S(current_gap)
        surv_at_gap = 1.0
        for t, s in km_curve:
            if t <= current_gap:
                surv_at_gap = s
            else:
                break

        est.survival_prob = max(surv_at_gap, 0.01)
        est.ghost_risk = round(1.0 - est.survival_prob, 3)
        est.censored = (current_gap > (sorted_intervals[-1] if sorted_intervals else 0))

        # 中位剩余寿命: S(t) = 0.5 处的时间
        half_found = False
        for t, s in km_curve:
            if s <= 0.5 and not half_found:
                est.median_remaining_life_days = t / 86400.0
                half_found = True
                break
        if not half_found and km_curve:
            est.median_remaining_life_days = km_curve[-1][0] / 86400.0

        # Greenwood公式计算90%置信区间
        if len(km_curve) >= 2:
            var = surv_at_gap * surv_at_gap * sum(
                1.0 / max((n - i) * (n - i - 1), 1)
                for i in range(min(int(current_gap / max(sorted_intervals[0], 1)), n)))
            se = _math.sqrt(max(var, 0.0))
            z = 1.645  # 90% CI
            est.ci_lower_90 = round(max(surv_at_gap - z * se, 0.0), 3)
            est.ci_upper_90 = round(min(surv_at_gap + z * se, 1.0), 3)

        return est

    @staticmethod
    def _static_score(has_deps: bool, has_compat: bool) -> float:
        s = 0.0
        if not has_deps:
            s += 0.6
        if not has_compat:
            s += 0.4
        return s

    @staticmethod
    def _status_score(status: str) -> float:
        return {
            _Status.MISSING.value: 0.9,
            _Status.PLACEHOLDER.value: 0.7,
            _Status.UNPARSEABLE.value: 0.6,
            _Status.RE_EXPORT.value: 0.3,
            _Status.MIXED.value: 0.15,
            _Status.IMPLEMENTED.value: 0.0,
        }.get(status, 0.4)

    @staticmethod
    def _compose_reason(static: float, surv: float, status_s: float,
                        se: SurvivalEstimate, days: float) -> str:
        parts = []
        if static > 0.5:
            parts.append('no dependents/compat')
        if surv > 0.5:
            ci = ''
            if se and se.ci_lower_90 > 0:
                ci = f' [90%CI:{se.ci_lower_90:.2f}-{se.ci_upper_90:.2f}]'
            parts.append(f'survival risk={surv:.2f}{ci}')
        if days > 180:
            parts.append(f'last seen {days:.0f}d ago')
        if se and se.median_remaining_life_days > 0:
            parts.append(f'median life {se.median_remaining_life_days:.0f}d')
        return '; '.join(parts) if parts else 'active'

    @staticmethod
    def _recommend(score: float, has_deps: bool, has_calls: bool,
                   status: str) -> str:
        if score >= 0.85:
            return 'archive_or_remove'
        if score >= 0.6:
            return 'deprecate_and_remove' if status == _Status.PLACEHOLDER.value else 'review_for_removal'
        if score >= 0.4:
            return 'monitor'
        return 'keep'

    def _build_dep_graph(self) -> dict:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
            return {
                name: {
                    'depended_by': sorted(node.depended_by),
                    'imports_from': sorted(node.imports_from),
                    'topo_depth': node.topo_depth,
                }
                for name, node in g.nodes.items()
            }
        except ImportError:
            return {}

    @staticmethod
    def _load_health_data() -> dict:
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            records = getattr(mon, '_records', {})
            type_obs = getattr(mon, '_type_observations', {})
            result = {}
            for name, rec in records.items():
                timestamps = []
                prefix = f'{name}::'
                for key, obs_list in type_obs.items():
                    if key.startswith(prefix):
                        timestamps.extend(o.get('ts', 0) for o in obs_list)
                result[name] = {
                    'call_count': rec.call_count,
                    'last_seen': rec.last_seen,
                    'first_seen': rec.first_seen,
                    'callers': dict(rec.caller_modules),
                    'timestamps': sorted(timestamps),
                }
            return result
        except ImportError:
            return {}

    def summary_report(self, reports: list[GhostReport] = None) -> str:
        if reports is None:
            reports = self.detect()
        ghosts = [r for r in reports if r.is_ghost]
        lines = [
            '# Ghost Detection Report (Survival Analysis)',
            f'Total: {len(reports)} | Ghosts: {len(ghosts)}',
            '',
        ]
        if ghosts:
            lines.append('| Module | Score | Survival | MedianLife | 90%CI | Action |')
            lines.append('|--------|------:|---------:|-----------:|-------|--------|')
            for g in ghosts[:20]:
                se = g.survival
                ci = f'{se.ci_lower_90:.2f}-{se.ci_upper_90:.2f}' if se else 'N/A'
                ml = f'{se.median_remaining_life_days:.0f}d' if se and se.median_remaining_life_days > 0 else 'N/A'
                lines.append(
                    f'| {g.module_name} | {g.ghost_score:.2f} | '
                    f'{g.survival_score:.2f} | {ml} | {ci} | '
                    f'{g.recommended_action} |')
        return '\n'.join(lines)


def detect_ghost_stubs(min_score: float = 0.4) -> list[GhostReport]:
    return GhostDetector().ghost_candidates(min_score)


__all__ = ['SurvivalEstimate', 'GhostReport', 'GhostDetector', 'detect_ghost_stubs']
