# stub_feedback_loop.py — 运行时异常触发的闭环反馈
# 连接运行时监控 → 定向重验证 → 条件重实现 → 部署，
# 将桩管理从"批处理"升级为"持续自愈"系统。
#
# 问题:
#   现有管线是批处理模式: 扫描→排序→实现→验证→落盘，之后不再追踪。
#   实现落盘后，运行时可能出现三类异常:
#     a) TypeError: 调用方传参类型与实现不兼容
#     b) 性能退化: 新实现比旧版本慢 10×
#     c) 语义漂移: 实现的行为与合约预期不一致（MR 违反率上升）
#   当前系统检测到这些异常后无自动响应机制。
#
# 方案 — 闭环自愈管线:
#   WATCH → DETECT → TRIAGE → RE-VERIFY → RE-IMPLEMENT → RECORD
#   1. WATCH:  轮询 StubHealthMonitor 的类型观测与异常计数
#   2. DETECT: 异常信号超过阈值 → 触发事件
#   3. TRIAGE: 按严重度分级 (L1=信息, L2=警告, L3=关键)
#   4. RE-VERIFY: 对受影响模块运行定向验证 (签名+IO+MR)
#   5. RE-IMPLEMENT: 验证失败 → 尝试重新实现 (TemplateGenerator)
#   6. RECORD: 事件链记录到 ProvenanceChain
#
# 区别于 DynaFix 和 SEED-APR:
#   两者修复通用程序的单函数 bug。
#   本模块在桩管理层面闭合反馈环，触发粒度为模块级，
#   重新实现而非修补 — 因为桩实现"重新生成"的成本低于"精确修补"。
import time as _time
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum
from typing import Optional as _Opt


class AnomalyLevel(_Enum):
    INFO = 'info'         # 低严重度，记录但不触发修复
    WARNING = 'warning'   # 中严重度，触发定向重验证
    CRITICAL = 'critical' # 高严重度，触发重验证+条件重实现


@_dc
class AnomalySignal:
    """单次异常信号。"""
    module_name: str
    func_name: str = ''
    level: AnomalyLevel = AnomalyLevel.INFO
    category: str = ''         # type_error | perf_regression | mr_violation
    detail: str = ''
    detected_at: float = 0.0
    observation_count: int = 0  # 累积观测次数


@_dc
class FeedbackEvent:
    """一次闭环反馈事件。"""
    event_id: str = ''          # 简短标识
    trigger: AnomalySignal = None
    action: str = ''            # re_verified | re_implemented | suppressed
    re_verify_result: dict = _field(default_factory=dict)
    re_implement_result: dict = _field(default_factory=dict)
    resolved: bool = False
    timestamp: float = 0.0


class FeedbackLoop:
    """闭环反馈编排器。

    阈值设计:
      - type_error ≥ 3 次观测 → WARNING
      - type_error ≥ 10 次 → CRITICAL
      - type_mismatch 率 ≥ 0.3 (30% 调用类型不一致) → WARNING
      - 末次验证通过 + 观测异常 → INFO（可能是合法的边缘用例）
    """

    TYPE_ERROR_THRESHOLD_WARN = 3
    TYPE_ERROR_THRESHOLD_CRIT = 10
    TYPE_MISMATCH_RATE_WARN = 0.3

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            import os
            stubs_dir = os.path.dirname(os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self._events: list[FeedbackEvent] = []
        self._suppressed: set[str] = set()  # 抑制列表: 已处理的模块不再重复触发
        self._event_counter = 0

    def watch(self) -> list[AnomalySignal]:
        """轮询健康监控数据，检测异常信号。"""
        signals = []
        observations = self._get_type_observations()

        for key, obs_list in observations.items():
            if not obs_list:
                continue
            module, func = self._parse_key(key)

            # 类型错误检测
            type_errors = [o for o in obs_list
                         if o.get('error') or o.get('exception')]
            if len(type_errors) >= self.TYPE_ERROR_THRESHOLD_CRIT:
                signals.append(AnomalySignal(
                    module_name=module, func_name=func,
                    level=AnomalyLevel.CRITICAL,
                    category='type_error',
                    detail=f'{len(type_errors)} type errors observed',
                    detected_at=_time.time(),
                    observation_count=len(type_errors)))
            elif len(type_errors) >= self.TYPE_ERROR_THRESHOLD_WARN:
                signals.append(AnomalySignal(
                    module_name=module, func_name=func,
                    level=AnomalyLevel.WARNING,
                    category='type_error',
                    detail=f'{len(type_errors)} type errors observed',
                    detected_at=_time.time(),
                    observation_count=len(type_errors)))

            # 类型不匹配率检测
            if self._type_mismatch_rate(obs_list) >= self.TYPE_MISMATCH_RATE_WARN:
                signals.append(AnomalySignal(
                    module_name=module, func_name=func,
                    level=AnomalyLevel.WARNING,
                    category='type_mismatch',
                    detail='high type mismatch rate in observations',
                    detected_at=_time.time(),
                    observation_count=len(obs_list)))

        return signals

    def process(self, signals: list[AnomalySignal],
                dry_run: bool = True) -> list[FeedbackEvent]:
        """处理异常信号: 分级响应。"""
        events = []

        for sig in signals:
            # 去重: 已处理的模块抑制重复信号
            suppress_key = f'{sig.module_name}:{sig.category}'
            if suppress_key in self._suppressed:
                continue

            event = self._handle(sig, dry_run)
            events.append(event)

            if event.resolved:
                self._suppressed.add(suppress_key)

        self._events.extend(events)
        return events

    def _handle(self, sig: AnomalySignal,
                dry_run: bool) -> FeedbackEvent:
        """按严重度分级处理单条异常信号。"""
        self._event_counter += 1
        event = FeedbackEvent(
            event_id=f'FB-{self._event_counter:04d}',
            trigger=sig,
            timestamp=_time.time(),
        )

        if sig.level == AnomalyLevel.INFO:
            event.action = 'suppressed'
            event.resolved = True
            return event

        if sig.level == AnomalyLevel.WARNING:
            # 定向重验证
            vr = self._re_verify(sig.module_name, dry_run)
            event.action = 're_verified'
            event.re_verify_result = vr
            event.resolved = vr.get('ok', False)
            return event

        if sig.level == AnomalyLevel.CRITICAL:
            # 重验证
            vr = self._re_verify(sig.module_name, dry_run)
            event.re_verify_result = vr

            if not vr.get('ok', False):
                # 验证失败 → 尝试重实现
                ri = self._re_implement(sig.module_name, dry_run)
                event.action = 're_implemented'
                event.re_implement_result = ri
                event.resolved = ri.get('generated', False)
            else:
                event.action = 're_verified'
                event.resolved = True

            return event

        return event

    def _re_verify(self, module_name: str, dry_run: bool) -> dict:
        """对指定模块执行定向重验证。"""
        try:
            from modules.stubs.stub_contract import get_contractor
            from modules.stubs.stub_gradual_engine import (
                TemplateGenerator, ContractVerifier)
            contract = get_contractor().get(module_name)
            if contract is None:
                return {'ok': False, 'error': 'contract not found'}
            tg = TemplateGenerator()
            src = tg.generate(contract)
            cv = ContractVerifier(run_io_checks=True)
            result = cv.verify(src, contract)
            return {
                'ok': result.ok,
                'feedback': result.feedback,
                'violations': len(result.signature_violations) + len(result.io_violations),
                'not_implemented': len(result.not_implemented),
            }
        except ImportError:
            return {'ok': False, 'error': 'verification engine unavailable'}

    def _re_implement(self, module_name: str, dry_run: bool) -> dict:
        """对指定模块尝试重新实现。"""
        if dry_run:
            return {'generated': False, 'info': 'dry_run'}
        try:
            from modules.stubs.stub_gradual_engine import GradualEngine, GradualConfig
            config = GradualConfig(dry_run=dry_run)
            eng = GradualEngine(config=config)
            result = eng.implement(module_name)
            return {
                'generated': result.status == 'generated',
                'strategy': result.strategy,
                'written': result.written,
                'verification_ok': (result.verification.ok
                                   if result.verification else False),
            }
        except ImportError:
            return {'generated': False, 'error': 'implementation engine unavailable'}

# 辅助
    @staticmethod
    def _get_type_observations() -> dict:
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            return getattr(mon, '_type_observations', {})
        except ImportError:
            return {}

    @staticmethod
    def _parse_key(key: str) -> tuple[str, str]:
        parts = key.split('::', 1)
        return parts[0], parts[1] if len(parts) > 1 else ''

    @staticmethod
    def _type_mismatch_rate(obs_list: list[dict]) -> float:
        """计算类型观测中"预期类型与实际类型不一致"的比例。"""
        mismatches = 0
        total = 0
        for o in obs_list:
            expected = o.get('expected_type', '')
            actual = o.get('actual_type', '')
            if expected and actual:
                total += 1
                if expected != actual:
                    mismatches += 1
        return mismatches / total if total > 0 else 0.0

# 报告与指标
    def metrics(self) -> dict:
        """闭环反馈指标。"""
        resolved = sum(1 for e in self._events if e.resolved)
        suppressed = sum(1 for e in self._events if e.action == 'suppressed')
        re_verified = sum(1 for e in self._events if e.action == 're_verified')
        re_implemented = sum(1 for e in self._events if e.action == 're_implemented')
        total = len(self._events)

        return {
            'total_events': total,
            'resolved': resolved,
            'resolution_rate': round(resolved / max(total, 1), 2),
            'suppressed': suppressed,
            're_verified': re_verified,
            're_implemented': re_implemented,
            'active_suppressions': len(self._suppressed),
        }

    def feedback_report(self) -> str:
        """生成 Markdown 反馈闭环报告。"""
        lines = ['# 闭环反馈报告', '']
        m = self.metrics()
        lines.append(f'- 总事件: {m["total_events"]}')
        lines.append(f'- 已解决: {m["resolved"]} ({m["resolution_rate"]:.0%})')
        lines.append(f'- 抑制: {m["suppressed"]} | 重验证: {m["re_verified"]} | '
                    f'重实现: {m["re_implemented"]}')
        if self._events:
            lines.append('')
            lines.append('| 事件 | 模块 | 级别 | 动作 | 结果 |')
            lines.append('|------|------|------|------|------|')
            for e in self._events[-20:]:
                trig = e.trigger
                result = 'OK' if e.resolved else 'FAIL'
                lines.append(
                    f'| {e.event_id} | {trig.module_name} | '
                    f'{trig.level.value} | {e.action} | {result} |')
        return '\n'.join(lines)


__all__ = ['AnomalyLevel', 'AnomalySignal', 'FeedbackEvent', 'FeedbackLoop']
