# stub_prioritizer.py — 实现优先级排序引擎
# 依据健康监控得分 + 调用频率 + 契约复杂度 + 实现状态，对 stubs/ 下模块
# 输出"先实现谁"的排序清单，驱动 stub_gradual_engine 的增量实现顺序。
# 设计意图：资源受限时（无 API 的规则降级、人工 review 预算），
# 用量化优先级信号替代拍脑袋，聚焦高影响缺口。
import time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    ImplementationStatus as _Status,
    StubContract as _StubContract,
    StubContractor as _StubContractor,
)
from modules.stubs.stub_health_monitor import StubHealthMonitor as _Monitor, StubCallRecord
from modules.stubs.stub_registry import StubRegistry as _Registry, get_registry as _get_registry

# 排序权重默认值 — "实现优先级"语义下缺口应主导（gap=0.40），
# 健康(0.20)与调用量(0.20)提供使用强度调制，复杂度(0.15)次之。
# 依据: 实现优先级 = "先补缺口大且被频繁引用的模块"。
@_dc
class PriorityWeights:
    health: float = 0.20    # 健康监控得分权重（废弃候选/低调用惩罚）
    complexity: float = 0.15  # 契约复杂度权重（高复杂度优先实现以释放人工预算）
    gap: float = 0.40       # 实现缺口权重（placeholder/missing 优先）
    call_volume: float = 0.20  # 调用频率权重（高使用量优先）
    recency: float = 0.05   # 最近调用时间权重（新近活跃优先）

    @classmethod
    def balanced(cls) -> 'PriorityWeights':
        return cls()

    @classmethod
    def health_driven(cls) -> 'PriorityWeights':
        """健康导向配置 — 强调活跃度与调用量，弱化缺口信号。"""
        return cls(health=0.45, complexity=0.15, gap=0.15,
                   call_volume=0.20, recency=0.05)

@_dc
class StubPriority:
    """单个模块的优先级评估结果。"""
    module_name: str
    status: str
    total_score: float = 0.0
    rank: int = 0
    health_score: float = 0.0
    complexity_score: float = 0.0
    gap_score: float = 0.0
    call_volume_score: float = 0.0
    recency_score: float = 0.0
    call_count: int = 0
    callers: list = _field(default_factory=list)
    reason: str = ''

    def to_dict(self) -> dict:
        return {
            'module_name': self.module_name, 'status': self.status,
            'rank': self.rank, 'total_score': round(self.total_score, 4),
            'health_score': round(self.health_score, 4),
            'complexity_score': round(self.complexity_score, 4),
            'gap_score': round(self.gap_score, 4),
            'call_volume_score': round(self.call_volume_score, 4),
            'recency_score': round(self.recency_score, 4),
            'call_count': self.call_count, 'callers': self.callers,
            'reason': self.reason,
        }


class ImplementationPrioritizer:
    """实现优先级排序器 — 整合健康监控、注册表与契约扫描器三维数据。"""

    def __init__(self, monitor: _Opt[_Monitor] = None,
                 registry: _Opt[_Registry] = None,
                 contractor: _Opt[_StubContractor] = None,
                 weights: _Opt[PriorityWeights] = None):
        self.monitor = monitor or _Monitor()
        self.registry = registry if registry is not None else _get_registry()
        self.contractor = contractor or _StubContractor()
        self.weights = weights or PriorityWeights.balanced()
        self._priorities: dict[str, StubPriority] = {}
        self._now = _time.time()

    def _health_score(self, rec: _Opt[StubCallRecord]) -> float:
        """健康得分 — 废弃候选或低调用量取 0，正常桩取 1。"""
        if rec is None:
            return 0.5  # 无观测记录：中性值，交由其他维度判定
        if rec.deprecation_candidate:
            return 0.0
        # 近 30 天有调用 → 健康；否则按调用密度线性衰减
        if self._now - rec.last_seen < 30 * 86400:
            return 1.0
        return max(0.0, 1.0 - (self._now - rec.last_seen) / (365 * 86400))

    def _complexity_score(self, contract: _Opt[_StubContract]) -> float:
        if contract is None or not contract.functions:
            return 0.3
        w = {'low': 0.2, 'medium': 0.6, 'high': 1.0}
        if len(contract.functions) == 1:
            return w.get(contract.functions[0].complexity, 0.2)
        return max(w.get(f.complexity, 0.2) for f in contract.functions)

    def _gap_score(self, status: str) -> float:
        """实现缺口 — 越接近纯占位状态，得分越高。"""
        return {
            _Status.MISSING.value: 1.0,
            _Status.PLACEHOLDER.value: 0.9,
            _Status.UNPARSEABLE.value: 0.7,
            _Status.RE_EXPORT.value: 0.3,
            _Status.MIXED.value: 0.1,
            _Status.IMPLEMENTED.value: 0.0,
        }.get(status, 0.5)

    def _call_volume_score(self, rec: _Opt[StubCallRecord]) -> float:
        if rec is None or rec.call_count <= 0:
            return 0.0
        return min(1.0, rec.call_count / 100.0)  # 100 次调用封顶

    def _recency_score(self, rec: _Opt[StubCallRecord]) -> float:
        if rec is None or rec.last_seen <= 0:
            return 0.0
        age_days = (self._now - rec.last_seen) / 86400.0
        if age_days < 7:
            return 1.0
        return max(0.0, 1.0 - age_days / 90.0)

    def rank(self) -> list:
        """计算全部模块优先级并返回降序排序清单。"""
        self._priorities = {}
        contracts = self.contractor.scan_all()
        # 访问 StubHealthMonitor 内部记录表；该表无公开查询接口，
        # 同模块族内按约定访问（防御性 getattr 兜底）。
        records = getattr(self.monitor, '_records', {})
        # 并集处理：运行期被引用但磁盘上不存在的模块（MISSING）
        # 必须进入排序，因其实现缺口最大。
        for name in sorted(set(contracts) | set(records)):
            contract = contracts.get(name)
            if contract is None:
                contract = self.contractor.build_contract(name)
            rec = records.get(name)
            hs = self._health_score(rec)
            cs = self._complexity_score(contract)
            gs = self._gap_score(contract.status)
            vs = self._call_volume_score(rec)
            rs = self._recency_score(rec)
            w = self.weights
            total = (w.health * hs + w.complexity * cs + w.gap * gs +
                     w.call_volume * vs + w.recency * rs)
            sp = StubPriority(
                module_name=name, status=contract.status, total_score=total,
                health_score=hs, complexity_score=cs, gap_score=gs,
                call_volume_score=vs, recency_score=rs,
                call_count=rec.call_count if rec else 0,
                callers=sorted(rec.caller_modules.keys()) if rec else [],
                reason=self._compose_reason(contract.status, hs, gs, vs),
            )
            self._priorities[name] = sp

        ordered = sorted(self._priorities.values(),
                         key=lambda p: p.total_score, reverse=True)
        for i, p in enumerate(ordered, start=1):
            p.rank = i
        return ordered

    def _compose_reason(self, status: str, hs: float, gs: float, vs: float) -> str:
        reasons = []
        if gs >= 0.9:
            reasons.append('纯占位/缺失')
        elif gs >= 0.7:
            reasons.append('语法损坏')
        if hs == 0.0:
            reasons.append('健康度低')
        if vs > 0.5:
            reasons.append('高调用量')
        if not reasons:
            reasons.append('常规')
        return ';'.join(reasons)

    def get(self, module_name: str) -> _Opt[StubPriority]:
        return self._priorities.get(module_name)

    def top(self, n: int = 10) -> list:
        """返回优先级最高的前 n 个。"""
        return self.rank()[:n]

    def implementation_backlog(self, n: _Opt[int] = None) -> list:
        """可行动清单 — 仅保留存在实现缺口的模块（gap>0），按综合分降序。
        与 rank() 的区别：rank 包含已实现热模块（提供健康上下文），
        backlog 直接回答"下一个实现谁"。"""
        backlog = [p for p in self.rank() if p.gap_score > 0.0]
        if n is not None:
            backlog = backlog[:n]
        return backlog

    def dependency_aware_backlog(self, n: _Opt[int] = None) -> list[str]:
        """拓扑约束下的实现积压清单 — 在可行性集中按优先级排序。

        依赖关系从跨模块 import/call AST 分析中提取。
        无依赖图可用时降级为普通 backlog 的模块名列表。
        """
        try:
            from modules.stubs.stub_dependency_graph import (
                ModuleDependencyGraph, TopologicalScheduler)
            dep_graph = ModuleDependencyGraph()
            dep_graph.build()
            scheduler = TopologicalScheduler(dep_graph)
            priorities = {p.module_name: p.total_score for p in self.rank()}
            ordered = scheduler.scheduled_order(priorities)
            if n is not None:
                ordered = ordered[:n]
            return ordered
        except ImportError:
            backlog = self.implementation_backlog(n)
            return [p.module_name for p in backlog]

    def generate_priority_report(self, top_n: int = 20) -> str:
        """输出 Markdown 排序清单报告。"""
        rows = self.rank()[:top_n]
        lines = [
            '# 桩实现优先级清单',
            f'生成时间: {_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'覆盖模块: {len(self._priorities)}',
            '',
            '| 排名 | 模块 | 状态 | 总分 | 健康 | 复杂度 | 缺口 | 调用量 | 理由 |',
            '|-----:|------|------|-----:|-----:|-------:|-----:|-------:|------|',
        ]
        for p in rows:
            lines.append(
                f'| {p.rank} | {p.module_name} | {p.status} | {p.total_score:.3f} | '
                f'{p.health_score:.2f} | {p.complexity_score:.2f} | {p.gap_score:.2f} | '
                f'{p.call_volume_score:.2f} | {p.reason} |')
        return '\n'.join(lines)


def rank_implementation_priority(monitor: _Opt[_Monitor] = None, top_n: int = 10) -> list:
    """一行式排序入口：monitor 为 None 时使用默认健康监控实例。"""
    prior = ImplementationPrioritizer(monitor=monitor)
    return prior.top(top_n)


__all__ = ['PriorityWeights', 'StubPriority', 'ImplementationPrioritizer',
           'rank_implementation_priority']
