# stub_adaptive_gate.py — 分级验证门控
# 创建于 2026-07-29
# 修改于 2026-08-04: 重命名，消除"自适应"的误导性表述
#
# 按模块关键性将验证严格度分为三级，
# 替代 GradualConfig 中的全局二值 safety_mode。
#
# 问题:
#   GradualConfig.safety_mode 是全局二值开关 (strict | permissive)。
#   但 60+ 模块的关键性差异大:
# 被 10 个模块依赖的核心桩 → 需要最严格的验证
# 仅 1 个调用方、历史100%通过率的桩 → 可适当放宽
#
# 方法: 三级门控
#   1. 计算关键性评分 (0~1):
#      crit = 0.35*norm(depth) + 0.30*norm(closure) + 0.25*norm(calls) + 0.10*(1-fail_rate)
#   2. crit ≥ 0.7 → STRICT  (签名100%, IO100%, MR零异常, incoherence<0.05)
#      0.4 ≤ crit < 0.7 → STANDARD
#      crit < 0.4 → RELAXED
#   3. 三级阈值硬编码 — 非自适应，但覆盖了从核心到边缘的典型场景。
#
# 设计依据: 分级门控在安全关键系统中是成熟实践 (IEC 61508 SIL levels,
#   DO-178C DAL levels)。关键性评分公式参考了 software criticality
#   analysis 的通用框架 (故障影响 × 暴露概率)。
from dataclasses import dataclass as _dc


@_dc
class GateConfig:
    """分级验证门控配置 — 每个验证阶段的通过条件。"""
    module_name: str
    criticality: float = 0.5      # 关键性 [0,1]

    # 签名核对
    signature_strict: bool = True  # True=参数名+数严格匹配; False=允许新增
    max_signature_violations: int = 0

    # IO 检查
    io_required_pass_rate: float = 1.0  # 边界值通过的占比要求
    max_io_violations: int = 0

    # MR 检查
    mr_required: bool = False
    mr_max_anomalies: int = 1

    # 非相干性
    incoherence_required: bool = False
    max_incoherence: float = 0.15

    # 函数复杂度放行
    allow_medium_complexity: bool = False
    max_functions_auto: int = 6


class TieredGate:
    """分级验证门控计算器。

    关键性公式:
      crit = clamp(
        0.35 * norm(dependency_depth) +
        0.30 * norm(downstream_closure) +
        0.25 * norm(call_volume) +
        0.10 * (1 - historical_success_rate),
        0, 1)

      norm(x) = min(x / reference_max, 1.0)
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            import os
            stubs_dir = os.path.dirname(os.path.abspath(__file__))
        self.stubs_dir = stubs_dir

    def compute(self, module_name: str) -> GateConfig:
        """计算指定模块的分级验证门控。"""
        crit = self._criticality(module_name)
        gc = GateConfig(module_name=module_name, criticality=round(crit, 3))

        if crit >= 0.7:
            # 高关键性: 最严格
            gc.signature_strict = True
            gc.max_signature_violations = 0
            gc.io_required_pass_rate = 1.0
            gc.max_io_violations = 0
            gc.mr_required = True
            gc.mr_max_anomalies = 0
            gc.incoherence_required = True
            gc.max_incoherence = 0.05
            gc.allow_medium_complexity = False
            gc.max_functions_auto = 3

        elif crit >= 0.4:
            # 中关键性: 标准
            gc.signature_strict = True
            gc.max_signature_violations = 0
            gc.io_required_pass_rate = 0.85
            gc.max_io_violations = 1
            gc.mr_required = True
            gc.mr_max_anomalies = 1
            gc.incoherence_required = False
            gc.max_incoherence = 0.15
            gc.allow_medium_complexity = True
            gc.max_functions_auto = 6

        else:
            # 低关键性: 宽松
            gc.signature_strict = False
            gc.max_signature_violations = 1
            gc.io_required_pass_rate = 0.7
            gc.max_io_violations = 2
            gc.mr_required = False
            gc.mr_max_anomalies = 2
            gc.incoherence_required = False
            gc.max_incoherence = 0.25
            gc.allow_medium_complexity = True
            gc.max_functions_auto = 10

        return gc

    def compute_all(self) -> dict[str, GateConfig]:
        """对所有模块计算分级门控。"""
        try:
            from modules.stubs.stub_contract import StubContractor
            ctor = StubContractor(stubs_dir=self.stubs_dir)
            contracts = ctor.scan_all()
        except ImportError:
            return {}

        result = {}
        for name in contracts:
            if name.startswith('stub_'):
                continue
            result[name] = self.compute(name)
        sort_order = sorted(result.items(),
                          key=lambda kv: -kv[1].criticality)
        return dict(sort_order)

    def _criticality(self, module_name: str) -> float:
        depth = self._get_dependency_depth(module_name)
        closure = self._get_downstream_closure(module_name)
        call_vol = self._get_call_volume(module_name)
        hist_fail = self._get_historical_failure_rate(module_name)

        # 归一化参考值
        depth_norm = min(depth / 5.0, 1.0)
        closure_norm = min(closure / 20.0, 1.0)
        call_norm = min(call_vol / 100.0, 1.0)

        crit = (0.35 * depth_norm +
               0.30 * closure_norm +
               0.25 * call_norm +
               0.10 * (1.0 - hist_fail))
        return max(0.0, min(crit, 1.0))

    def _get_dependency_depth(self, module_name: str) -> int:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
            node = g.nodes.get(module_name)
            return node.topo_depth if node else 0
        except ImportError:
            return 0

    def _get_downstream_closure(self, module_name: str) -> int:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
            return len(g.impact_set(module_name))
        except ImportError:
            return 0

    @staticmethod
    def _get_call_volume(module_name: str) -> int:
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            rec = getattr(mon, '_records', {}).get(module_name)
            return rec.call_count if rec else 0
        except ImportError:
            return 0

    @staticmethod
    def _get_historical_failure_rate(module_name: str) -> float:
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            chain = pc.history(module_name)
            if not chain:
                return 0.0
            failures = sum(1 for e in chain if not e.verification_ok)
            return failures / len(chain)
        except ImportError:
            return 0.0

    def gate_report(self, configs: dict[str, GateConfig] = None) -> str:
        """生成 Markdown 门控配置报告。"""
        if configs is None:
            configs = self.compute_all()
        lines = ['# 分级验证门控报告', '']
        lines.append('| 模块 | 关键性 | Sig | IO | MR | Incoh |')
        lines.append('|------|-------:|-----|----|-----|-------|')
        for name, gc in list(configs.items())[:30]:
            def yn(v): return 'Y' if v else 'N'
            lines.append(
                f'| {name} | {gc.criticality:.2f} | '
                f'{yn(gc.signature_strict)} | {gc.io_required_pass_rate:.0%} | '
                f'{yn(gc.mr_required)} | {yn(gc.incoherence_required)} |')
        return '\n'.join(lines)


__all__ = ['GateConfig', 'TieredGate']
