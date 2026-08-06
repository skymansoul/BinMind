# -*- coding: utf-8 -*-
# 创建: 2026-08-04  |  跨模块集成管线入口
# 修改: 2026-08-04  |  审计后补充
# 修改: 2026-08-05  |  二次审计修复 2026-08-04  |  审计后新增——串联17个子系统的统一入口
#
"""
跨模块集成管线——串联17个子系统的统一分析与报告生成。

管线阶段:
  1. 发现: CADE + PHS → 异常函数 + 指针危险评分
  2. 检测: CSSA(若崩溃可用) + BYRS(YARA规则生成)
  3. 溯源: TVP(若仓库可用) → 漏洞引入追溯
  4. 预测: MEWF → 武器化概率 + RAVO → 修复优先级
  5. 关联: CMVC → 跨模态证据关联 + 确认链
  6. 防御: EPASS → seccomp策略生成
  7. 运维: VDDA → 若有基线运行则生成增量报告

输出: UnifiedVulnReport — JSON序列化的统一漏洞情报报告。

设计约束:
  - 每个阶段是可选的——根据输入数据的可用性自动跳过
  - 单阶段失败不影响其他阶段
  - 全阶段完成后聚合为统一报告
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


@dataclass
class StageResult:
    stage_name: str
    success: bool
    output: Any = None
    error: str = ""
    elapsed_ms: float = 0.0


@dataclass
class UnifiedVulnReport:
    """统一漏洞情报报告——17个子系统的聚合输出"""
    binary_name: str
    generated_at: str = ""
    # 发现阶段
    anomalies: Optional[Any] = None        # CADE输出
    pointer_hazards: Optional[Any] = None  # PHS输出
    # 检测阶段
    crash_analysis: Optional[Any] = None   # CSSA输出
    yara_rules: Optional[Any] = None       # BYRS输出
    # 溯源阶段
    provenance: Optional[Any] = None       # TVP输出
    # 预测阶段
    weaponization: Optional[Any] = None    # MEWF输出
    fix_schedule: Optional[Any] = None     # RAVO输出
    # 关联阶段
    correlation: Optional[Any] = None      # CMVC输出
    # 防御阶段
    sandbox_policies: Optional[Any] = None # EPASS输出
    # 运维阶段
    delta_report: Optional[Any] = None     # VDDA输出
    # 元数据
    stages: List[StageResult] = field(default_factory=list)
    total_elapsed_ms: float = 0.0


class IntegrationPipeline:
    """跨模块集成管线——按序执行各阶段并聚合结果。"""

    def __init__(self):
        self._stages: List[StageResult] = []

    def run(self, **inputs) -> UnifiedVulnReport:
        """执行完整集成管线——所有阶段输入均为可选, 缺失则跳过。"""
        report = UnifiedVulnReport(
            binary_name=inputs.get('binary_name', 'unknown'),
            generated_at=datetime.now(timezone.utc).isoformat())
        t0 = time.time()
        # 阶段间共享上下文——前序阶段产出可被后续阶段消费
        ctx: Dict[str, Any] = dict(inputs)

        # Phase 1: 发现
        self._run_stage('CADE', report, ctx, self._run_cade)
        self._run_stage('PHS', report, ctx, self._run_phs)

        # Phase 2: 检测
        self._run_stage('CSSA', report, ctx, self._run_cssa)
        self._run_stage('BYRS', report, ctx, self._run_byrs)

        # Phase 3: 溯源
        self._run_stage('TVP', report, ctx, self._run_tvp)

        # Phase 4: 预测 —— MEWF输出流入RAVO
        self._run_stage('MEWF', report, ctx, self._run_mewf)
        # 将MEWF武器化概率注入漏洞列表供RAVO消费
        self._inject_weaponization(ctx, report)
        self._run_stage('RAVO', report, ctx, self._run_ravo)

        # Phase 5: 关联 —— CADE/PHS异常流入CMVC
        self._inject_anomalies_to_correlation(ctx, report)
        self._run_stage('CMVC', report, ctx, self._run_cmvc)

        # Phase 6: 防御
        self._run_stage('EPASS', report, ctx, self._run_epass)

        # Phase 7: 运维
        self._run_stage('VDDA', report, ctx, self._run_vdda)

        report.stages = self._stages
        report.total_elapsed_ms = round((time.time() - t0) * 1000, 1)
        return report

    def _inject_weaponization(self, ctx: Dict, report: UnifiedVulnReport):
        if report.weaponization is None:
            return
        vulns = ctx.get('vulnerabilities')
        if not vulns:
            return
        wf_list = report.weaponization if isinstance(
            report.weaponization, list) else [report.weaponization]
        for i, v in enumerate(vulns):
            if i < len(wf_list):
                v['weapon_prob'] = wf_list[i].weaponization_probability_30d

    def _inject_anomalies_to_correlation(self, ctx: Dict,
                                           report: UnifiedVulnReport):
        if report.anomalies is None:
            return
        findings = ctx.get('findings_by_modality', {})
        from .cade_engine import CadeReport
        cade = report.anomalies
        if isinstance(cade, CadeReport) and cade.findings:
            cade_findings = [{
                'function_name': af.function_name,
                'type': 'structural_anomaly',
                'confidence': af.anomaly_score,
                'modality': 'cade_anomaly',
            } for af in cade.findings[:20]]
            findings['cade_anomaly'] = cade_findings
            ctx['findings_by_modality'] = findings

    def _run_stage(self, name: str, report: UnifiedVulnReport,
                    inputs: Dict, runner):
        t0 = time.time()
        try:
            result = runner(inputs)
            if result is not None:
                setattr(report, self._field_for(name), result)
            self._stages.append(StageResult(
                stage_name=name, success=True, output=result,
                elapsed_ms=round((time.time() - t0) * 1000, 1)))
        except Exception as e:
            _log.warning('阶段%s失败: %s', name, e)
            self._stages.append(StageResult(
                stage_name=name, success=False, error=str(e),
                elapsed_ms=round((time.time() - t0) * 1000, 1)))

    def _field_for(self, name: str) -> str:
        return {
            'CADE': 'anomalies', 'PHS': 'pointer_hazards',
            'CSSA': 'crash_analysis', 'BYRS': 'yara_rules',
            'TVP': 'provenance', 'MEWF': 'weaponization',
            'RAVO': 'fix_schedule', 'CMVC': 'correlation',
            'EPASS': 'sandbox_policies', 'VDDA': 'delta_report',
        }.get(name, '')

    # ---- 各阶段实现 ----

    def _run_cade(self, inputs: Dict):
        profiles = inputs.get('function_profiles')
        if not profiles:
            return None
        from .cade_engine import CadeEngine
        return CadeEngine().analyze(profiles, inputs.get('known_findings'))

    def _run_phs(self, inputs: Dict):
        funcs = inputs.get('function_instructions')
        if not funcs:
            return None
        from .phs_engine import PhsEngine
        return PhsEngine().analyze(funcs, inputs.get('binary_name', ''))

    def _run_cssa(self, inputs: Dict):
        crashes = inputs.get('crash_states')
        if not crashes:
            return None
        from .cssa_dedup_engine import CssaDedupEngine
        return CssaDedupEngine().deduplicate(crashes)

    def _run_byrs(self, inputs: Dict):
        funcs = inputs.get('function_instructions')
        func_bytes = inputs.get('function_bytes')
        if not funcs or not func_bytes:
            _log.info('BYRS跳过: 需要function_instructions和function_bytes')
            return None
        from .byrs_rule_synthesizer import synthesize_yara_from_function
        results = []
        for fname in list(funcs.keys())[:5]:
            fbytes = func_bytes.get(fname)
            if not fbytes:
                continue
            insns = funcs.get(fname, [])
            ruleset = synthesize_yara_from_function(
                fbytes, insns, fname)
            if ruleset and ruleset.strict_rule:
                results.append(ruleset)
        return results if results else None

    def _run_tvp(self, inputs: Dict):
        repo = inputs.get('git_repo_path')
        if not repo:
            return None
        from .tvp_provenance_engine import TemporalProvenanceEngine
        vulns = inputs.get('vulnerabilities', [])
        if not vulns:
            return None
        engine = TemporalProvenanceEngine(repo)
        return engine.batch_trace(vulns[:10])

    def _run_mewf(self, inputs: Dict):
        vulns = inputs.get('vulnerabilities')
        if not vulns:
            return None
        from .mewf_forecaster import WeaponizationForecaster
        fc = WeaponizationForecaster()
        return fc.batch_forecast(vulns[:20])

    def _run_ravo(self, inputs: Dict):
        vulns = inputs.get('vulnerabilities')
        if not vulns:
            return None
        from .ravo_engine import RavoEngine
        return RavoEngine().analyze(vulns)

    def _run_cmvc(self, inputs: Dict):
        findings = inputs.get('findings_by_modality')
        if not findings:
            return None
        from .cmvc_engine import CmvcEngine
        return CmvcEngine().analyze(findings)

    def _run_epass(self, inputs: Dict):
        strategies = inputs.get('exploit_strategies')
        if not strategies:
            return None
        from .epass_engine import EpassEngine
        return EpassEngine().generate(strategies=strategies,
                                       binary_name=inputs.get('binary_name', ''))

    def _run_vdda(self, inputs: Dict):
        baseline = inputs.get('baseline_findings')
        current = inputs.get('findings_by_modality')
        if not baseline:
            return None
        from .vdda_engine import VddaEngine
        # 展平当前finding
        all_current = []
        for mod_findings in (current or {}).values():
            all_current.extend(mod_findings)
        return VddaEngine().run(all_current, baseline)


def run_full_pipeline(binary_name: str = "", **kwargs) -> Dict:
    """集成管线便捷入口——返回JSON序列化的字典"""
    pipeline = IntegrationPipeline()
    report = pipeline.run(binary_name=binary_name, **kwargs)
    return {
        'binary': report.binary_name,
        'generated_at': report.generated_at,
        'stages': [{
            'name': s.stage_name,
            'success': s.success,
            'elapsed_ms': s.elapsed_ms,
            'error': s.error if not s.success else '',
        } for s in report.stages],
        'total_elapsed_ms': report.total_elapsed_ms,
    }


__all__ = [
    "StageResult",
    "UnifiedVulnReport",
    "IntegrationPipeline",
    "run_full_pipeline",
]
