"""补丁报告编排器 —— 跨模块聚合，输出格式化综合报告。

将 patching 各模块分析结果聚合为单一结构化报告。
参考 rubric-guided 评估标准 的思路和
VeriBin 的多层次报告格式。

报告维度：
  1. 补丁安全性 (PatchSafetyVerifier)
  2. 栈完整性 (StackIntegrityChecker)
  3. Gadget 风险 (GadgetChainAnalyzer)
  4. 反编译质量 (DistortionDetector)
  5. bounded check 结果 (BoundedModelChecker)
  6. 补丁可靠性 (ReliabilityPredictor)
  7. 综合评分与建议

所有输入报告均为可选 —— 缺失某维度时标记 "not evaluated"。
"""

import os, json, logging, hashlib
import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from collections import OrderedDict

_log_ = logging.getLogger(__name__)

@dataclass
class DimensionScore:
    # 单个评估维度的评分
    name: str
    score: float = 0.0          # 0..1 归一化
    raw_score: Any = None       # 原始评分值
    status: str = "not_evaluated"  # pass, fail, warning, error, not_evaluated
    source_module: str = ""
    details: Dict = field(default_factory=dict)
    weight: float = 0.0         # 综合评分中的权重

@dataclass
class CompositeReport:
    """多维综合补丁报告。"""
    report_id: str = ""
    binary_path: str = ""
    patched_binary_path: str = ""
    generated_at: str = ""
    dimensions: List[DimensionScore] = field(default_factory=list)
    overall_score: float = 0.0
    overall_grade: str = "N/A"  # A+, A, B, C, D, F
    critical_findings: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict:
        return OrderedDict([
            ('report_id', self.report_id),
            ('binary_path', self.binary_path),
            ('generated_at', self.generated_at),
            ('overall_score', round(self.overall_score, 4)),
            ('overall_grade', self.overall_grade),
            ('dimensions', [
                OrderedDict([
                    ('name', _d.name),
                    ('score', round(_d.score, 4)),
                    ('status', _d.status),
                    ('source', _d.source_module),
                    ('details', _d.details),
                ])
                for _d in self.dimensions
            ]),
            ('critical_findings', self.critical_findings),
            ('warnings', self.warnings),
            ('recommendations', self.recommendations),
            ('summary', self.summary),
        ])

    def to_markdown(self) -> str:
        """Markdown 可读报告。"""
        _lines = [
            "# Binary Patch Composite Assessment Report",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| Report ID | {} |".format(self.report_id),
            "| Binary | {} |".format(self.binary_path),
            "| Generated | {} |".format(self.generated_at),
            "| Overall Score | {:.2%} |".format(self.overall_score),
            "| Grade | **{}** |".format(self.overall_grade),
            "",
            "## Dimension Scores",
            "",
        ]

        for _d in self.dimensions:
            _icon = {'pass': '✅', 'fail': '❌', 'warning': '⚠️',
                     'error': '🚫', 'not_evaluated': '⬜'}.get(_d.status, '⬜')
            _lines.append("- {} **{}**: {:.2%} ({})".format(
                _icon, _d.name, _d.score, _d.status))

        if self.critical_findings:
            _lines.append("")
            _lines.append("## Critical Findings")
            for _f in self.critical_findings:
                _lines.append("- 🔴 " + str(_f)[:200])

        if self.warnings:
            _lines.append("")
            _lines.append("## Warnings")
            for _w in self.warnings:
                _lines.append("- 🟡 " + str(_w)[:200])

        if self.recommendations:
            _lines.append("")
            _lines.append("## Recommendations")
            _idx = 1
            for _r in self.recommendations:
                _lines.append("{}. {}".format(_idx, _r))
                _idx += 1

        return '\n'.join(_lines)

class PatchReportComposer:
    """综合报告编排器 —— 聚合所有子模块分析结果。

    采用 rubric-guided 评估，每个维度预设权重，生成结构化评分报告。
    参考评分标准 []。
    """

    # 维度权重 —— 安全性权重最高
    _DEFAULT_WEIGHTS = OrderedDict([
        ('safety',          0.25),
        ('stack_integrity', 0.15),
        ('gadget_risk',     0.10),
        ('decomp_quality',  0.10),
        ('model_check',     0.15),
        ('reliability',     0.15),
        ('test_coverage',   0.10),
    ])

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self._weights = weights or dict(self._DEFAULT_WEIGHTS)

    # 主编排 —— 接受各模块输出 raw result
    def compose(self, binary_path: str = "",
                patched_binary_path: str = "",
                safety_result: Optional[Dict] = None,
                stack_integrity_result: Optional[Dict] = None,
                gadget_result: Optional[Dict] = None,
                distortion_result: Optional[Dict] = None,
                model_check_result: Optional[Dict] = None,
                reliability_result: Optional[Dict] = None,
                test_coverage_result: Optional[Dict] = None,
                ) -> CompositeReport:
        """聚合并输出综合报告。"""
        _rpt = CompositeReport(
            report_id="cr_" + hashlib.sha256(
                (binary_path + str(_dt.datetime.now().timestamp())).encode()
            ).hexdigest()[:12],
            binary_path=binary_path,
            patched_binary_path=patched_binary_path or binary_path,
            generated_at=_dt.datetime.now().isoformat(),
        )

        # 逐维度评估
        _dims = []

        # Dimension 1: 安全性
        _d_safety = self._eval_safety(safety_result)
        _dims.append(_d_safety)

        # Dimension 2: 栈完整性
        _d_stack = self._eval_stack_integrity(stack_integrity_result)
        _dims.append(_d_stack)

        # Dimension 3: Gadget 风险
        _d_gadget = self._eval_gadget(gadget_result)
        _dims.append(_d_gadget)

        # Dimension 4: 反编译质量
        _d_decomp = self._eval_distortion(distortion_result)
        _dims.append(_d_decomp)

        # Dimension 5: bounded check
        _d_model = self._eval_model_check(model_check_result)
        _dims.append(_d_model)

        # Dimension 6: 可靠性
        _d_reliability = self._eval_reliability(reliability_result)
        _dims.append(_d_reliability)

        # Dimension 7: 测试覆盖
        _d_test = self._eval_test_coverage(test_coverage_result)
        _dims.append(_d_test)

        _rpt.dimensions = _dims

        # 综合评分
        _rpt.overall_score = self._compute_overall_score(_dims)

        # 评级
        _rpt.overall_grade = self._compute_grade(_rpt.overall_score)

        # 收集 critical 与 warning
        _rpt.critical_findings = self._collect_critical(_dims)
        _rpt.warnings = self._collect_warnings(_dims)
        _rpt.recommendations = self._generate_recommendations(_dims, _rpt)

        # 摘要
        _rpt.summary = self._generate_summary(_rpt)

        return _rpt

# 各维度评估

    def _eval_safety(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Patch Safety", source_module="patch_safety_verifier",
                           weight=self._weights.get('safety', 0.25))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _verdict = _res.get('verdict', 'UNCERTAIN')
        _conf = _res.get('confidence', 0.0)

        _d.score = _conf
        _d.details = {
            'verdict': _verdict,
            'regions': _res.get('region_count', 0),
            'safe_patterns': _res.get('safe_patterns', 0),
            'risk_score': _res.get('risk_score', 0),
            'suspicious': len(_res.get('suspicious_instructions', [])),
        }

        if _verdict in ('SAFE_STRONG', 'SAFE_LIKELY'):
            _d.status = 'pass'
        elif _verdict == 'UNCERTAIN':
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

    def _eval_stack_integrity(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Stack Integrity", source_module="stack_integrity_checker",
                           weight=self._weights.get('stack_integrity', 0.15))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _safety = _res.get('safety_score', 0.0)
        _d.score = _safety
        _d.details = {
            'total_functions': _res.get('total_functions', 0),
            'risky_functions': _res.get('risky_functions', 0),
            'canary_coverage': _res.get('canary_coverage', 0.0),
            'overall_risk': _res.get('overall_risk', 'UNKNOWN'),
        }

        _risk = _res.get('overall_risk', '')
        if _risk in ('CLEAN', 'LOW_RISK'):
            _d.status = 'pass'
        elif _risk == 'MEDIUM_RISK':
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

    def _eval_gadget(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Gadget Risk", source_module="gadget_chain_analyzer",
                           weight=self._weights.get('gadget_risk', 0.10))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _defense = _res.get('defense_score', 0.0)
        _d.score = _defense
        _d.details = {
            'total_gadgets': _res.get('total_gadgets', 0),
            'rop_gadgets': _res.get('rop_gadgets', 0),
            'jop_gadgets': _res.get('jop_gadgets', 0),
            'syscall_gadgets': _res.get('syscall_gadgets', 0),
            'longest_chain': _res.get('longest_chain', 0),
        }

        if _defense >= 0.70:
            _d.status = 'pass'
        elif _defense >= 0.40:
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

    def _eval_distortion(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Decomp Quality", source_module="decomp_distortion_detector",
                           weight=self._weights.get('decomp_quality', 0.10))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _quality = _res.get('overall_quality_score', 0.0)
        _d.score = _quality
        _d.details = {
            'total_functions': _res.get('total_functions', 0),
            'distorted_functions': _res.get('distorted_functions', 0),
            'total_instances': _res.get('total_instances', 0),
            'by_kind': _res.get('by_kind', {}),
        }

        if _quality >= 0.80:
            _d.status = 'pass'
        elif _quality >= 0.50:
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

    def _eval_model_check(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Model Checking", source_module="bounded_model_checker",
                           weight=self._weights.get('model_check', 0.15))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _verdict = _res.get('overall_verdict', 'inconclusive')
        _total = _res.get('total_checks', 0)
        _passed = _res.get('passed', 0)
        _d.score = _passed / max(_total, 1)
        _d.details = {
            'verdict': _verdict,
            'passed': _passed,
            'failed': _res.get('failed', 0),
            'total_checks': _total,
            'counterexamples': _res.get('counterexamples', []),
        }

        if _verdict == 'verified':
            _d.status = 'pass'
        elif _verdict == 'falsified':
            _d.status = 'fail'
        else:
            _d.status = 'warning'

        return _d

    def _eval_reliability(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Reliability", source_module="reliability_predictor",
                           weight=self._weights.get('reliability', 0.15))
        if result is None:
            return _d

        # reliability_predictor 返回 PredictionResult / ReliabilityReport
        _survival = 0.0
        if hasattr(result, 'success_rate'):
            _survival = getattr(result, 'success_rate', 0.0)
        elif isinstance(result, dict):
            _survival = result.get('success_rate', result.get('survival_rate', 0.0))

        _d.score = _survival
        _d.details = {
            'survival_rate': _survival,
            'exploitability': getattr(result, 'exploitability_score', 0.0) if hasattr(result, 'exploitability_score') else result.get('exploitability_score', 0.0) if isinstance(result, dict) else 0.0,
            'patch_difficulty': getattr(result, 'patch_difficulty', 'unknown') if hasattr(result, 'patch_difficulty') else result.get('patch_difficulty', 'unknown') if isinstance(result, dict) else 'unknown',
        }

        if _survival >= 0.90:
            _d.status = 'pass'
        elif _survival >= 0.60:
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

    def _eval_test_coverage(self, result: Optional[Dict]) -> DimensionScore:
        _d = DimensionScore(name="Test Coverage", source_module="patch_test_generator",
                           weight=self._weights.get('test_coverage', 0.10))
        if result is None or not result.get('success'):
            return _d

        _res = result.get('result', {})
        _cov = _res.get('coverage_estimate', 0.0)
        _d.score = _cov
        _d.details = {
            'total_count': _res.get('total_count', 0),
            'by_kind': _res.get('by_kind', {}),
            'coverage_estimate': _cov,
        }

        if _cov >= 0.60:
            _d.status = 'pass'
        elif _cov >= 0.30:
            _d.status = 'warning'
        else:
            _d.status = 'fail'

        return _d

# 综合评分

    def _compute_overall_score(self, dimensions: List[DimensionScore]) -> float:
        _total_weight = 0.0
        _weighted_sum = 0.0
        for _d in dimensions:
            if _d.status != 'not_evaluated':
                _w = _d.weight
                _weighted_sum += _d.score * _w
                _total_weight += _w
        if _total_weight == 0.0:
            return 0.0
        return _weighted_sum / _total_weight

    def _compute_grade(self, score: float) -> str:
        if score >= 0.95:
            return "A+"
        elif score >= 0.85:
            return "A"
        elif score >= 0.75:
            return "B"
        elif score >= 0.60:
            return "C"
        elif score >= 0.40:
            return "D"
        else:
            return "F"

    def _collect_critical(self, dims: List[DimensionScore]) -> List[str]:
        _critical = []
        for _d in dims:
            if _d.status == 'fail' and _d.score < 0.30:
                _critical.append("{}: score {:.2%} — CRITICAL FAILURE".format(
                    _d.name, _d.score))
        return _critical

    def _collect_warnings(self, dims: List[DimensionScore]) -> List[str]:
        _warnings = []
        for _d in dims:
            if _d.status in ('warning', 'fail'):
                _warnings.append("{}: score {:.2%} ({})".format(
                    _d.name, _d.score, _d.status))
        return _warnings

    def _generate_recommendations(self, dims: List[DimensionScore],
                                  report: CompositeReport) -> List[str]:
        _recs = []
        for _d in dims:
            if _d.status == 'fail':
                _recs.append("{} requires immediate attention (score: {:.2%})".format(
                    _d.name, _d.score))
            elif _d.status == 'warning':
                _recs.append("{} should be reviewed (score: {:.2%})".format(
                    _d.name, _d.score))
        if report.overall_grade in ('D', 'F'):
            _recs.append("Overall grade {}: NOT recommended for production deployment".format(
                report.overall_grade))
        elif report.overall_grade == 'C':
            _recs.append("Overall grade C: proceed with caution; additional testing recommended")
        else:
            _recs.append("Overall grade {}: patch meets safety thresholds".format(
                report.overall_grade))
        return _recs

    def _generate_summary(self, report: CompositeReport) -> str:
        _dim_count = sum(1 for _d in report.dimensions if _d.status != 'not_evaluated')
        _pass_count = sum(1 for _d in report.dimensions if _d.status == 'pass')
        _fail_count = sum(1 for _d in report.dimensions if _d.status == 'fail')
        return ("{} dimensions evaluated: {} pass, {} fail, {} warnings. "
                "Overall: {:.2%} (Grade {})".format(
                    _dim_count, _pass_count, _fail_count,
                    sum(1 for _d in report.dimensions if _d.status == 'warning'),
                    report.overall_score, report.overall_grade))

# 便捷入口

def compose_patch_report(binary_path: str = "",
                         safety_result: Optional[Dict] = None,
                         stack_integrity_result: Optional[Dict] = None,
                         gadget_result: Optional[Dict] = None,
                         distortion_result: Optional[Dict] = None,
                         model_check_result: Optional[Dict] = None,
                         reliability_result: Optional[Dict] = None,
                         test_coverage_result: Optional[Dict] = None,
                         ) -> CompositeReport:
    _composer = PatchReportComposer()
    return _composer.compose(
        binary_path=binary_path,
        safety_result=safety_result,
        stack_integrity_result=stack_integrity_result,
        gadget_result=gadget_result,
        distortion_result=distortion_result,
        model_check_result=model_check_result,
        reliability_result=reliability_result,
        test_coverage_result=test_coverage_result,
    )
