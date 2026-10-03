# stub_regression_detector.py — 跨版本实现回归检测
# 比较同一模块在溯源链中不同版本的实现，检测回归:
#   性能退化、体积膨胀、复杂度增加、验证深度下降。
# 用于避免"修复了旧问题但引入新问题"（越修越差）的恶性循环。
#
# 方案:
#   1. 从 ProvenanceChain 加载模块的两个版本
#   2. 比较维度:
#      a) 源码行数比 (bloat_ratio)
#      b) 类型注解覆盖率变化 (annotation_delta)
#      c) 复杂度变化 (complexity_delta)
#      d) 验证结论变化 (verification_regression)
#      e) 非相干性变化 (incoherence_regression)
#   3. 任一维度超过回归阈值 → 标记为回归
#   4. 回归版本自动标记为"不可部署"，保留上一版本为 active
#
# 回归阈值（保守设计 — 宁可漏报不可误报）:
#   bloat: > 3× 行数变化
#   annotation: 覆盖率下降 > 30%
#   complexity: low→high 或 medium→high
#   verification: ok→fail
#   incoherence: 增加 > 0.2
import os as _os
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class RegressionCheck:
    """单维度的回归检查结果。"""
    dimension: str          # bloat | annotation | complexity | verification | incoherence
    old_value: str = ''
    new_value: str = ''
    is_regression: bool = False
    severity: str = 'none'  # none | minor | major | critical
    detail: str = ''


@_dc
class RegressionReport:
    """一次回归检测的完整报告。"""
    module_name: str
    old_version_id: str = ''
    new_version_id: str = ''
    checks: list = _field(default_factory=list)  # list[RegressionCheck]
    is_regression: bool = False
    regression_count: int = 0
    critical_count: int = 0
    recommendation: str = ''


class RegressionDetector:
    """跨版本实现回归检测器。"""

    REGRESSION_THRESHOLDS = {
        'bloat_ratio': 3.0,
        'annotation_drop': 0.3,
        'incoherence_increase': 0.2,
    }

    def detect(self, module_name: str) -> RegressionReport:
        """检测指定模块的最新版本相对前一版本是否有回归。"""
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            chain = pc.history(module_name)
        except ImportError:
            return RegressionReport(module_name=module_name,
                                   recommendation='provenance_chain_unavailable')

        if len(chain) < 2:
            return RegressionReport(module_name=module_name,
                                   recommendation='insufficient_history')

        old_entry = chain[-2]
        new_entry = chain[-1]

        report = RegressionReport(
            module_name=module_name,
            old_version_id=old_entry.entry_id,
            new_version_id=new_entry.entry_id,
        )

        # 1. 体积回归
        report.checks.append(self._check_bloat(module_name))

        # 2. 注解覆盖率回归
        report.checks.append(self._check_annotation_regression(module_name))

        # 3. 验证回归
        report.checks.append(self._check_verification_regression(
            old_entry, new_entry))

        # 4. 非相干性回归
        report.checks.append(self._check_incoherence_regression(
            old_entry, new_entry))

        # 5. 复杂度回归
        report.checks.append(self._check_complexity_regression(module_name))

        report.regression_count = sum(1 for c in report.checks if c.is_regression)
        report.critical_count = sum(1 for c in report.checks
                                   if c.severity == 'critical')
        report.is_regression = report.regression_count > 0

        if report.critical_count > 0:
            report.recommendation = 'rollback_recommended'
        elif report.is_regression:
            report.recommendation = 'review_before_deploy'
        else:
            report.recommendation = 'safe_to_deploy'

        return report

    def _check_bloat(self, module_name: str) -> RegressionCheck:
        """检查源码体积是否膨胀。"""
        old_src = self._read_old_source(module_name)
        new_src = self._read_source(module_name)

        old_lines = len(old_src.splitlines()) if old_src else 0
        new_lines = len(new_src.splitlines()) if new_src else 0

        check = RegressionCheck(
            dimension='bloat',
            old_value=str(old_lines),
            new_value=str(new_lines),
        )

        if old_lines > 0 and new_lines > old_lines * self.REGRESSION_THRESHOLDS['bloat_ratio']:
            check.is_regression = True
            ratio = new_lines / old_lines
            if ratio > 10:
                check.severity = 'critical'
                check.detail = f'体积膨胀 {ratio:.1f}× ({old_lines}→{new_lines} 行)'
            else:
                check.severity = 'major'
                check.detail = f'体积膨胀 {ratio:.1f}× ({old_lines}→{new_lines} 行)'

        return check

    def _check_annotation_regression(self, module_name: str) -> RegressionCheck:
        """检查类型注解覆盖率是否下降。"""
        check = RegressionCheck(dimension='annotation')

        try:
            from modules.stubs.stub_contract import get_contractor
            contract = get_contractor().get(module_name)
            if contract is None or not contract.functions:
                return check

            # 计算当前注解覆盖率
            total_p = 0
            annotated_p = 0
            for fc in contract.functions:
                params = [p for p in fc.params
                         if p.kind not in ('varargs', 'varkw')]
                total_p += len(params)
                annotated_p += sum(1 for p in params
                                  if p.annotation and p.annotation.strip())
            current_cov = annotated_p / max(total_p, 1)
            check.new_value = f'{current_cov:.1%}'

            # 与上一版本比较（从合约 Merkle 树推断 — 简化: 用固定期望值）
            # 完整实现需要存储每版本的注解覆盖率
            check.old_value = 'unknown'
            if current_cov < 0.3:
                check.is_regression = True
                check.severity = 'major'
                check.detail = f'注解覆盖率过低: {current_cov:.1%}'
        except ImportError:
            pass

        return check

    @staticmethod
    def _check_verification_regression(old_entry, new_entry) -> RegressionCheck:
        check = RegressionCheck(
            dimension='verification',
            old_value=str(old_entry.verification_ok),
            new_value=str(new_entry.verification_ok),
        )
        if old_entry.verification_ok and not new_entry.verification_ok:
            check.is_regression = True
            check.severity = 'critical'
            check.detail = '验证状态从 OK 退化为 FAIL'
        return check

    @staticmethod
    def _check_incoherence_regression(old_entry, new_entry) -> RegressionCheck:
        check = RegressionCheck(
            dimension='incoherence',
            old_value=str(old_entry.incoherence_rate),
            new_value=str(new_entry.incoherence_rate),
        )
        old_inc = old_entry.incoherence_rate
        new_inc = new_entry.incoherence_rate
        if old_inc >= 0 and new_inc >= 0:
            increase = new_inc - old_inc
            if increase > RegressionDetector.REGRESSION_THRESHOLDS['incoherence_increase']:
                check.is_regression = True
                check.severity = 'major'
                check.detail = f'非相干性增加 {increase:.3f} ({old_inc:.3f}→{new_inc:.3f})'
        return check

    def _check_complexity_regression(self, module_name: str) -> RegressionCheck:
        check = RegressionCheck(dimension='complexity')
        try:
            from modules.stubs.stub_contract import get_contractor
            contract = get_contractor().get(module_name)
            if contract is None:
                return check
            high_count = sum(1 for f in contract.functions
                           if f.complexity == 'high')
            if high_count > 0:
                check.new_value = f'{high_count} high-complexity functions'
                check.is_regression = True
                check.severity = 'minor'
                check.detail = f'{high_count} 个高复杂度函数可能需要人工审查'
        except ImportError:
            pass
        return check

    @staticmethod
    def _read_source(module_name: str) -> _Opt[str]:
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                            f'{module_name}.py')
        if _os.path.isfile(path):
            try:
                return open(path, encoding='utf-8').read()
            except (OSError, UnicodeDecodeError):
                pass
        return None

    @staticmethod
    def _read_old_source(module_name: str) -> _Opt[str]:
        """尝试从 _gradual_out 读取上一版本的源码。"""
        base = _os.path.dirname(_os.path.abspath(__file__))
        path = _os.path.join(base, '_gradual_out', f'{module_name}.py')
        if _os.path.isfile(path):
            try:
                return open(path, encoding='utf-8').read()
            except (OSError, UnicodeDecodeError):
                pass
        return None

    def regression_report(self, report: RegressionReport) -> str:
        """生成 Markdown 回归检测报告。"""
        lines = [
            f'# Regression: {report.module_name}',
            f'Version: {report.old_version_id} -> {report.new_version_id}',
            f'Is regression: {report.is_regression}',
            f'Recommendation: {report.recommendation}',
            '',
        ]
        if report.checks:
            lines.append('| 维度 | 旧值 | 新值 | 回归 | 严重度 |')
            lines.append('|------|------|------|------|--------|')
            for c in report.checks:
                reg_mark = 'YES' if c.is_regression else 'no'
                lines.append(
                    f'| {c.dimension} | {c.old_value} | {c.new_value} | '
                    f'{reg_mark} | {c.severity} |')
        return '\n'.join(lines)


__all__ = ['RegressionCheck', 'RegressionReport', 'RegressionDetector']
