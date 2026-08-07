# coding: utf-8
# 创建: 2026-06-01  |  补丁完备性引擎
# 修改: 2026-06-01  |  审计后补充文件头与错误处理
#
"""
语义补丁完备性验证引擎——编排契约推断与抽象解释的完整验证管线。

管线流程: 契约推断→代码提取→抽象解释→语义比较→完备性分级。

与patch_quality_evaluator互补: 后者检查代码模式，本引擎检查语义完备。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .spcv_contract_inferrer import (
    FunctionContract,
    ContractViolation,
    ContractInferrer,
    infer_param_bounds,
)
from .spcv_abstract_checker import (
    AbstractInterpreter,
    SemanticDiffResult,
    check_patch_completeness,
)

_log = logging.getLogger(__name__)


# 完备性报告


class CompletenessGrade(str):
    COMPLETE = "COMPLETE"         # 语义完备——补丁满足所有推断契约
    PARTIAL = "PARTIAL"           # 部分完备——核心约束满足，边缘条件存疑
    INCOMPLETE = "INCOMPLETE"     # 不完备——存在可确认的契约违反
    REGRESSION = "REGRESSION"     # 回归——补丁引入了新的安全问题
    UNVERIFIABLE = "UNVERIFIABLE"  # 不可验证——源码信息不足


@dataclass
class CompletenessReport:
    """补丁完备性验证报告"""
    patch_id: str
    function_name: str
    cve_id: str
    grade: str                      # CompletenessGrade值
    # 契约信息
    contract: Optional[FunctionContract] = None
    contract_confidence: str = ""   # strong | moderate | weak
    # 语义差异
    semantic_diff: Optional[SemanticDiffResult] = None
    # 违反详情
    violations: List[ContractViolation] = field(default_factory=list)
    violation_count: int = 0
    # 推荐措施
    recommendations: List[str] = field(default_factory=list)
    # 管线元数据
    source_lines_analyzed: int = 0
    patch_lines_analyzed: int = 0


# 补丁diff解析


def _parse_unified_diff(diff_text: str) -> Tuple[List[str], List[str]]:
    """解析unified diff——提取原代码（删除行）与补丁代码（新增行）。

    返回(original_lines, patched_lines)——仅含代码内容，不含diff标记。
    """
    original: List[str] = []
    patched: List[str] = []

    for line in diff_text.split('\n'):
        if line.startswith('---') or line.startswith('+++'):
            continue
        if line.startswith('@@'):
            continue
        if line.startswith('-') and not line.startswith('---'):
            original.append(line[1:])
        elif line.startswith('+') and not line.startswith('+++'):
            patched.append(line[1:])
        else:
            # 上下文行——两版共用
            content = line[1:] if line.startswith(' ') else line
            original.append(content)
            patched.append(content)

    return original, patched


def _extract_function_body(lines: List[str],
                            func_name: str) -> List[str]:
    """从源码行中提取函数体——大括号范围内的行"""
    in_func = False
    brace_depth = 0
    body = []
    for line in lines:
        stripped = line.strip()
        if not in_func:
            if func_name in stripped and '(' in stripped and '{' in stripped:
                in_func = True
                brace_depth += stripped.count('{') - stripped.count('}')
                continue
        else:
            body.append(line)
            brace_depth += stripped.count('{') - stripped.count('}')
            if brace_depth <= 0:
                break
    return body


# 完备性引擎


class CompletenessEngine:
    """语义补丁完备性验证引擎——契约推断 + 抽象解释 + 语义比较。

    verify() → CompletenessReport 含COMPLETE/PARTIAL/INCOMPLETE/REGRESSION分级。
    与patch_quality_evaluator互补: 后者检查代码模式，本引擎检查语义完备。
    """

    def __init__(self):
        self._contract_inferrer = ContractInferrer()

    def verify(self, source_lines: List[str],
               patch_diff: str = "",
               patched_lines: List[str] = None,
               function_name: str = "",
               cve_id: str = "",
               param_names: List[str] = None
               ) -> CompletenessReport:
        """执行补丁完备性验证——完整管线。

        source_lines/patched_lines二选一，function_name/cve_id为必填。
        """
        report = CompletenessReport(
            patch_id=f"VERIFY_{function_name}_{cve_id}",
            function_name=function_name, cve_id=cve_id,
            grade=CompletenessGrade.UNVERIFIABLE)

        # 提取代码
        if patch_diff:
            orig_body, patch_body = _parse_unified_diff(patch_diff)
        elif patched_lines:
            orig_body = _extract_function_body(source_lines, function_name)
            patch_body = (_extract_function_body(patched_lines, function_name)
                          if patched_lines else [])
        else:
            report.recommendations.append("需要补丁diff或补丁后源码")
            return report

        if not orig_body:
            report.recommendations.append("无法提取原始函数体")
            return report

        report.source_lines_analyzed = len(orig_body)
        report.patch_lines_analyzed = len(patch_body) if patch_body else 0

        # 契约推断
        contract = self._contract_inferrer.infer_from_source(
            source_lines, function_name)

        if param_names:
            bounds = infer_param_bounds(source_lines, function_name, param_names)
            contract.param_bounds = bounds

        report.contract = contract
        if contract.call_site_count >= 3:
            report.contract_confidence = "strong"
        elif contract.call_site_count >= 2:
            report.contract_confidence = "moderate"
        else:
            report.contract_confidence = "weak"

        # 抽象解释 + 语义比较
        if not patch_body:
            report.recommendations.append("补丁体为空——函数被移除？")
            return report

        diff_result = check_patch_completeness(orig_body, patch_body, contract)
        report.semantic_diff = diff_result
        report.violations = diff_result.violations
        report.violation_count = len(diff_result.violations)

        # 完备性分级
        report.grade = self._assign_grade(diff_result, contract, report.contract_confidence)

        # 生成建议
        report.recommendations = self._generate_recommendations(
            report.grade, diff_result, contract)

        return report

    def _assign_grade(self, diff: SemanticDiffResult,
                       contract: FunctionContract,
                       confidence: str) -> str:
        """根据语义差异与契约置信度分配完备性等级。

        分级矩阵:
                       无违反  轻微违反  严重违反  新增风险
          strong契约   COMPLETE  PARTIAL  INCOMPLETE REGRESSION
          moderate     COMPLETE  PARTIAL  INCOMPLETE INCOMPLETE
          weak         COMPLETE  PARTIAL  PARTIAL    INCOMPLETE
        """
        has_critical = any(v.severity == "CRITICAL" for v in diff.violations)
        has_high = any(v.severity == "HIGH" for v in diff.violations)
        has_regression = diff.abstract_paths_diverged and not diff.buffer_bounds_tightened

        if diff.violations:
            if has_regression:
                return CompletenessGrade.REGRESSION
            if has_critical:
                return CompletenessGrade.INCOMPLETE
            if has_high:
                if confidence == "weak":
                    return CompletenessGrade.PARTIAL
                return CompletenessGrade.INCOMPLETE
            return CompletenessGrade.PARTIAL

        if confidence == "weak":
            return CompletenessGrade.PARTIAL  # 无法确认完备
        return CompletenessGrade.COMPLETE

    def _generate_recommendations(self, grade: str,
                                    diff: SemanticDiffResult,
                                    contract: FunctionContract
                                    ) -> List[str]:
        """基于完备性分级生成可操作的修复建议"""
        recs = []
        if grade == CompletenessGrade.COMPLETE:
            recs.append("补丁在语义层面通过完备性验证。建议追加运行时验证以确认。")
        elif grade == CompletenessGrade.PARTIAL:
            recs.append("补丁修复了主要路径，但存在边缘条件未覆盖。")
            for v in diff.violations:
                recs.append(f"  - {v.contract_entry}: {v.patched_behavior}")
        elif grade == CompletenessGrade.INCOMPLETE:
            recs.append("补丁不完整——存在可确认的契约违反。")
            recs.append("建议在修复中逐项处理以下违反:")
            for v in diff.violations:
                recs.append(f"  - [{v.severity}] {v.contract_entry} @ {v.fix_location}")
        elif grade == CompletenessGrade.REGRESSION:
            recs.append("补丁引入了新的安全问题——不建议合并。")
            recs.append(f"缓冲区边界未收紧——抽象路径分歧: {diff.abstract_paths_diverged}")

        if contract.return_check_pattern == "always_checked":
            recs.append("注意: 调用方始终检查返回值——补丁应保持此约定。")
        return recs

    def batch_verify(self, patches: List[Dict]) -> List[CompletenessReport]:
        """批量验证——对多个补丁依次执行管线。

        patches格式: [{"source_lines": [...], "diff": "...",
                        "function": str, "cve": str}, ...]
        """
        reports = []
        for p in patches:
            try:
                r = self.verify(
                    source_lines=p['source_lines'],
                    patch_diff=p.get('diff', ''),
                    function_name=p['function'],
                    cve_id=p.get('cve', ''),
                    param_names=p.get('params'))
                reports.append(r)
            except Exception as e:
                _log.error("批量验证失败 [%s]: %s", p.get('function', '?'), e)
        return reports


# 便捷入口


def verify_patch_completeness(source_lines: List[str],
                               patch_diff: str,
                               function_name: str,
                               cve_id: str = "",
                               param_names: List[str] = None
                               ) -> CompletenessReport:
    """补丁完备性验证便捷入口——单行调用"""
    engine = CompletenessEngine()
    return engine.verify(
        source_lines=source_lines, patch_diff=patch_diff,
        function_name=function_name, cve_id=cve_id,
        param_names=param_names)


__all__ = [
    "CompletenessGrade",
    "CompletenessReport",
    "CompletenessEngine",
    "verify_patch_completeness",
]
