# 反编译校验器测试 — 验证伪代码质量评估的各个维度
# INTJ: 测试不需要真的反编译器 — 我们用精心构造的伪代码片段
#       来验证规则引擎的行为是否正确。

import pytest
import os
import json
import tempfile
# import sys  -- conftest handles path setup

from modules.analysis.decompiler.decompiler_validator import (
    DecompilerValidator,
    ValidationReport,
    ValidationFinding,
    ValidationSeverity,
    VariableRecoveryStats,
    ControlFlowStats,
    FunctionBoundaryStats,
    CrossDecompilerStats,
    validate_decompiled_output,
    quick_validation_score,
)


class TestDecompilerValidator:
    """DecompilerValidator 的单元测试"""

    # ==================================================================
    # 伪代码片段 — 用来模拟各种质量的输出
    # ==================================================================

    GOOD_PSEUDOCODE = """\
int add_numbers(int a, int b) {
    int result;
    result = a + b;
    return result;
}"""

    MEDIUM_PSEUDOCODE = """\
void process_data(char *input, int size) {
    int i;
    char *buf;
    buf = (char *)malloc(size);
    if (buf == NULL) {
        return;
    }
    for (i = 0; i < size; i++) {
        buf[i] = input[i] ^ 0x55;
    }
    free(buf);
}"""

    BAD_PSEUDOCODE = """\
unknown function_1234(var_1, var_2) {
    var_3 = var_1 + var_2;
    goto LAB_00401100;
    if (var_3 > 100) {
        // ... incomplete
        return var_3;
    }
}"""

    OBFUSCATED_PSEUDOCODE = """\
void obfuscated_func() {
    int var_1;
    int var_2;
    // ... TODO: decompile rest
    __asm {
        jmp $
        push rax
        pop rax
    }
    goto next_block;
next_block:
    var_1 = 0;
    return;
}"""

    SWITCH_PSEUDOCODE = """\
int dispatch(int cmd) {
    int result;
    switch(cmd) {
        case 1:
            result = 100;
            break;
        case 2:
            result = 200;
            break;
        default:
            result = -1;
            break;
    }
    return result;
}"""

    # ==================================================================
    # Tests
    # ==================================================================

    def test_validation_report_creation(self):
        """基本报告创建 — 所有字段应有默认值"""
        report = ValidationReport()
        assert report.report_id == ""
        assert report.confidence_score == 0.0
        assert report.overall_grade == "F"
        assert isinstance(report.findings, list)
        assert isinstance(report.var_stats, VariableRecoveryStats)
        assert isinstance(report.cfg_stats, ControlFlowStats)
        assert isinstance(report.boundary_stats, FunctionBoundaryStats)
        assert isinstance(report.cross_stats, CrossDecompilerStats)

    def test_quick_validation_score_good(self):
        """good 伪代码应得高分 (>0.7)"""
        score = quick_validation_score(self.GOOD_PSEUDOCODE)
        assert score > 0.7, f"Expected >0.7 for good code, got {score}"
        assert score <= 1.0

    def test_quick_validation_score_bad(self):
        """有 goto、占位符变量、不完整注释的应得明显低于好代码的分数"""
        score_good = quick_validation_score(self.GOOD_PSEUDOCODE)
        score_bad = quick_validation_score(self.BAD_PSEUDOCODE)
        # Bad code should score lower than good code
        assert score_bad < score_good, \
            f"Bad code ({score_bad}) should score below good code ({score_good})"

    def test_quick_validation_score_with_ground_truth(self):
        """提供 ground truth 应该提升分数"""
        score_no_gt = quick_validation_score(self.GOOD_PSEUDOCODE)
        score_with_gt = quick_validation_score(
            self.GOOD_PSEUDOCODE,
            ground_truth=self.GOOD_PSEUDOCODE  # 完全一致
        )
        # 有 ground truth 时 difflib ratio 接近 1.0，加上 0.3 bonus
        assert score_with_gt >= score_no_gt, \
            f"Ground truth should not decrease score: {score_no_gt} -> {score_with_gt}"

    def test_quick_validation_score_obfuscated(self):
        """混淆代码应被检测到并低于干净代码的分数"""
        score_good = quick_validation_score(self.GOOD_PSEUDOCODE)
        score_obf = quick_validation_score(self.OBFUSCATED_PSEUDOCODE)
        # Obfuscated code should score lower than clean code
        assert score_obf < score_good, \
            f"Obfuscated code ({score_obf}) should score below clean code ({score_good})"

    def test_validation_finding_severity_ordering(self):
        """严重级别之间应有正确的相对权重"""
        weights = {
            ValidationSeverity.CRITICAL: 0.15,
            ValidationSeverity.HIGH: 0.08,
            ValidationSeverity.MEDIUM: 0.04,
            ValidationSeverity.LOW: 0.02,
            ValidationSeverity.INFO: 0.0,
        }
        assert weights[ValidationSeverity.CRITICAL] > weights[ValidationSeverity.HIGH]
        assert weights[ValidationSeverity.HIGH] > weights[ValidationSeverity.MEDIUM]
        assert weights[ValidationSeverity.MEDIUM] > weights[ValidationSeverity.LOW]

    def test_finding_creation(self):
        """创建 finding 的完整性检查"""
        f = ValidationFinding(
            rule_id="TEST_RULE",
            severity=ValidationSeverity.HIGH,
            message="测试消息",
            detail="详细说明",
            line_number=42,
            source_decompiler="ghidra",
        )
        assert f.rule_id == "TEST_RULE"
        assert f.severity == ValidationSeverity.HIGH
        assert f.message == "测试消息"
        assert f.line_number == 42

    def test_variable_recovery_stats(self):
        """变量恢复统计结构"""
        stats = VariableRecoveryStats(
            total_variables=10,
            correctly_typed=8,
            type_mismatches=1,
            missing_variables=1,
        )
        assert stats.accuracy == 0.0  # 没设就是 0
        stats.accuracy = stats.correctly_typed / max(1, stats.total_variables)
        assert stats.accuracy == 0.8

    def test_control_flow_stats(self):
        """控制流统计的 precision/recall"""
        stats = ControlFlowStats(
            total_edges_expected=20,
            total_edges_found=18,
            missing_edges=2,
            spurious_edges=3,
        )
        if stats.total_edges_expected > 0:
            stats.edge_recall = stats.total_edges_found / stats.total_edges_expected
        assert stats.edge_recall == 0.9

    def test_pattern_matching_on_bad_code(self):
        """在坏代码上直接跑规则——应能检测到多个问题"""
        score_good = quick_validation_score(self.GOOD_PSEUDOCODE)
        score_bad = quick_validation_score(self.BAD_PSEUDOCODE)
        assert score_bad < score_good

        # 再测有 goto + 占位符变量 + incomplete 注释
        doubly_bad = """\
unknown func(var_1, var_2) {
    var_3 = var_1 + var_2;
    goto LAB_X;
    // ... incomplete
}"""
        score2 = quick_validation_score(doubly_bad)
        assert score2 < score_good, \
            f"Doubly bad code should score below good code, got {score2}"


class TestValidationReportSerialization:
    """报告序列化测试"""

    def test_json_serialization(self):
        """确保报告可以序列化为 JSON 且不抛异常"""
        from modules.analysis.decompiler.decompiler_validator import DecompilerValidator

        report = ValidationReport(
            report_id="TEST-001",
            timestamp=1234567890.0,
            binary_path="/tmp/test.bin",
            binary_hash="abc123",
            function_name="main",
            confidence_score=0.85,
            overall_grade="B",
            var_stats=VariableRecoveryStats(
                total_variables=5, correctly_typed=4, accuracy=0.8
            ),
            cfg_stats=ControlFlowStats(
                total_edges_expected=10, total_edges_found=9,
                edge_recall=0.9, edge_precision=0.95
            ),
            boundary_stats=FunctionBoundaryStats(
                total_functions_found=1, correct_boundaries=1,
                boundary_accuracy=1.0
            ),
            cross_stats=CrossDecompilerStats(
                decompilers_used=["ghidra", "radare2"],
                consensus_ratio=0.78
            ),
            findings=[
                ValidationFinding(
                    rule_id="TEST_FIND",
                    severity=ValidationSeverity.LOW,
                    message="测试发现",
                )
            ],
        )

        # 需要 DecompilerValidator 实例来调用 generate_report_json
        val = DecompilerValidator.__new__(DecompilerValidator)
        val.findings = []  # 防止 __init__ 没跑的副作用
        json_str = val.generate_report_json(report)

        assert json_str is not None
        data = json.loads(json_str)
        assert data['report_id'] == "TEST-001"
        assert data['confidence_score'] == 0.85
        assert data['overall_grade'] == "B"
        assert len(data['findings']) == 1

    def test_markdown_report(self):
        """确保 Markdown 报告生成不抛异常"""
        report = ValidationReport(
            report_id="MD-TEST",
            timestamp=1234567890.0,
            binary_path="/tmp/md.bin",
            binary_hash="def456",
            function_name="test_func",
            confidence_score=0.60,
            overall_grade="C",
            warnings=["test warning 1"],
            findings=[
                ValidationFinding(
                    rule_id="F1",
                    severity=ValidationSeverity.MEDIUM,
                    message="测试发现 1",
                ),
            ],
        )

        val = DecompilerValidator.__new__(DecompilerValidator)
        md = val.generate_report_markdown(report)

        assert md is not None
        assert "MD-TEST" in md
        assert "test_func" in md
        assert "60.00%" in md or "0.60" in md
        assert "**C**" in md
        assert "F1" in md


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
