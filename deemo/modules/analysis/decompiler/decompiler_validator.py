# 反编译引擎_validator.py：校验 反编译引擎 输出 correctness
#
# Cross-检查 反编译伪代码 against ground-truth patterns
# 度量 variable recovery accuracy, control-flow fidelity
# function-boundary precision. cross-校验 across multiple
# 反编译引擎 backends one available
#
# INTJ: core insight single metric captures "correctness."
# need a multi-axis 报告 — precision vars, recall edges
# a composite 置信度 a human actually trust

import logging
import re
import json
import os
import hashlib
import time
import uuid
import math
import difflib
import itertools       # unused — kept because 's conceptually 关闭
from pathlib import Path  # 保留 for future path handling
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# 核心依赖 — 从现有的 decomp_ai 导入需要的组件
from modules.analysis.decompiler.decomp_ai import (
    DecompilerAI,
    strip_ansi_escape,
    compute_binary_hash,
    DECOMPILER_RADARE2,
    DECOMPILER_GHIDRA,
    DECOMPILER_IDA,
    DECOMPILER_BINARYNINJA,
    DECOMPILER_AUTO,
)

logger = logging.getLogger(__name__)

_LEGACY_MODE = False  # 保留


# ---------------------------------------------------------------------------
# 反痕迹 — 留着没事干的helper
# ---------------------------------------------------------------------------

def _debug_print(msg: str, level: int = 0) -> None:
	"""Leftover debug helper. 不删，说不定哪天又用上了"""
	indent = "  " * level
	if os.environ.get("DECOMP_DEBUG", "") == "1":
		print(f"{indent}[DEBUG] {msg}")



# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

class ValidationSeverity(str, Enum):
	"""严重级别 — 直接影响 confidence score 的扣分权重"""
	CRITICAL = "critical"         # 函数边界整个错的
	HIGH = "high"                 # 控制流缺失明显
	MEDIUM = "medium"             # 变量类型推断不准
	LOW = "low"                   # 细微偏差
	INFO = "info"                 # 仅供参考


@dataclass
class ValidationFinding:
	"""单条校验发现"""
	rule_id: str
	severity: ValidationSeverity
	message: str
	detail: str = ""
	line_number: int = -1
	source_decompiler: str = ""
	expected: str = ""
	actual: str = ""


@dataclass
class VariableRecoveryStats:
	"""变量恢复精度统计"""
	total_variables: int = 0
	correctly_typed: int = 0
	type_mismatches: int = 0
	missing_variables: int = 0
	spurious_variables: int = 0
	accuracy: float = 0.0


@dataclass
class ControlFlowStats:
	"""控制流重建精度统计"""
	total_edges_expected: int = 0
	total_edges_found: int = 0
	missing_edges: int = 0
	spurious_edges: int = 0
	edge_recall: float = 0.0
	edge_precision: float = 0.0


@dataclass
class FunctionBoundaryStats:
	"""函数边界精度统计"""
	total_functions_expected: int = 0
	total_functions_found: int = 0
	correct_boundaries: int = 0
	missing_functions: int = 0
	spurious_functions: int = 0
	boundary_accuracy: float = 0.0


@dataclass
class CrossDecompilerStats:
	"""跨反编译器一致性统计"""
	decompilers_used: List[str] = field(default_factory=list)
	pairwise_jaccard: Dict[str, float] = field(default_factory=dict)
	agreeing_lines: int = 0
	disagreeing_lines: int = 0
	consensus_ratio: float = 0.0


@dataclass
class ValidationReport:
	"""完整的校验报告"""
	report_id: str = ""
	timestamp: float = 0.0
	binary_path: str = ""
	binary_hash: str = ""
	function_name: str = ""

	# 各维度统计
	var_stats: VariableRecoveryStats = field(default_factory=VariableRecoveryStats)
	cfg_stats: ControlFlowStats = field(default_factory=ControlFlowStats)
	boundary_stats: FunctionBoundaryStats = field(default_factory=FunctionBoundaryStats)
	cross_stats: CrossDecompilerStats = field(default_factory=CrossDecompilerStats)

	# 发现列表
	findings: List[ValidationFinding] = field(default_factory=list)

	# 综合评分
	confidence_score: float = 0.0
	overall_grade: str = "F"

	# 元数据
	elapsed_seconds: float = 0.0
	ground_truth_available: bool = False
	warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 规则引擎 — 内置的校验规则
# ---------------------------------------------------------------------------

# 遗留 pre-v1 pattern matcher (kept for 引用)
# def _legacy_match_patterns(pseudocode):
#     results = []
#     for pattern in LEGACY_PATTERNS:
#         m = re.search(pattern, pseudocode)
#         if m:
#             results.append((pattern, m.group(0)))
#     return results

# 这些模式用来匹配置信度低的伪代码特征
_LOW_CONFIDENCE_PATTERNS: List[Tuple[str, re.Pattern, ValidationSeverity, str]] = [
    ("UNKNOWN_VAR", re.compile(r'\bunknown\d*\b', re.IGNORECASE), ValidationSeverity.MEDIUM,
     "存在未解析的变量名 (unknown)"),
    ("INCOMPLETE_BLOCK", re.compile(r'(?://\s*\.\.\.|/\*\s*incomplete|/\*\s*TODO)', re.IGNORECASE), ValidationSeverity.HIGH,
     "代码块不完整或包含占位注释"),
    ("FAILED_DECOMP", re.compile(r'(decompil\w*\s*(fail|error)|could\s*not\s*decompil)', re.IGNORECASE), ValidationSeverity.CRITICAL,
     "反编译失败标记"),
    ("MISSING_RETURN", re.compile(r'^\s*\}\s*$', re.MULTILINE), ValidationSeverity.LOW,
     "函数结尾缺少 return 语句的模式"),
    ("GOTO_HEAVY", re.compile(r'\bgoto\b', re.IGNORECASE), ValidationSeverity.MEDIUM,
     "包含 goto 语句 — 控制流可能未完全还原"),
    ("INLINE_ASM", re.compile(r'\b(__asm__?|_asm|asm\s*\{|asm\s*\()', re.IGNORECASE), ValidationSeverity.LOW,
     "包含内联汇编 — 部分逻辑未反编译"),
    ("CAST_CASCADE", re.compile(r'(\(\s*\w+\s*\*?\s*\)\s*){4,}'), ValidationSeverity.LOW,
     "连续多次强制类型转换 — 类型推断可能有误"),
    ("EMPTY_FUNC_BODY", re.compile(r'\{\s*\}'), ValidationSeverity.HIGH,
     "空函数体 — 可能丢失了全部逻辑"),
]

# 常见于恶意样本或加壳后的残留模式
_OBFUSCATION_INDICATORS: List[Tuple[str, re.Pattern, str]] = [
    ("JUNK_CODE", re.compile(r'(?:jmp\s+\$|jmp\s+next|__debugbreak|int\s+3|ud2)', re.IGNORECASE),
     "检测到混淆/反调试指令残余"),
    ("STACK_STRING", re.compile(r'(?:mov\s+(?:byte|word|dword|qword)\s+ptr\s+\[)', re.IGNORECASE),
     "栈上字符串构造 — 常见于混淆代码"),
    ("OPAQUE_PREDICATE", re.compile(r'(?:xor\s+e\w+,\s*e\w+\s*\n\s*j\w+)', re.IGNORECASE),
     "可能的不透明谓词"),
]


# ---------------------------------------------------------------------------
# 主校验器
# ---------------------------------------------------------------------------

class DecompilerValidator:
    """
    反编译输出校验器 —— 多维度评估伪代码质量
    INTJ: 这个类的设计哲学是用多轴评分代替单一的"好/坏"二分类
    没有人能说一句伪代码"完全正确"，但我们可以告诉用户
    在哪些维度上可信，哪些维度上需要人工复查
    """

    def __init__(self, binary_path: str, ground_truth_path: Optional[str] = None):
        """
        Args:
            binary_path: 目标二进制路径
            ground_truth_path: 可选的 ground-truth 伪代码/源码路径
        """
        self.binary_path = binary_path
        self.ground_truth_path = ground_truth_path
        self.ground_truth_lines: List[str] = []
        self._load_ground_truth()

        self.decompiler_ai = DecompilerAI(binary_path, decompiler=DECOMPILER_AUTO)
        self.available_decompilers = self.decompiler_ai.get_available_decompilers()

        self.findings: List[ValidationFinding] = []
        self._start_time: float = 0.0

        logger.info(f"DecompilerValidator initialized for {binary_path}")
        logger.info(f"Available decompilers: {list(self.available_decompilers.keys())}")
        if ground_truth_path:
            logger.info(f"Ground truth loaded: {len(self.ground_truth_lines)} lines")

    def _load_ground_truth(self) -> None:
        # 加载 ground truth source file, provided
        if not self.ground_truth_path or not os.path.exists(self.ground_truth_path):
            self.ground_truth_lines = []
            return

        try:
            with open(self.ground_truth_path, 'r', encoding='utf-8', errors='replace') as f:
                self.ground_truth_lines = [
                    line.rstrip() for line in f.readlines()
                ]
        except Exception as e:
            logger.warning(f"无法加载 ground truth: {e}")
            self.ground_truth_lines = []

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def validate(self, function_name: str = "main") -> ValidationReport:
        """
        对指定函数执行全面校验
        
        Args:
        function_name: 目标函数名
        
        返回:
        完整的 校验Report
        """
        self._start_time = time.time()
        self.findings = []

        report = ValidationReport(
            report_id=self._generate_report_id(function_name),
            timestamp=self._start_time,
            binary_path=self.binary_path,
            binary_hash=compute_binary_hash(self.binary_path) or "unknown",
            function_name=function_name,
            ground_truth_available=bool(self.ground_truth_lines),
        )

        logger.info(f"Starting validation of '{function_name}'")

        # Step 1 — 反编译
        pseudocode = self.decompiler_ai.decompile(function_name)
        if not pseudocode:
            report.warnings.append(f"无法反编译函数 {function_name}")
            report.overall_grade = "F"
            report.elapsed_seconds = time.time() - self._start_time
            return report

        pseudocode_lines = pseudocode.split('\n')

        # Step 2 — 各维度分析
        report.var_stats = self._validate_variable_recovery(pseudocode, pseudocode_lines)
        report.cfg_stats = self._validate_control_flow(pseudocode, pseudocode_lines)
        report.boundary_stats = self._validate_function_boundaries(pseudocode, pseudocode_lines)

        # Step 3 — 跨反编译器交叉校验（如果有多个可用）
        if sum(1 for v in self.available_decompilers.values() if v) >= 2:
            report.cross_stats = self._cross_validate(function_name)

        # Step 4 — 模式匹配规则
        self._run_pattern_rules(pseudocode, pseudocode_lines)

        # Step 5 — 与 ground truth 对比
        if self.ground_truth_lines:
            self._compare_with_ground_truth(pseudocode_lines)

        # 汇总
        report.findings = self.findings
        report.confidence_score = self._compute_confidence(report)
        report.overall_grade = self._compute_grade(report.confidence_score)
        report.elapsed_seconds = time.time() - self._start_time

        logger.info(
            f"Validation complete: score={report.confidence_score:.2f}, "
            f"grade={report.overall_grade}, findings={len(report.findings)}"
        )
        return report

    def validate_batch(self,
                       function_names: List[str]) -> List[ValidationReport]:
        """批量校验多个函数"""
        reports = []
        for fname in function_names:
            try:
                report = self.validate(fname)
                reports.append(report)
            except Exception as e:
                logger.error(f"校验函数 {fname} 时出错: {e}")
                error_report = ValidationReport(
                    report_id=f"ERROR-{fname}",
                    timestamp=time.time(),
                    binary_path=self.binary_path,
                    function_name=fname,
                    overall_grade="F",
                    warnings=[str(e)],
                )
                reports.append(error_report)
        return reports

    # ------------------------------------------------------------------
    # 变量恢复校验
    # ------------------------------------------------------------------

    def _validate_variable_recovery(
        self, pseudocode: str, lines: List[str]
    ) -> VariableRecoveryStats:
        # 评估变量恢复质量：检测占位符变量名/类型一致性/声明-使用比例
        stats = VariableRecoveryStats()

        # 找所有疑似变量名的 token
        var_pattern = re.compile(
            r'\b(var_\d+|uVar\d+|iVar\d+|local_\w+|puVar\d+|'
            r'piVar\d+|pbVar\d+|pvVar\d+|in_\w+|unaff_\w+)\b'
        )
        matches = var_pattern.findall(pseudocode)
        stats.total_variables = len(set(matches)) if matches else 0

        if stats.total_variables == 0:
            stats.accuracy = 1.0
            return stats

        # 占位符变量 -> 推断不完整
        placeholder_pattern = re.compile(r'^var_\d+$|^uVar\d+$|^iVar\d+$')
        placeholders = [m for m in set(matches) if placeholder_pattern.match(m)]
        stats.missing_variables = len(placeholders)

        # 类型一致性：找变量声明但后续有不同的 cast 模式
        type_decl_pattern = re.compile(
            r'(int|uint|long|ulong|char|short|byte|float|double|void)\s+(\w+)'
        )
        declarations = type_decl_pattern.findall(pseudocode)
        declared_vars = set(name for _, name in declarations)
        stats.correctly_typed = len(declared_vars)

        # 启发式：统计类型标注 vs 占位符的比例
        total_typed = stats.correctly_typed + stats.missing_variables
        if total_typed > 0:
            stats.accuracy = stats.correctly_typed / total_typed

        # 检测类型不一致 (同一个变量被多次声明为不同类型)
        var_types: Dict[str, Set[str]] = {}
        for vtype, vname in declarations:
            if vname not in var_types:
                var_types[vname] = set()
            var_types[vname].add(vtype)
        stats.type_mismatches = sum(
            1 for types in var_types.values() if len(types) > 1
        )

        # 分类 — 给 findings 加一条
        if stats.missing_variables > 0:
            self.findings.append(ValidationFinding(
                rule_id="VAR_PLACEHOLDER",
                severity=ValidationSeverity.MEDIUM,
                message=f"发现 {stats.missing_variables} 个占位符变量名",
                detail=f"示例: {placeholders[:5]}",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))

        if stats.type_mismatches > 0:
            self.findings.append(ValidationFinding(
                rule_id="VAR_TYPE_INCONSISTENT",
                severity=ValidationSeverity.LOW,
                message=f"发现 {stats.type_mismatches} 处类型不一致",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))

        return stats

    # ------------------------------------------------------------------
    # 控制流校验
    # ------------------------------------------------------------------

    def _validate_control_flow(
        self, pseudocode: str, lines: List[str]
    ) -> ControlFlowStats:
        """
        控制流重建正确性评估：
        - 检测 /else 是否配对
        - 循环结构是否存在
        - goto/jump 残余
        - 大括号平衡
        """
        stats = ControlFlowStats()

        # if/else 配对检测
        if_count = len(re.findall(r'\bif\s*\(', pseudocode))
        else_count = len(re.findall(r'\belse\b', pseudocode))
        else_if_count = len(re.findall(r'\belse\s+if\b', pseudocode))

        # while/for 检测
        while_count = len(re.findall(r'\bwhile\s*\(', pseudocode))
        for_count = len(re.findall(r'\bfor\s*\(', pseudocode))
        do_count = len(re.findall(r'\bdo\s*\{', pseudocode))

        # switch 检测
        switch_count = len(re.findall(r'\bswitch\s*\(', pseudocode))

        # goto 残留 — 越多说明控制流越原始
        goto_count = len(re.findall(r'\bgoto\b', pseudocode))

        # 从伪代码推断期望的边数
        stats.total_edges_expected = (
            if_count + else_if_count + while_count + for_count +
            do_count + switch_count + 1  # +1 for entry
        )
        stats.total_edges_found = max(0, stats.total_edges_expected - goto_count)

        # 大括号平衡检查
        open_braces = pseudocode.count('{')
        close_braces = pseudocode.count('}')
        brace_balanced = (open_braces == close_braces)

        if not brace_balanced:
            stats.missing_edges += abs(open_braces - close_braces)
            self.findings.append(ValidationFinding(
                rule_id="CFG_BRACE_MISMATCH",
                severity=ValidationSeverity.HIGH,
                message=f"大括号不匹配: {{ = {open_braces}, }} = {close_braces}",
                detail="控制流块边界可能不正确",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))

        # goto 越少越好
        if goto_count > 0:
            stats.spurious_edges += goto_count
            self.findings.append(ValidationFinding(
                rule_id="CFG_GOTO_RESIDUAL",
                severity=ValidationSeverity.MEDIUM,
                message=f"检测到 {goto_count} 个 goto —— 控制流未完全还原",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))

        # 计算 precision/recall
        if stats.total_edges_expected > 0:
            stats.edge_recall = stats.total_edges_found / stats.total_edges_expected
        if stats.total_edges_found + stats.spurious_edges > 0:
            stats.edge_precision = (
                stats.total_edges_found /
                (stats.total_edges_found + stats.spurious_edges)
            )

        # 截断到 [0, 1]
        stats.edge_recall = max(0.0, min(1.0, stats.edge_recall))
        stats.edge_precision = max(0.0, min(1.0, stats.edge_precision))

        return stats

    # ------------------------------------------------------------------
    # 函数边界校验
    # ------------------------------------------------------------------

    def _validate_function_boundaries(
        self, pseudocode: str, lines: List[str]
    ) -> FunctionBoundaryStats:
        """
        函数边界精度评估：
          - 检测函数签名是否完整
          - prologue/epilogue 模式
          - 是否有截断或拼接的迹象
        """
        stats = FunctionBoundaryStats()

        # 找所有的函数签名
        func_sig_pattern = re.compile(
            r'^\s*(?:\w+(?:\s+\*)?\s+)+(\w+)\s*\([^)]*\)\s*\{?',
            re.MULTILINE
        )
        signatures = func_sig_pattern.findall(pseudocode)
        stats.total_functions_found = len(signatures)

        # 检测有效的函数签名（有返回类型 + 函数名）
        valid_sig_pattern = re.compile(
            r'^\s*(void|int|long|char|short|float|double|bool|'
            r'uint\w*|size_t|ssize_t|DWORD|WORD|BYTE|HRESULT|BOOL)\s+'
            r'(\w+)\s*\([^)]*\)',
            re.MULTILINE
        )
        valid_sigs = valid_sig_pattern.findall(pseudocode)
        stats.correct_boundaries = len(valid_sigs)

        if stats.total_functions_found > 0:
            stats.boundary_accuracy = (
                stats.correct_boundaries / stats.total_functions_found
            )

        # 检测常见的函数边界问题
        if stats.total_functions_found == 0:
            self.findings.append(ValidationFinding(
                rule_id="BOUNDARY_NO_FUNC",
                severity=ValidationSeverity.CRITICAL,
                message="未检测到任何函数定义",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))
        elif stats.boundary_accuracy < 0.5:
            self.findings.append(ValidationFinding(
                rule_id="BOUNDARY_LOW_QUALITY",
                severity=ValidationSeverity.HIGH,
                message=f"函数边界精度低: {stats.boundary_accuracy:.1%}",
                detail="仅有 {stats.correct_boundaries}/{stats.total_functions_found} 个有效签名",
                source_decompiler=self.decompiler_ai.get_active_decompiler(),
            ))

        return stats

    # ------------------------------------------------------------------
    # 跨编译器交叉校验
    # ------------------------------------------------------------------

    def _cross_validate(self, function_name: str) -> CrossDecompilerStats:
        """
        使用多个可用反编译器交叉校验同一个函数
        INTJ: 多编译器的一致性是"正确答案"的强信号
        """
        stats = CrossDecompilerStats()
        decompiled_outputs: Dict[str, str] = {}

        # 依次尝试各个可用的反编译器
        decompiler_order = [DECOMPILER_GHIDRA, DECOMPILER_IDA,
                            DECOMPILER_BINARYNINJA, DECOMPILER_RADARE2]

        for dec in decompiler_order:
            if not self.available_decompilers.get(dec):
                continue
            try:
                from modules.analysis.decompiler.decomp_ai import DecompilerAI
                d = DecompilerAI(self.binary_path, decompiler=dec)
                result = d.decompile(function_name)
                if result:
                    decompiled_outputs[dec] = strip_ansi_escape(result)
                    _debug_print(f"cross-validate: {dec} produced {len(result)} chars", 1)
            except Exception as e:
                logger.warning(f"跨校验 — {dec} 失败: {e}")

        stats.decompilers_used = list(decompiled_outputs.keys())

        # pairwise Jaccard 相似度
        keys = list(decompiled_outputs.keys())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                a_tokens = set(re.findall(r'\w+', decompiled_outputs[keys[i]].lower()))
                b_tokens = set(re.findall(r'\w+', decompiled_outputs[keys[j]].lower()))
                if a_tokens or b_tokens:
                    intersection = a_tokens & b_tokens
                    union = a_tokens | b_tokens
                    jaccard = len(intersection) / len(union) if union else 0.0
                    stats.pairwise_jaccard[f"{keys[i]}-{keys[j]}"] = round(jaccard, 4)

        # 共识比率
        if stats.pairwise_jaccard:
            stats.consensus_ratio = sum(stats.pairwise_jaccard.values()) / len(stats.pairwise_jaccard)

        if len(stats.decompilers_used) >= 2 and stats.consensus_ratio < 0.4:
            self.findings.append(ValidationFinding(
                rule_id="CROSS_LOW_CONSENSUS",
                severity=ValidationSeverity.HIGH,
                message=f"跨反编译器共识度低: {stats.consensus_ratio:.2f}",
                detail=f"参与反编译器: {', '.join(stats.decompilers_used)}",
            ))

        return stats

    # ------------------------------------------------------------------
    # 模式规则
    # ------------------------------------------------------------------

    def _run_pattern_rules(self, pseudocode: str, lines: List[str],
                           source: str = "unknown") -> None:
        """对所有内置模式运行检测。source 为反编译器名称，若 self 没有 decompiler_ai 则用传入值"""
        try:
            decomp_name = self.decompiler_ai.get_active_decompiler()  # type: ignore
        except AttributeError:
            decomp_name = source

        # 跑低置信度模式
        for rule_id, pattern, severity, message in _LOW_CONFIDENCE_PATTERNS:
            match = pattern.search(pseudocode)
            if match:
                line_no = -1
                for i, line in enumerate(lines):
                    if match.group(0) in line:
                        line_no = i + 1
                        break
                self.findings.append(ValidationFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    line_number=line_no,
                    actual=match.group(0)[:120],
                    source_decompiler=decomp_name,
                ))

        # 混淆指示器
        for rule_id, pattern, message in _OBFUSCATION_INDICATORS:
            matches = pattern.findall(pseudocode)
            if matches:
                self.findings.append(ValidationFinding(
                    rule_id=f"OBFUSCATION_{rule_id}",
                    severity=ValidationSeverity.LOW,
                    message=message,
                    detail=f"匹配到 {len(matches)} 处",
                    source_decompiler=decomp_name,
                ))

    # ------------------------------------------------------------------
    # Ground truth 对比
    # ------------------------------------------------------------------

    def _compare_with_ground_truth(self, decompiled_lines: List[str]) -> None:
        """
        与 ground truth 做逐行 diff
        """
        if not self.ground_truth_lines:
            return

        # 用 difflib 计算相似度
        sm = difflib.SequenceMatcher(
            None, self.ground_truth_lines, decompiled_lines
        )
        ratio = sm.ratio()

        if ratio < 0.5:
            self.findings.append(ValidationFinding(
                rule_id="GT_LOW_SIMILARITY",
                severity=ValidationSeverity.HIGH,
                message=f"与 ground truth 相似度仅 {ratio:.2%}",
                detail=f"GT lines: {len(self.ground_truth_lines)}, "
                        f"decompiled: {len(decompiled_lines)}",
            ))
        elif ratio < 0.8:
            self.findings.append(ValidationFinding(
                rule_id="GT_MODERATE_SIMILARITY",
                severity=ValidationSeverity.MEDIUM,
                message=f"与 ground truth 相似度 {ratio:.2%}",
            ))

        # 详细 diff — 仅记录前 20 个 opcode 块
        opcodes = sm.get_opcodes()
        diff_count = 0
        for tag, i1, i2, j1, j2 in opcodes:
            if tag in ('replace', 'delete', 'insert'):
                diff_count += 1
                if diff_count <= 20:
                    self.findings.append(ValidationFinding(
                        rule_id=f"GT_DIFF_{tag.upper()}",
                        severity=ValidationSeverity.LOW,
                        message=f"GT 差异 (block {diff_count}): {tag}",
                        expected=str(self.ground_truth_lines[i1:i2])[:200],
                        actual=str(decompiled_lines[j1:j2])[:200],
                    ))

    # ------------------------------------------------------------------
    # 评分 & 报告
    # ------------------------------------------------------------------

    def _compute_confidence(self, report: ValidationReport) -> float:
        """
        综合置信度评分（0.0 ~ 1.0）
        
        权重分配:
        - 变量恢复: 0.25
        - 控制流: 0.30
        - 函数边界: 0.20
        - 跨编译器: 0.15
        - 模式惩罚: 0.10
        """
        scores: List[float] = []

        # 变量恢复 (0.25)
        scores.append((0.25, report.var_stats.accuracy))

        # 控制流 — 取 precision/recall 的调和平均 (0.30)
        if report.cfg_stats.edge_precision + report.cfg_stats.edge_recall > 0:
            f1 = 2 * report.cfg_stats.edge_precision * report.cfg_stats.edge_recall / \
                 (report.cfg_stats.edge_precision + report.cfg_stats.edge_recall)
        else:
            f1 = report.cfg_stats.edge_recall
        scores.append((0.30, f1))

        # 函数边界 (0.20)
        scores.append((0.20, report.boundary_stats.boundary_accuracy))

        # 跨编译器共识 (0.15)
        scores.append((0.15, report.cross_stats.consensus_ratio))

        # 模式惩罚 (0.10) — 每条 finding 扣分
        penalty = 0.0
        severity_weights = {
            ValidationSeverity.CRITICAL: 0.15,
            ValidationSeverity.HIGH: 0.08,
            ValidationSeverity.MEDIUM: 0.04,
            ValidationSeverity.LOW: 0.02,
            ValidationSeverity.INFO: 0.0,
        }
        for f in report.findings:
            penalty += severity_weights.get(f.severity, 0.01)
        penalty = min(1.0, penalty)
        mode_score = max(0.0, 1.0 - penalty)
        scores.append((0.10, mode_score))

        # 加权平均
        total_weight = sum(w for w, _ in scores)
        if total_weight == 0:
            return 0.0

        weighted = sum(w * s for w, s in scores) / total_weight
        return round(max(0.0, min(1.0, weighted)), 4)

    def _compute_grade(self, score: float) -> str:
        """分数 -> 等级"""
        if score >= 0.90:
            return "A"
        elif score >= 0.75:
            return "B"
        elif score >= 0.55:
            return "C"
        elif score >= 0.35:
            return "D"
        else:
            return "F"

    def _generate_report_id(self, function_name: str) -> str:
        """生成报告 ID"""
        ts = int(time.time())
        short_hash = hashlib.md5(
            f"{self.binary_path}:{function_name}:{ts}".encode()
        ).hexdigest()[:8]
        return f"VR-{short_hash}-{ts}"

    def generate_report_json(self, report: ValidationReport) -> str:
        """导出 JSON 格式报告"""
        def _serialize(obj):
            if isinstance(obj, ValidationReport):
                return {
                    'report_id': obj.report_id,
                    'timestamp': obj.timestamp,
                    'binary_path': obj.binary_path,
                    'binary_hash': obj.binary_hash,
                    'function_name': obj.function_name,
                    'var_stats': _serialize(obj.var_stats),
                    'cfg_stats': _serialize(obj.cfg_stats),
                    'boundary_stats': _serialize(obj.boundary_stats),
                    'cross_stats': _serialize(obj.cross_stats),
                    'findings': [_serialize(f) for f in obj.findings],
                    'confidence_score': obj.confidence_score,
                    'overall_grade': obj.overall_grade,
                    'elapsed_seconds': obj.elapsed_seconds,
                    'ground_truth_available': obj.ground_truth_available,
                    'warnings': obj.warnings,
                }
            elif isinstance(obj, (VariableRecoveryStats, ControlFlowStats,
                                  FunctionBoundaryStats, CrossDecompilerStats)):
                return {k: v for k, v in obj.__dict__.items()}
            elif isinstance(obj, ValidationFinding):
                return {k: v for k, v in obj.__dict__.items()}
            return str(obj)

        return json.dumps(_serialize(report), indent=2, ensure_ascii=False)

    def generate_report_markdown(self, report: ValidationReport) -> str:
        """导出 Markdown 格式报告"""
        lines = [
            f"# Decompiler Validation Report",
            f"",
            f"**Report ID:** {report.report_id}",
            f"**Binary:** `{os.path.basename(report.binary_path)}`",
            f"**Hash:** `{report.binary_hash}`",
            f"**Function:** `{report.function_name}`",
            f"**Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.timestamp))}",
            f"**Ground Truth:** {'Yes' if report.ground_truth_available else 'No'}",
            f"",
            f"## Overall Score",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Confidence | **{report.confidence_score:.2%}** |",
            f"| Grade | **{report.overall_grade}** |",
            f"| Elapsed | {report.elapsed_seconds:.2f}s |",
            f"",
            f"## Variable Recovery",
            f"",
            f"| Stat | Value |",
            f"|------|-------|",
            f"| Accuracy | {report.var_stats.accuracy:.2%} |",
            f"| Correctly Typed | {report.var_stats.correctly_typed} |",
            f"| Type Mismatches | {report.var_stats.type_mismatches} |",
            f"| Missing Variables | {report.var_stats.missing_variables} |",
            f"",
            f"## Control Flow",
            f"",
            f"| Stat | Value |",
            f"|------|-------|",
            f"| Edge Recall | {report.cfg_stats.edge_recall:.2%} |",
            f"| Edge Precision | {report.cfg_stats.edge_precision:.2%} |",
            f"| Missing Edges | {report.cfg_stats.missing_edges} |",
            f"| Spurious Edges | {report.cfg_stats.spurious_edges} |",
            f"",
            f"## Function Boundaries",
            f"",
            f"| Stat | Value |",
            f"|------|-------|",
            f"| Boundary Accuracy | {report.boundary_stats.boundary_accuracy:.2%} |",
            f"| Functions Found | {report.boundary_stats.total_functions_found} |",
            f"| Correct Boundaries | {report.boundary_stats.correct_boundaries} |",
            f"",
        ]

        if report.cross_stats.decompilers_used:
            lines.extend([
                f"## Cross-Decompiler",
                f"",
                f"| Stat | Value |",
                f"|------|-------|",
                f"| Consensus Ratio | {report.cross_stats.consensus_ratio:.2%} |",
                f"| Decompilers | {', '.join(report.cross_stats.decompilers_used)} |",
                f"",
            ])

        if report.findings:
            lines.append("## Findings")
            lines.append("")
            for f in report.findings:
                sev_icon = {"CRITICAL": ":red_circle:", "HIGH": ":orange_circle:",
                            "MEDIUM": ":yellow_circle:", "LOW": ":green_circle:",
                            "INFO": ":information_source:"}.get(
                    f.severity.value.upper() if hasattr(f.severity, 'value') else str(f.severity).upper(),
                    ":question:"
                )
                lines.append(f"- {sev_icon} **[{f.rule_id}]** {f.message}")

        if report.warnings:
            lines.append("")
            lines.append("## Warnings")
            for w in report.warnings:
                lines.append(f"- :warning: {w}")

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# 便捷函数 — 给不想构造完整对象的懒人用
# ---------------------------------------------------------------------------

def validate_decompiled_output(
    binary_path: str,
    function_name: str = "main",
    ground_truth_path: Optional[str] = None,
) -> ValidationReport:
    """
    一站式校验：给一个 binary 路径和函数名，返回完整报告
    
    Args:
    binary_path: 二进制文件路径
    function_name: 目标函数名
    ground_truth_path: 可选的参考源码路径
    
    返回:
    校验Report
    """
    validator = DecompilerValidator(binary_path, ground_truth_path)
    return validator.validate(function_name)


def quick_validation_score(
    pseudocode: str,
    ground_truth: Optional[str] = None,
) -> float:
    """
    快速评分子——只做模式匹配，不跑外部反编译器
    在 CI 或自动化流水线里用，速度快但不精确
    
    Args:
    pseudocode: 反编译输出的伪代码
    ground_truth: 可选的参考代码
    
    返回:
    置信度 [0.0, 1.0]
    """
    lines = pseudocode.split('\n')
    findings = []

    # 跑模式规则（不依赖 DecompilerAI 实例）
    val = DecompilerValidator.__new__(DecompilerValidator)
    val.findings = findings
    val._run_pattern_rules(pseudocode, lines)  # type: ignore

    # 简化评分
    penalty = sum(
        {"critical": 0.20, "high": 0.10, "medium": 0.05, "low": 0.02, "info": 0.0}.get(
            str(f.severity.value if hasattr(f.severity, 'value') else f.severity).lower(), 0.01
        )
        for f in findings
    )

    # 如果有 ground truth，加 difflib 相似度
    truth_bonus = 0.0
    if ground_truth:
        gt_lines = ground_truth.split('\n')
        sm = difflib.SequenceMatcher(None, gt_lines, lines)
        truth_bonus = sm.ratio() * 0.3  # 最多加 0.3

    base = max(0.0, 1.0 - penalty)
    score = min(1.0, base + truth_bonus)
    return round(score, 4)


# 2026-08-03: 这个 辅助 留作未来拓展——等接上 Ghidra script 的
#             结构化输出之后可以直接对比 AST 树
def _ast_similarity(tree_a: Any, tree_b: Any) -> float:
    # AST-level similarity comparison (placeholder)
    # TODO(hermit1016): wire up to actual AST extraction from decompiled C
    return 0.0

# ---- 遗留 v1 校验 流水线 (已废弃) ----
# def _run_full_validation_pipeline(binary_path, functions):
#     reports = []
#     for fn in functions:
#         v = DecompilerValidator(binary_path)
#         r = v.validate(fn)
#         md = v.generate_report_markdown(r)
#         reports.append((fn, r, md))
#     return reports
