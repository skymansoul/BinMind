# 蜕变预言机引擎 — 驱动蜕变关系检查的编排与报告层
#
# 定位:
#   本模块不定义蜕变关系 (见 metamorphic_relations.py), 而是提供:
#     1. 蜕变测试的编排循环: 对每条关系生成变换后输入 → 执行 → 断言
#     2. 多引擎聚合: 同一蜕变关系在多个分析引擎上并行验证
#     3. 结果报告: 按关系/引擎/严重级组织的结构化输出
#     4. 反馈融合: 将蜕变违例反馈给 fuzzer 作为新的种子能量信号
#
# 与现有模块的接合:
#   - diff_tester.py: 接收 MetamorphicReport, 补充差分测试结果
# drift_calibrator.py: 蜕变违例率上升时可触发策略调整建议
#   - triage_reporter.py: 蜕变违例可作为 TriageEntry 导出
#
# 核心度量:
#   MR Violation Rate (MVR): 蜕变关系违例数 / 总检查数
#   MVR 的突然上升通常指示:
#     a) 分析工具版本回归 (对已知关系的新违例)
#     b) 输入语料中出现了触发工具边界行为的新模式
#     c) 工具之间的交互效应 (多引擎模式下, 某引擎的异常可能仅
#        在蜕变变换后才暴露)
#
# 文献:
#   Segura et al. 2016, "A Survey on Metamorphic Testing", ACM Computing Surveys
#     — 蜕变测试系统综述, 本项目参照其 MR 选择准则和执行框架
#   ROSA — 蜕变预言机驱动 fuzzing;
#     本项目取其 MR+oracle+fuzzing 的三元结构, 但将 MR 作用于分析工具
#     而非被测二进制, 构成一种元测试 (meta-testing) 框架

from __future__ import annotations

import hashlib
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .metamorphic_relations import (
    MetamorphicRelation,
    PREDEFINED_RELATIONS,
    RelationScope,
    TransformKind,
    get_relations_for_scope,
)


class ViolationSeverity(str, Enum):
    """蜕变违例严重级——与 triage 三分类对齐"""
    CRITICAL = "critical"    # 崩溃/挂起不一致
    HIGH = "high"            # 结构级偏离 (CFG变化, 语义哈希偏离)
    MEDIUM = "medium"        # 度量级偏离 (指令计数异常等)
    LOW = "low"              # 非关键不一致


@dataclass
class MRViolation:
    """单条蜕变关系违例"""
    mr_id: str
    transform_kind: str
    engine_name: str
    severity: ViolationSeverity
    description: str
    original_hash: str = ""
    transformed_hash: str = ""
    execution_time_ms: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MRCheckResult:
    """单条蜕变关系在单个引擎上的检查结果"""
    mr_id: str
    engine_name: str
    passed: bool
    violation: Optional[MRViolation] = None
    execution_time_ms: float = 0.0


@dataclass
class MetamorphicReport:
    """蜕变测试完整报告"""
    total_relations: int = 0
    total_checks: int = 0         # 关系数 × 引擎数 × 输入数
    passed: int = 0
    violations: List[MRViolation] = field(default_factory=list)
    by_relation: Dict[str, List[MRCheckResult]] = field(default_factory=dict)
    by_engine: Dict[str, List[MRCheckResult]] = field(default_factory=dict)
    violation_rate: float = 0.0
    execution_time_s: float = 0.0
    summary: str = ""


class MetamorphicOracle:
    """蜕变预言机——驱动蜕变关系的编排、执行和报告。

    典型用法:
        oracle = MetamorphicOracle()
        oracle.add_engine("ghidra", ghidra_runner)
        oracle.add_engine("ida", ida_runner)
        report = oracle.check(
            inputs=[b"\x55\x48\x89\xe5\xb8\x00\x00\x00\x00\x5d\xc3"],
            relations=[mr_nop, mr_align],
        )
        # 将违例反馈给 fuzzer
        if report.violation_rate > 0.1:
            fuzzer.boost_energy(report.violations)
    """

    def __init__(self, seed: Optional[int] = None):
        self._engines: Dict[str, Callable[[bytes], Any]] = {}
        self._history: List[MetamorphicReport] = []
        # 违例率 EWMA——平滑短期波动
        self._ewma_violation_rate: float = 0.0
        self._ewma_alpha: float = 0.3

    def add_engine(self, name: str, runner: Callable[[bytes], Any]) -> None:
        """注册分析引擎。runner(bytes) -> 引擎输出对象 (需含 stdout/stderr)。"""
        self._engines[name] = runner

    def remove_engine(self, name: str) -> None:
        self._engines.pop(name, None)

    @property
    def engine_names(self) -> List[str]:
        return list(self._engines.keys())

    # 主检查入口

    def check(self,
              inputs: List[bytes],
              relations: Optional[List[MetamorphicRelation]] = None,
              engines: Optional[List[str]] = None,
              stop_on_first_violation: bool = False,
              ) -> MetamorphicReport:
        """执行蜕变测试。

        inputs: 原始输入集合, 每条关系对每个输入生成变换版本并分别执行。
        relations/engines 默认使用全部已注册项。
        stop_on_first_violation 用于快速检查模式。
        """
        if relations is None:
            relations = list(PREDEFINED_RELATIONS.values())
        if engines is None:
            engines = list(self._engines.keys())

        t_start = time.perf_counter()
        report = MetamorphicReport(total_relations=len(relations))
        report.total_checks = len(relations) * len(engines) * len(inputs)

        for mr in relations:
            report.by_relation[mr.mr_id] = []
            for eng_name in engines:
                runner = self._engines.get(eng_name)
                if runner is None:
                    continue
                if eng_name not in report.by_engine:
                    report.by_engine[eng_name] = []

                for original_input in inputs:
                    check = self._check_one(mr, eng_name, runner, original_input)
                    report.by_relation[mr.mr_id].append(check)
                    report.by_engine[eng_name].append(check)

                    if check.passed:
                        report.passed += 1
                    elif check.violation is not None:
                        report.violations.append(check.violation)
                        if stop_on_first_violation:
                            break

                if stop_on_first_violation and report.violations:
                    break
            if stop_on_first_violation and report.violations:
                break

        report.execution_time_s = time.perf_counter() - t_start
        report.violation_rate = (
            len(report.violations) / max(1, report.total_checks)
        )
        # 更新 EWMA 供策略层使用
        self._ewma_violation_rate = (
            self._ewma_alpha * report.violation_rate
            + (1 - self._ewma_alpha) * self._ewma_violation_rate
        )
        report.summary = self._build_summary(report)
        self._history.append(report)
        return report

    def _check_one(self,
                   mr: MetamorphicRelation,
                   engine_name: str,
                   runner: Callable[[bytes], Any],
                   original_input: bytes,
                   ) -> MRCheckResult:
        """对单条关系 + 单个引擎 + 单个原始输入执行一次检查"""
        t0 = time.perf_counter()

        # 执行原始输入
        try:
            orig_output = runner(original_input)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return MRCheckResult(
                mr_id=mr.mr_id, engine_name=engine_name, passed=False,
                violation=MRViolation(
                    mr_id=mr.mr_id,
                    transform_kind=mr.transform_kind.value,
                    engine_name=engine_name,
                    severity=ViolationSeverity.CRITICAL,
                    description=f"原始输入执行异常: {exc}",
                    execution_time_ms=elapsed,
                    context={"exception": str(exc)},
                ),
                execution_time_ms=elapsed,
            )

        # 生成变换后输入并执行
        try:
            transformed_input = mr.input_transform(original_input)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return MRCheckResult(
                mr_id=mr.mr_id, engine_name=engine_name, passed=False,
                violation=MRViolation(
                    mr_id=mr.mr_id,
                    transform_kind=mr.transform_kind.value,
                    engine_name=engine_name,
                    severity=ViolationSeverity.LOW,
                    description=f"输入变换失败: {exc}",
                    execution_time_ms=elapsed,
                ),
                execution_time_ms=elapsed,
            )

        try:
            trans_output = runner(transformed_input)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return MRCheckResult(
                mr_id=mr.mr_id, engine_name=engine_name, passed=False,
                violation=MRViolation(
                    mr_id=mr.mr_id,
                    transform_kind=mr.transform_kind.value,
                    engine_name=engine_name,
                    severity=ViolationSeverity.CRITICAL,
                    description=f"变换后输入执行异常: {exc}",
                    execution_time_ms=elapsed,
                    context={"exception": str(exc)},
                ),
                execution_time_ms=elapsed,
            )

        # 断言蜕变关系
        elapsed = (time.perf_counter() - t0) * 1000
        try:
            passed, msg = mr.output_predicate(orig_output, trans_output)
        except Exception as exc:
            return MRCheckResult(
                mr_id=mr.mr_id, engine_name=engine_name, passed=False,
                violation=MRViolation(
                    mr_id=mr.mr_id,
                    transform_kind=mr.transform_kind.value,
                    engine_name=engine_name,
                    severity=ViolationSeverity.MEDIUM,
                    description=f"断言执行异常: {exc}",
                    execution_time_ms=elapsed,
                    context={"exception": str(exc), "traceback": traceback.format_exc()},
                ),
                execution_time_ms=elapsed,
            )

        if passed:
            return MRCheckResult(
                mr_id=mr.mr_id, engine_name=engine_name,
                passed=True, execution_time_ms=elapsed,
            )

        return MRCheckResult(
            mr_id=mr.mr_id, engine_name=engine_name, passed=False,
            violation=MRViolation(
                mr_id=mr.mr_id,
                transform_kind=mr.transform_kind.value,
                engine_name=engine_name,
                severity=self._classify_severity(mr, msg),
                description=msg,
                original_hash=self._hash_output(orig_output),
                transformed_hash=self._hash_output(trans_output),
                execution_time_ms=elapsed,
            ),
            execution_time_ms=elapsed,
        )

    # 多引擎共识模式

    def check_consensus(self,
                        inputs: List[bytes],
                        relations: Optional[List[MetamorphicRelation]] = None,
                        consensus_threshold: float = 0.5,
                        ) -> MetamorphicReport:
        """多引擎共识模式: 仅当 >= consensus_threshold 比例的引擎同时违例时才报告。

        这过滤掉单个引擎的偶发异常, 聚焦于跨引擎共同缺陷
        (如编译器生成的代码导致多个反编译器同时解析错误)。
        """
        base_report = self.check(inputs, relations, stop_on_first_violation=False)
        engine_count = len(self._engines)

        # 按 (mr_id, input_hash) 聚合各引擎的违例计数
        violation_groups: Dict[Tuple[str, str], List[MRViolation]] = defaultdict(list)
        for v in base_report.violations:
            key = (v.mr_id, v.original_hash)
            violation_groups[key].append(v)

        consensus_violations: List[MRViolation] = []
        for key, group in violation_groups.items():
            violating_engines = {v.engine_name for v in group}
            if len(violating_engines) / max(1, engine_count) >= consensus_threshold:
                # 标记为共识违例
                for v in group:
                    v.severity = ViolationSeverity.HIGH
                    v.context["consensus"] = True
                    v.context["violating_engines"] = sorted(violating_engines)
                consensus_violations.extend(group)

        base_report.violations = consensus_violations
        base_report.violation_rate = (
            len(consensus_violations) / max(1, base_report.total_checks)
        )
        base_report.summary = self._build_summary(base_report)
        return base_report

    # 反馈接口: 供 fuzzer 使用

    def violation_signal(self) -> float:
        """返回 [0, 1] 的蜕变违例信号, 供种子能量调度使用。

        较高值 → 当前语料包含触发分析工具边界行为的输入,
        应提升这些种子及相关变异体的能量。
        """
        return min(1.0, self._ewma_violation_rate * 10.0)

    def feedback_to_drift_calibrator(self) -> Dict[str, Any]:
        """生成供 drift_calibrator.py 使用的结构化反馈"""
        return {
            "ewma_violation_rate": round(self._ewma_violation_rate, 4),
            "total_checks": sum(r.total_checks for r in self._history[-3:]),
            "total_violations": sum(len(r.violations) for r in self._history[-3:]),
            "recent_mr_ids": list({
                v.mr_id for r in self._history[-3:]
                for v in r.violations
            }),
        }

    # 辅助

    @staticmethod
    def _hash_output(output: Any) -> str:
        data = output
        if hasattr(output, 'stdout'):
            data = output.stdout
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        if isinstance(data, bytes):
            return hashlib.sha256(data[:4096]).hexdigest()[:12]
        return hashlib.sha256(str(data).encode()).hexdigest()[:12]

    @staticmethod
    def _classify_severity(mr: MetamorphicRelation, msg: str) -> str:
        msg_lower = msg.lower()
        if any(kw in msg_lower for kw in ('crash', '崩溃', 'segfault', 'signal')):
            return ViolationSeverity.CRITICAL
        if any(kw in msg_lower for kw in ('cfg', '结构', 'structure', 'hash', 'graph')):
            return ViolationSeverity.HIGH
        if any(kw in msg_lower for kw in ('指令', 'instruction', 'count', '数量')):
            return ViolationSeverity.MEDIUM
        return ViolationSeverity.LOW

    @staticmethod
    def _build_summary(report: MetamorphicReport) -> str:
        lines = [
            f"蜕变测试: {report.total_relations} 关系 × "
            f"{report.total_checks} 检查, "
            f"通过 {report.passed}/{report.total_checks}, "
            f"违例率 {report.violation_rate:.2%}",
        ]
        if report.violations:
            lines.append(f"违例详情 ({len(report.violations)} 条):")
            for v in report.violations[:10]:
                lines.append(
                    f"  [{v.severity}] {v.mr_id} @ {v.engine_name}: "
                    f"{v.description[:120]}")
            if len(report.violations) > 10:
                lines.append(f"  ... 及其他 {len(report.violations) - 10} 条")
        return "\n".join(lines)

    # 统计与重置

    def stats(self) -> Dict[str, Any]:
        return {
            "engines": len(self._engines),
            "history_reports": len(self._history),
            "ewma_violation_rate": round(self._ewma_violation_rate, 4),
            "total_violations_ever": sum(
                len(r.violations) for r in self._history),
        }

    def reset(self) -> None:
        self._history.clear()
        self._ewma_violation_rate = 0.0


# 便捷入口

def quick_check(inputs: List[bytes],
                engine_runners: Dict[str, Callable[[bytes], Any]],
                relations: Optional[List[MetamorphicRelation]] = None,
                ) -> MetamorphicReport:
    """便捷入口: 使用给定引擎和输入做快速蜕变检查"""
    oracle = MetamorphicOracle()
    for name, runner in engine_runners.items():
        oracle.add_engine(name, runner)
    return oracle.check(inputs, relations)
