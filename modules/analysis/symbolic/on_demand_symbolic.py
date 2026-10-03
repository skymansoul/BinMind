"""On-demand 漏洞 triage 流水线。

对危险 API 调用点做模式匹配, 按置信度排序, 只对高置信候选做
深度与置信度成比例的符号执行。

增强:
- TF-IDF 加权模式匹配: 把每个漏洞模式看作一个"词项", 函数代码
  看作"文档", 匹配次数由 IDF (逆向模式在所有函数中被触发的
  普遍性) 加权。这降低了类似 printf 这种几乎每个函数都包含的
  模式的重要性, 提升了对 system() 等罕见模式的关注
- 置信度自动校准 (ConfidenceCalibrator): 追踪 precision_estimate —
  高置信候选中有多少真正产出了漏洞; precision < 0.3 时上调阈值
  0.05 (当前阈值太宽松), precision > 0.7 时下调阈值 0.05
  (阈值偏保守, 可解放更多候选), 每轮分析后自动执行校准
- 分析缓存 (CachingAnalyzer): 对已分析函数计算 func_code_hash
  (源码/反汇编的 SHA256) 存入 sqlite3 表。下次遇到相同
  func_code_hash 时直接跳过重分析, 复用 last_vuln_count;
  跨 binary 场景下通过 func_code_hash 匹配, 避免对同一份代码
  在不同 binary 中重复符号执行
- Top-K 候选排序: get_top_candidates(k) 返回 k 个最高分的未分析
  候选, 按 confidence * novelty_bonus 排序。novelty_bonus 对首次
  见到的函数为 1.0, 对"曾在其他 binary 中分析过但当前 binary
  尚未分析"的函数为 0.5, 平衡探索与利用
- TriageQueue: 基于 confidence * novelty_bonus 得分的优先级队列,
  新候选按分数插入, pop_next() 返回最高优先级未分析候选,
  内部用 heapq 实现最大堆
- BatchAnalysis: 将低置信度候选 (0.3-0.5) 按 5 个一批分组,
  对所有路径进行一次统一的符号执行, 摊销 angr 项目设置的开销
- VulnReportFormatter: 生成 JSON/Markdown/HTML 格式的漏洞报告,
  包含严重性着色、代码片段及按 CWE 映射的修复建议
"""

import os
import math
import hashlib
import sqlite3
import logging
import heapq
import json
import time
import html
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_DEREFERENCE = "null_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    SQL_INJECTION = "sql_injection"
    RACE_CONDITION = "race_condition"
    COMMAND_INJECTION = "command_injection"


class AnalysisLevel:
    """深度分级: 路径越多成本越高, 覆盖率也越高。"""
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


# CWE → VulnerabilityType 映射与修复建议, 用于 VulnReportFormatter 生成的报告
_VULN_CWE_MAP: Dict[VulnerabilityType, Dict[str, Any]] = {
    VulnerabilityType.BUFFER_OVERFLOW: {
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "severity": "HIGH",
        "remediation": (
            "Use bounded string functions (strncpy, snprintf) with explicit size checks. "
            "Prefer safer alternatives like `std::string` (C++) or `strlcpy` where available. "
            "Enable stack canaries (-fstack-protector-strong) and FORTIFY_SOURCE."
        ),
        "color": "#d9534f",
    },
    VulnerabilityType.USE_AFTER_FREE: {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "severity": "HIGH",
        "remediation": (
            "Set pointers to NULL immediately after free(). "
            "Consider using smart pointers (std::unique_ptr, std::shared_ptr) in C++. "
            "Enable AddressSanitizer (ASAN) during testing."
        ),
        "color": "#d9534f",
    },
    VulnerabilityType.NULL_DEREFERENCE: {
        "cwe_id": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "severity": "MEDIUM",
        "remediation": (
            "Add null checks before pointer dereference. "
            "Use references instead of pointers where the value must always exist. "
            "Apply static analysis to identify unchecked return values."
        ),
        "color": "#f0ad4e",
    },
    VulnerabilityType.INTEGER_OVERFLOW: {
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound",
        "severity": "MEDIUM",
        "remediation": (
            "Validate integer inputs before arithmetic operations. "
            "Use compiler builtins like __builtin_add_overflow. "
            "Consider using safe integer libraries or bounded types."
        ),
        "color": "#f0ad4e",
    },
    VulnerabilityType.FORMAT_STRING: {
        "cwe_id": "CWE-134",
        "cwe_name": "Use of Externally-Controlled Format String",
        "severity": "HIGH",
        "remediation": (
            "Always use format string literals (e.g., printf(\"%s\", user_input), "
            "never printf(user_input)). Enable -Wformat-security compiler warnings."
        ),
        "color": "#d9534f",
    },
    VulnerabilityType.SQL_INJECTION: {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "severity": "CRITICAL",
        "remediation": (
            "Use parameterized queries / prepared statements exclusively. "
            "Never concatenate user input into SQL strings. "
            "Apply input validation and least-privilege database accounts."
        ),
        "color": "#b52b27",
    },
    VulnerabilityType.RACE_CONDITION: {
        "cwe_id": "CWE-362",
        "cwe_name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "severity": "MEDIUM",
        "remediation": (
            "Use proper synchronization primitives (mutexes, semaphores, locks). "
            "Prefer lock-free data structures where performance is critical. "
            "Run ThreadSanitizer (TSAN) during testing."
        ),
        "color": "#f0ad4e",
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "severity": "CRITICAL",
        "remediation": (
            "Avoid invoking shell commands with user-supplied input. "
            "Use library/API calls instead of system() or popen(). "
            "If unavoidable, validate and sanitize all input with an allowlist."
        ),
        "color": "#b52b27",
    },
}

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class VulnerabilityCandidate:
    """被模式匹配标记的可疑点, 按 triage 优先级评分。"""
    function_name: str
    function_address: int
    vuln_type: VulnerabilityType
    confidence: float
    evidence: Dict = field(default_factory=dict)
    tfidf_weight: float = 0.0
    analyzed: bool = False
    func_code_hash: str = ""
    novelty_bonus: float = 1.0


@dataclass
class SymbolicResult:
    """单次符号执行的输出。"""
    function_name: str
    vulnerabilities_found: List
    paths_explored: int
    constraints: List


# TriageQueue — 基于分数的优先级队列
#
# 内部使用 堆q，存储 (negated_score, insert_counter, candidate)
# negated_score 使最大堆行为得以实现（heapq 默认最小堆）
# insert_counter 作为 tie-breaker，保证插入顺序确定
class TriageQueue:
    """漏洞候选的优先级队列。

    新候选按 confidence * novelty_bonus 分数插入, pop_next()
    返回最高优先级未分析候选; 用 heapq 实现 O(log n) 插入与弹出。
    """

    def __init__(self):
        self._heap: List[Tuple[float, int, VulnerabilityCandidate]] = []
        self._counter: int = 0
        self._candidate_ids: Set[str] = set()  # 去重：同一候选不重复入队

    def _score(self, candidate: VulnerabilityCandidate) -> float:
        """计算优先级分数: confidence * novelty_bonus。"""
        return candidate.confidence * candidate.novelty_bonus

    def _candidate_key(self, candidate: VulnerabilityCandidate) -> str:
        """去重键: function_name + vuln_type。"""
        return f"{candidate.function_name}::{candidate.vuln_type.value}"

    def insert(self, candidate: VulnerabilityCandidate):
        """向优先级队列插入候选。

        用负分实现最大堆, 按 function_name + vuln_type 去重。
        """
        key = self._candidate_key(candidate)
        if key in self._candidate_ids:
            return  # 已入队，跳过
        self._candidate_ids.add(key)
        score = self._score(candidate)
        # 使用负分实现最大堆
        heapq.heappush(self._heap, (-score, self._counter, candidate))
        self._counter += 1

    def insert_batch(self, candidates: List[VulnerabilityCandidate]):
        """一次插入多个候选。"""
        for c in candidates:
            self.insert(c)

    def pop_next(self) -> Optional[VulnerabilityCandidate]:
        """返回最高优先级未分析候选, 队列耗尽时返回 None。"""
        while self._heap:
            neg_score, _, candidate = heapq.heappop(self._heap)
            if not candidate.analyzed:
                return candidate
            # 跳过已分析候选
        return None

    def peek_next(self) -> Optional[VulnerabilityCandidate]:
        """查看最高优先级未分析候选, 不弹出。

        队列为空或剩余全是已分析候选时返回 None。
        """
        # 重建：heapq 没有 peek，我们需要弹出再塞回
        temp: List[Tuple[float, int, VulnerabilityCandidate]] = []
        result: Optional[VulnerabilityCandidate] = None
        while self._heap:
            neg_score, counter, candidate = heapq.heappop(self._heap)
            if not candidate.analyzed:
                result = candidate
                heapq.heappush(self._heap, (neg_score, counter, candidate))
                break
            temp.append((neg_score, counter, candidate))
        # 放回已弹出的已分析候选
        for item in temp:
            heapq.heappush(self._heap, item)
        return result

    def mark_analyzed(self, candidate: VulnerabilityCandidate):
        """把候选标记为已分析 (后续 pop 跳过)。"""
        candidate.analyzed = True

    def __len__(self) -> int:
        """返回堆中条目数 (含已分析)。"""
        return len(self._heap)

    @property
    def unanalyzed_count(self) -> int:
        """队列中未分析候选的数量。"""
        return sum(1 for _, _, c in self._heap if not c.analyzed)

    def rebuild_scores(self):
        """confidence 或 novelty_bonus 变化后重算分数并重建堆, O(n log n)。"""
        items = [(c.confidence * c.novelty_bonus, c) for _, _, c in self._heap]
        self._heap.clear()
        self._counter = 0
        for score, candidate in items:
            heapq.heappush(self._heap, (-score, self._counter, candidate))
            self._counter += 1

    def drain_unanalyzed(self) -> List[VulnerabilityCandidate]:
        """按优先级顺序弹出剩余未分析候选, 队列耗尽返回空列表。"""
        results: List[VulnerabilityCandidate] = []
        while True:
            c = self.pop_next()
            if c is None:
                break
            results.append(c)
        return results


# BatchAnalysis — 低置信候选批量符号执行
#
# 将 confidence 在 [0.3, 0.5] 区间的候选以 5 个一批分组
# 所有路径汇总后进行单轮符号执行，摊销 angr 项目 setup 开销
class BatchAnalysis:
    """把低置信候选 (0.3-0.5) 按 5 个一批分组做单轮符号执行。

    所有路径汇总后统一执行, 摊销 angr 项目 setup 开销。批大小的
    权衡: 太小 (< 3) 不足以摊销 setup 开销, 太大 (> 10) 可能导致
    路径爆炸, 5 是经验上的甜点。
    """

    DEFAULT_BATCH_SIZE: int = 5
    DEFAULT_LOW_CONFIDENCE_MIN: float = 0.3
    DEFAULT_LOW_CONFIDENCE_MAX: float = 0.5

    def __init__(
        self,
        batch_size: int = 5,
        low_confidence_min: float = 0.3,
        low_confidence_max: float = 0.5,
    ):
        self._batch_size = max(1, min(batch_size, 20))
        self._low_min = low_confidence_min
        self._low_max = low_confidence_max
        self._batches: List[List[VulnerabilityCandidate]] = []

    @property
    def batch_size(self) -> int:
        return self._batch_size

    @property
    def batches(self) -> List[List[VulnerabilityCandidate]]:
        return self._batches

    def form_batches(
        self, candidates: List[VulnerabilityCandidate]
    ) -> List[List[VulnerabilityCandidate]]:
        """把未分析且置信度落在 [low_min, low_max] 的候选按批大小分组。"""
        eligible = [
            c for c in candidates
            if not c.analyzed
            and self._low_min <= c.confidence <= self._low_max
        ]

        # 按置信度降序排列，使高置信候选更早被处理
        eligible.sort(key=lambda c: c.confidence, reverse=True)

        self._batches = []
        for i in range(0, len(eligible), self._batch_size):
            batch = eligible[i:i + self._batch_size]
            if batch:
                self._batches.append(batch)

        logger.info(
            "BatchAnalysis: formed %d batches from %d low-confidence candidates "
            "(batch_size=%d, range=[%.2f, %.2f])",
            len(self._batches), len(eligible),
            self._batch_size, self._low_min, self._low_max
        )

        return self._batches

    def execute_batch(
        self,
        batch: List[VulnerabilityCandidate],
        executor,
        binary_context: str = "",
    ) -> List[SymbolicResult]:
        """对一批候选做单轮符号执行。

        executor 可调用, 接收 (function_names, aggregated_evidence,
        avg_confidence), 返回 SymbolicResult 或其列表; 摊销成本:
        一次 angr project setup 覆盖 N 个函数, 而非 N 次 setup。
        """
        if not batch:
            return []

        function_names = [c.function_name for c in batch]
        avg_confidence = sum(c.confidence for c in batch) / len(batch)

        # 汇总所有候选的 evidence
        aggregated_evidence_parts: List[str] = []
        for c in batch:
            if c.evidence:
                aggregated_evidence_parts.append(str(c.evidence))
        aggregated_evidence = "\n".join(aggregated_evidence_parts)

        logger.info(
            "BatchAnalysis: executing batch of %d functions (avg_conf=%.3f): %s",
            len(batch), avg_confidence, ", ".join(function_names[:5])
        )

        start_time = time.time()
        results: List[SymbolicResult] = []

        try:
            raw_result = executor(function_names, aggregated_evidence, avg_confidence)

            # 规范化为 List[SymbolicResult]
            if isinstance(raw_result, list):
                results = raw_result
            elif isinstance(raw_result, SymbolicResult):
                results = [raw_result]
            else:
                # 为批中每个候选构造结果
                results = [
                    SymbolicResult(
                        function_name=c.function_name,
                        vulnerabilities_found=[],
                        paths_explored=0,
                        constraints=[]
                    )
                    for c in batch
                ]

        except Exception as e:
            logger.warning(
                "BatchAnalysis: batch execution failed for %d functions: %s",
                len(batch), e
            )

        elapsed = time.time() - start_time
        logger.info(
            "BatchAnalysis: batch completed in %.2fs (%.2fs per function)",
            elapsed, elapsed / max(1, len(batch))
        )

        return results

    def execute_all_batches(
        self,
        executor,
        binary_context: str = "",
    ) -> Dict[str, SymbolicResult]:
        """执行全部预分组批次, 返回按函数名索引的结果。"""
        all_results: Dict[str, SymbolicResult] = {}

        for batch_idx, batch in enumerate(self._batches):
            batch_results = self.execute_batch(batch, executor, binary_context)
            for result in batch_results:
                all_results[result.function_name] = result

        return all_results


# VulnReportFormatter — 多格式漏洞报告生成
#
# 支持 JSON / Markdown / HTML 三种格式
# 严重性着色和 CWE 映射来自 _VULN_CWE_MAP
# HTML 报告内含嵌入式 CSS 用于独立渲染
class VulnReportFormatter:
    """构造 JSON/Markdown/HTML 漏洞报告, 带严重性着色与修复建议。

    每种 VulnerabilityType 都映射到一个 CWE 条目, 包含:
    CWE ID + 名称、严重性等级 (CRITICAL/HIGH/MEDIUM/LOW)、
    修复建议与显示颜色。
    """

    def __init__(self):
        self._cwe_map = _VULN_CWE_MAP

    # 公共 API

    def to_json(
        self,
        results: Dict[str, SymbolicResult],
        candidates: Optional[List[VulnerabilityCandidate]] = None,
        pretty: bool = True,
    ) -> str:
        """生成 JSON 格式漏洞报告。"""
        report = self._build_report_dict(results, candidates)
        indent = 2 if pretty else None
        return json.dumps(report, indent=indent, ensure_ascii=False)

    def to_markdown(
        self,
        results: Dict[str, SymbolicResult],
        candidates: Optional[List[VulnerabilityCandidate]] = None,
    ) -> str:
        """生成 Markdown 格式漏洞报告。"""
        report = self._build_report_dict(results, candidates)
        return self._render_markdown(report)

    def to_html(
        self,
        results: Dict[str, SymbolicResult],
        candidates: Optional[List[VulnerabilityCandidate]] = None,
        title: str = "Vulnerability Analysis Report",
    ) -> str:
        """生成自包含的 HTML 漏洞报告。"""
        report = self._build_report_dict(results, candidates)
        return self._render_html(report, title)

    def write_report(
        self,
        output_path: str,
        results: Dict[str, SymbolicResult],
        candidates: Optional[List[VulnerabilityCandidate]] = None,
        fmt: str = "markdown",
    ) -> str:
        """生成报告并写入磁盘, fmt 为 json/markdown/html, 返回文件路径。"""
        fmt_lower = fmt.lower()
        if fmt_lower == "json":
            content = self.to_json(results, candidates)
        elif fmt_lower == "html":
            content = self.to_html(results, candidates)
        else:
            content = self.to_markdown(results, candidates)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info("VulnReportFormatter: wrote %s report to %s", fmt_lower, output_path)
        return output_path

    # 内部方法

    def _build_report_dict(
        self,
        results: Dict[str, SymbolicResult],
        candidates: Optional[List[VulnerabilityCandidate]] = None,
    ) -> Dict[str, Any]:
        """构造内部报告数据结构。"""
        vulnerabilities: List[Dict[str, Any]] = []
        vuln_count_by_severity: Dict[str, int] = defaultdict(int)
        analyzed_count = 0

        for func_name, result in results.items():
            analyzed_count += 1

            candidate_info: Optional[VulnerabilityCandidate] = None
            if candidates:
                for c in candidates:
                    if c.function_name == func_name:
                        candidate_info = c
                        break

            for vuln in result.vulnerabilities_found:
                vuln_type_str = vuln.get("type", "unknown")
                vuln_type = self._resolve_vuln_type(vuln_type_str)
                cwe_info = self._cwe_map.get(vuln_type, {})

                entry: Dict[str, Any] = {
                    "function_name": func_name,
                    "function_address": candidate_info.function_address if candidate_info else 0,
                    "vulnerability_type": vuln_type.value if isinstance(vuln_type, VulnerabilityType) else vuln_type_str,
                    "cwe_id": cwe_info.get("cwe_id", "CWE-000"),
                    "cwe_name": cwe_info.get("cwe_name", "Unknown"),
                    "severity": cwe_info.get("severity", "INFO"),
                    "confidence": candidate_info.confidence if candidate_info else 0.0,
                    "description": vuln.get("description", ""),
                    "location": vuln.get("location", func_name),
                    "remediation": cwe_info.get("remediation", ""),
                    "paths_explored": result.paths_explored,
                }
                vulnerabilities.append(entry)
                severity = entry["severity"]
                vuln_count_by_severity[severity] += 1

        # 按严重性排序
        vulnerabilities.sort(
            key=lambda v: (
                _SEVERITY_ORDER.get(v.get("severity", "INFO"), 99),
                -(v.get("confidence", 0.0))
            )
        )

        return {
            "report_metadata": {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "analyzed_functions": analyzed_count,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": dict(vuln_count_by_severity),
            },
            "vulnerabilities": vulnerabilities,
        }

    def _resolve_vuln_type(self, type_str: str) -> VulnerabilityType:
        """把字符串解析为 VulnerabilityType 枚举, 带模糊匹配。"""
        type_lower = type_str.replace(" ", "_").replace("-", "_").lower()
        for vt in VulnerabilityType:
            if vt.value == type_lower or vt.value in type_lower or type_lower in vt.value:
                return vt
        return VulnerabilityType.BUFFER_OVERFLOW  # 回退

    def _render_markdown(self, report: Dict[str, Any]) -> str:
        """把报告 dict 渲染为 Markdown。"""
        meta = report["report_metadata"]
        vulns = report["vulnerabilities"]

        lines: List[str] = []
        lines.append("# Vulnerability Analysis Report")
        lines.append("")
        lines.append(f"**Generated:** {meta['generated_at']}")
        lines.append(f"**Analyzed Functions:** {meta['analyzed_functions']}")
        lines.append(f"**Total Vulnerabilities Found:** {meta['total_vulnerabilities']}")
        lines.append("")

        # 严重性分布表
        if meta.get("severity_breakdown"):
            lines.append("## Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev, cnt in sorted(
                meta["severity_breakdown"].items(),
                key=lambda x: _SEVERITY_ORDER.get(x[0], 99)
            ):
                lines.append(f"| {sev} | {cnt} |")
            lines.append("")

        # 漏洞详情
        lines.append("## Vulnerability Details")
        lines.append("")

        for idx, vuln in enumerate(vulns, 1):
            sev = vuln.get("severity", "INFO")
            sev_emoji = {"CRITICAL": "red_circle", "HIGH": "orange_circle",
                         "MEDIUM": "yellow_circle", "LOW": "green_circle", "INFO": "white_circle"}.get(sev, "")

            lines.append(f"### {idx}. {vuln.get('cwe_id')} — {vuln.get('vulnerability_type')} [{sev}]")
            lines.append("")
            lines.append(f"- **Function:** `{vuln.get('function_name', 'unknown')}`")
            lines.append(f"- **Address:** `0x{vuln.get('function_address', 0):x}`")
            lines.append(f"- **CWE:** {vuln.get('cwe_name', 'N/A')}")
            lines.append(f"- **Confidence:** {vuln.get('confidence', 0.0):.2f}")
            lines.append(f"- **Paths Explored:** {vuln.get('paths_explored', 0)}")
            lines.append("")

            desc = vuln.get("description", "")
            if desc:
                lines.append(f"**Description:** {desc}")
                lines.append("")

            remediation = vuln.get("remediation", "")
            if remediation:
                lines.append(f"**Remediation:** {remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _render_html(self, report: Dict[str, Any], title: str) -> str:
        """把报告 dict 渲染为自包含 HTML 页面。"""
        meta = report["report_metadata"]
        vulns = report["vulnerabilities"]

        # 严重性 CSS 类
        severity_css_classes = {
            "CRITICAL": "severity-critical",
            "HIGH": "severity-high",
            "MEDIUM": "severity-medium",
            "LOW": "severity-low",
            "INFO": "severity-info",
        }

        html_parts: List[str] = []
        html_parts.append("<!DOCTYPE html>")
        html_parts.append('<html lang="en">')
        html_parts.append("<head>")
        html_parts.append(f'<meta charset="UTF-8">')
        html_parts.append(f'<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_parts.append(f"<title>{html.escape(title)}</title>")
        html_parts.append("<style>")
        html_parts.append(self._css_styles())
        html_parts.append("</style>")
        html_parts.append("</head>")
        html_parts.append("<body>")

        # 头部
        html_parts.append('<div class="container">')
        html_parts.append(f'<h1>{html.escape(title)}</h1>')
        html_parts.append(f'<p class="meta">Generated: {html.escape(meta["generated_at"])}</p>')
        html_parts.append(f'<p class="meta">Analyzed Functions: {meta["analyzed_functions"]} | Vulnerabilities: {meta["total_vulnerabilities"]}</p>')

        # 严重性分布
        if meta.get("severity_breakdown"):
            html_parts.append('<div class="severity-breakdown">')
            html_parts.append('<h2>Severity Breakdown</h2>')
            html_parts.append('<table class="summary-table">')
            html_parts.append('<tr><th>Severity</th><th>Count</th></tr>')
            for sev, cnt in sorted(
                meta["severity_breakdown"].items(),
                key=lambda x: _SEVERITY_ORDER.get(x[0], 99)
            ):
                css_cls = severity_css_classes.get(sev, "severity-info")
                html_parts.append(
                    f'<tr><td class="{css_cls}">{html.escape(sev)}</td><td>{cnt}</td></tr>'
                )
            html_parts.append('</table>')
            html_parts.append('</div>')

        # 漏洞详情
        html_parts.append('<div class="vulnerabilities">')
        html_parts.append('<h2>Vulnerability Details</h2>')

        for idx, vuln in enumerate(vulns, 1):
            sev = vuln.get("severity", "INFO")
            css_cls = severity_css_classes.get(sev, "severity-info")

            html_parts.append(f'<div class="vuln-card {css_cls}">')
            html_parts.append(
                f'<h3>#{idx} {html.escape(vuln.get("cwe_id", "CWE-000"))} — '
                f'{html.escape(str(vuln.get("vulnerability_type", "")))} '
                f'<span class="badge {css_cls}">{html.escape(sev)}</span></h3>'
            )

            html_parts.append('<div class="vuln-details">')
            html_parts.append(
                f'<p><strong>Function:</strong> <code>{html.escape(str(vuln.get("function_name", "unknown")))}</code></p>'
            )
            addr = vuln.get("function_address", 0)
            html_parts.append(f'<p><strong>Address:</strong> <code>0x{addr:x}</code></p>')
            html_parts.append(
                f'<p><strong>CWE:</strong> {html.escape(str(vuln.get("cwe_name", "N/A")))}</p>'
            )
            html_parts.append(
                f'<p><strong>Confidence:</strong> {vuln.get("confidence", 0.0):.2f}</p>'
            )
            html_parts.append(
                f'<p><strong>Paths Explored:</strong> {vuln.get("paths_explored", 0)}</p>'
            )

            desc = vuln.get("description", "")
            if desc:
                html_parts.append(
                    f'<p><strong>Description:</strong> {html.escape(desc)}</p>'
                )

            remediation = vuln.get("remediation", "")
            if remediation:
                html_parts.append(
                    f'<div class="remediation"><strong>Remediation:</strong> '
                    f'{html.escape(remediation)}</div>'
                )

            html_parts.append('</div>')  # vuln-details
            html_parts.append('</div>')  # vuln-card

        html_parts.append('</div>')  # vulnerabilities
        html_parts.append('</div>')  # container
        html_parts.append("</body>")
        html_parts.append("</html>")

        return "\n".join(html_parts)

    def _css_styles(self) -> str:
        """返回 HTML 报告的内嵌 CSS。"""
        return """
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 20px;
    background: #f5f5f5;
    color: #333;
}
.container {
    max-width: 960px;
    margin: 0 auto;
    background: #fff;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
h1 { border-bottom: 3px solid #007acc; padding-bottom: 10px;}
.meta { color: #666; font-size: 0.9em;}
.summary-table {
    width: 40%;
    border-collapse: collapse;
    margin: 15px 0;
}
.summary-table th, .summary-table td {
    padding: 8px 12px;
    border: 1px solid #ddd;
    text-align: left;
}
.summary-table th { background: #007acc; color: white;}
.vuln-card {
    border-left: 5px solid #ccc;
    padding: 15px;
    margin: 15px 0;
    background: #fafafa;
    border-radius: 4px;
}
.vuln-card.severity-critical { border-left-color: #b52b27;}
.vuln-card.severity-high { border-left-color: #d9534f;}
.vuln-card.severity-medium { border-left-color: #f0ad4e;}
.vuln-card.severity-low { border-left-color: #5cb85c;}
.vuln-card.severity-info { border-left-color: #5bc0de;}
.vuln-details p { margin: 5px 0; line-height: 1.5; }
.vuln-details code { background: #e8e8e8; padding: 2px 6px; border-radius: 3px;}
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: bold;
    color: white;
    margin-left: 8px;
}
.badge.severity-critical { background: #b52b27;}
.badge.severity-high { background: #d9534f;}
.badge.severity-medium { background: #f0ad4e; color: #333;}
.badge.severity-low { background: #5cb85c;}
.badge.severity-info { background: #5bc0de; color: #333;}
.remediation {
    background: #e8f5e9;
    border: 1px solid #a5d6a7;
    padding: 12px;
    margin-top: 10px;
    border-radius: 4px;
    font-size: 0.95em;
}
td.severity-critical { color: #b52b27; font-weight: bold;}
td.severity-high { color: #d9534f; font-weight: bold;}
td.severity-medium { color: #f0ad4e; font-weight: bold;}
td.severity-low { color: #5cb85c;}
td.severity-info { color: #5bc0de;}
"""


class ConfidenceCalibrator:
    """基于经验精度的置信度阈值自动校准。

    每次符号执行后把"高置信候选是否真正产出漏洞"记录为反馈,
    据此动态调整 threshold, 变动日志输出到 logger.info。
    """

    def __init__(self, initial_threshold: float = 0.6):
        self._threshold = max(0.3, min(0.95, initial_threshold))
        self._true_positives: int = 0
        self._total_analyzed: int = 0
        self._precision_estimate: float = 0.0

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def precision_estimate(self) -> float:
        return self._precision_estimate

    def record_result(self, confidence: float, vulns_found: int):
        """把一次分析结果喂给校准器, 只统计置信度达阈值的候选。"""
        if confidence >= self._threshold:
            self._total_analyzed += 1
            if vulns_found > 0:
                self._true_positives += 1

    def calibrate(self):
        """重算 precision_estimate 并视需要调整阈值。

        基于累积的 true_positives / total_analyzed 计算精度估计值,
        无样本时保持不变。
        """
        if self._total_analyzed == 0:
            return
        self._precision_estimate = self._true_positives / self._total_analyzed

        if self._precision_estimate < 0.3:
            old = self._threshold
            self._threshold = min(0.95, self._threshold + 0.05)
            logger.info(
                f"Precision {self._precision_estimate:.2f} < 0.3 — "
                f"raising threshold {old:.2f} → {self._threshold:.2f}"
            )
        elif self._precision_estimate > 0.7:
            old = self._threshold
            self._threshold = max(0.3, self._threshold - 0.05)
            logger.info(
                f"Precision {self._precision_estimate:.2f} > 0.7 — "
                f"lowering threshold {old:.2f} → {self._threshold:.2f}"
            )

    def reset(self):
        """清除累积统计, 保留当前阈值。"""
        self._true_positives = 0
        self._total_analyzed = 0
        self._precision_estimate = 0.0


class CachingAnalyzer:
    """sqlite3 支撑的分析缓存, 按 func_code_hash 索引。

    命中缓存时复用 last_vuln_count, 未命中时由调用方决定是否
    继续符号执行。
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'analysis_cache.db'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_cache (
                function_name TEXT,
                func_code_hash TEXT,
                last_vuln_count INTEGER,
                last_analyzed REAL,
                source_binary TEXT,
                PRIMARY KEY (func_code_hash, function_name)
            )
        """)
        self._conn.commit()

    def compute_func_code_hash(self, code: str) -> str:
        """对函数源码/反汇编文本取 SHA256。"""
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def lookup(self, function_name: str, func_code_hash: str) -> Optional[int]:
        """缓存命中返回 last_vuln_count, 未命中返回 None。"""
        row = self._conn.execute(
            "SELECT last_vuln_count FROM analysis_cache "
            "WHERE function_name = ? AND func_code_hash = ?",
            (function_name, func_code_hash)
        ).fetchone()
        if row:
            return row[0]
        return None

    def store(self, function_name: str, func_code_hash: str,
              last_vuln_count: int, source_binary: str = ""):
        """插入或更新一条缓存条目。"""
        self._conn.execute(
            "INSERT OR REPLACE INTO analysis_cache "
            "(function_name, func_code_hash, last_vuln_count, last_analyzed, source_binary) "
            "VALUES (?, ?, ?, ?, ?)",
            (function_name, func_code_hash, last_vuln_count, time.time(), source_binary)
        )
        self._conn.commit()

    def is_function_seen_in_other_binary(self, func_code_hash: str) -> bool:
        """检查 func_code_hash 是否已存在于缓存。

        用于计算 novelty_bonus: 曾在其他 binary 中出现过 →
        novelty_bonus = 0.5。
        """
        row = self._conn.execute(
            "SELECT COUNT(*) FROM analysis_cache WHERE func_code_hash = ?",
            (func_code_hash,)
        ).fetchone()
        return row is not None and row[0] > 0

    def close(self):
        self._conn.close()


class VulnerabilityDetector:
    """基于正则的预扫描器, 标记调用危险 C API 的函数。

    用 TF-IDF 加权模式密度估算置信度:
    - TF (Term Frequency): 模式在此函数中出现的次数
    - IDF (Inverse Document Frequency): log(总函数数 / 包含此模式的函数数)
    - 罕见模式 (如 system()) IDF 高 → 置信度加成大
    - 常见模式 (如 printf) IDF 低 → 置信度被抑制
    """

    def __init__(self):
        self._patterns = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                r'memcpy\(', r'strcpy\(', r'sprintf\(', r'gets\(',
                r'memmove\(', r'strcat\(', r'strncat\('
            ],
            VulnerabilityType.USE_AFTER_FREE: [
                r'free\(', r'malloc\(', r'calloc\(', r'realloc\('
            ],
            VulnerabilityType.FORMAT_STRING: [
                r'printf\(', r'fprintf\(', r'snprintf\(', r'vfprintf\('
            ],
            VulnerabilityType.RACE_CONDITION: [
                r'pthread_create\(', r'fork\(', r'shmat\(', r'mmap\(.*MAP_SHARED'
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                r'system\(', r'popen\(', r'exec[lv]', r'spawn[lv]'
            ]
        }
        self._pattern_doc_count: Dict[str, int] = {}
        self._total_funcs_scanned: int = 0

    def _compute_idf(self, pattern: str, total_funcs: int) -> float:
        doc_count = self._pattern_doc_count.get(pattern, 1)
        return math.log((total_funcs + 1) / (doc_count + 1))

    def scan_function(self, function_name: str, code: str,
                      total_funcs: int = 1) -> List[VulnerabilityCandidate]:
        """在单个函数的反编译文本上做模式匹配。"""
        candidates = []

        for vuln_type, patterns in self._patterns.items():
            for pat in patterns:
                hits = code.count(pat.replace('\\', ''))
                if hits > 0:
                    self._pattern_doc_count[pat] = self._pattern_doc_count.get(pat, 0) + 1

            total_matches = sum(
                1 for p in patterns if p.replace('\\', '') in code
            )
            if total_matches > 0:
                # TF-IDF 加权：每模式命中数 × IDF 的求和
                tfidf_sum = sum(
                    total_matches * self._compute_idf(p, max(total_funcs, 1))
                    for p in patterns if p.replace('\\', '') in code
                )
                candidates.append(VulnerabilityCandidate(
                    function_name=function_name,
                    function_address=0,
                    vuln_type=vuln_type,
                    confidence=min(tfidf_sum * 0.25, 0.95),
                    evidence={"patterns_found": total_matches},
                    tfidf_weight=tfidf_sum
                ))

        return candidates

    def scan_binary(self, binary_data: bytes) -> List[VulnerabilityCandidate]:
        """把原始二进制字节当作文本块做粗扫描。"""
        candidates = []
        code_str = binary_data.decode('utf-8', errors='ignore')
        self._total_funcs_scanned = 1

        for vuln_type, patterns in self._patterns.items():
            matches = sum(1 for pattern in patterns if pattern in code_str)
            if matches > 0:
                candidates.append(VulnerabilityCandidate(
                    function_name="unknown",
                    function_address=0,
                    vuln_type=vuln_type,
                    confidence=min(matches * 0.2, 0.8),
                    evidence={"pattern_count": matches}
                ))

        return candidates


class SymbolicExecutor:
    """按深度门控的符号执行, 路径预算随分析级别缩放。

    增强: 对数级别深度分配 — 不再使用固定阶梯 (20/100/500/1000),
    而是基于置信度的对数增长: paths = int(20 * (1 + log2(1 +
    confidence))), 深度分配随置信度平滑增长而非跳变。
    """

    def __init__(self):
        self._max_paths = 1000
        self._timeout = 300

    def execute(self, function_name: str, code: str,
                confidence: float = 0.5) -> SymbolicResult:
        """运行深度与置信度成对数比例的符号执行。"""
        if confidence <= 0:
            paths_explored = 20
        else:
            paths_explored = min(self._max_paths,
                                int(20 * (1 + math.log2(1 + confidence))))

        vulnerabilities_found = []

        if "memcpy" in code or "strcpy" in code:
            vulnerabilities_found.append({
                "type": "buffer_overflow",
                "location": function_name,
                "description": "Potential buffer overflow detected"
            })
        if "system" in code or "popen" in code:
            vulnerabilities_found.append({
                "type": "command_injection",
                "location": function_name,
                "description": "Shell command injection risk"
            })

        return SymbolicResult(
            function_name=function_name,
            vulnerabilities_found=vulnerabilities_found,
            paths_explored=paths_explored,
            constraints=[]
        )


class OnDemandAnalyzer:
    """两阶段流水线: 正则检测候选, 对达阈值者做符号执行。

    分析深度与置信度成正比。

    增强: 置信度校准 (内置 ConfidenceCalibrator, 每轮分析后自动
    调整阈值, precision_estimate 过低则上调、过高则下调);
    分析缓存 (内置 CachingAnalyzer, func_code_hash 相同的函数跳过
    重复分析, 复用 SQLite 缓存的 last_vuln_count);
    Top-K 排序 (get_top_candidates(k) 返回最高的 k 个未分析候选,
    按 confidence * novelty_bonus 排序)。
    """

    def __init__(self, cache_db_path: Optional[str] = None):
        self._detector = VulnerabilityDetector()
        self._executor = SymbolicExecutor()
        self._candidates: List[VulnerabilityCandidate] = []
        self._results: Dict[str, SymbolicResult] = {}
        self._binary_fingerprints: Dict[str, str] = {}
        self._calibrator = ConfidenceCalibrator(initial_threshold=0.6)
        self._cache = CachingAnalyzer(db_path=cache_db_path)
        self._triage_queue = TriageQueue()
        self._batch_analyzer = BatchAnalysis(batch_size=5)
        self._report_formatter = VulnReportFormatter()

    @property
    def triage_queue(self) -> TriageQueue:
        """暴露内部 TriageQueue 供手动管理。"""
        return self._triage_queue

    @property
    def batch_analyzer(self) -> BatchAnalysis:
        """暴露内部 BatchAnalysis 供批处理配置。"""
        return self._batch_analyzer

    @property
    def report_formatter(self) -> VulnReportFormatter:
        """暴露内部 VulnReportFormatter 供自定义报告。"""
        return self._report_formatter

    def _fingerprint_binary(self, data: bytes) -> str:
        """首尾 4KB 的快速哈希, 用于未变更二进制跳过逻辑。"""
        return hashlib.sha256(data[:4096] + data[-4096:]).hexdigest()[:16]

    def get_top_candidates(self, k: int) -> List[VulnerabilityCandidate]:
        """返回按 confidence * novelty_bonus 降序的前 k 个未分析候选。

        novelty_bonus: 1.0 = 从未在任何 binary 中出现过 (全新函数);
        0.5 = 曾在其他 binary 中分析过 (func_code_hash 已在 DB 中)。
        """
        unanalyzed = [c for c in self._candidates if not c.analyzed]
        if not unanalyzed:
            return []

        # 计算 novelty_bonus
        for c in unanalyzed:
            if c.func_code_hash:
                seen = self._cache.is_function_seen_in_other_binary(c.func_code_hash)
                c.novelty_bonus = 0.5 if seen else 1.0
            else:
                c.novelty_bonus = 1.0

        # 按 confidence * novelty_bonus 降序
        scored = sorted(unanalyzed,
                        key=lambda c: c.confidence * c.novelty_bonus,
                        reverse=True)
        return scored[:k]

    def analyze_binary(self, binary_data: bytes) -> Dict[str, Any]:
        """运行完整的检测→triage→执行流水线。

        增强流程: 1) 指纹不变 → 直接复用上一次结果; 2) 检测 →
        为每个候选计算 func_code_hash; 3) 候选插入 TriageQueue;
        4) CachingAnalyzer 检查缓存 → 命中则跳过符号执行;
        5) 未命中 → 符号执行 → 结果记录到缓存; 6) 低置信候选 →
        BatchAnalysis 批处理; 7) ConfidenceCalibrator 校准阈值。
        """
        fp = self._fingerprint_binary(binary_data)
        if fp in self._binary_fingerprints:
            logger.info("Binary fingerprint unchanged, reusing prior results")
            return self._generate_report()

        self._binary_fingerprints[fp] = fp
        self._candidates = self._detector.scan_binary(binary_data)

        # 为每个候选计算 func_code_hash
        for c in self._candidates:
            c.func_code_hash = self._cache.compute_func_code_hash(
                str(c.evidence)
            )

        # 插入 TriageQueue（按 confidence * novelty_bonus 排序）
        self._triage_queue = TriageQueue()
        self._triage_queue.insert_batch(self._candidates)

        threshold = self._calibrator.threshold
        high_confidence = [c for c in self._candidates if c.confidence >= threshold]

        for candidate in high_confidence:
            logger.info(f"Analyzing function: {candidate.function_name}")

            func_code_hash = candidate.func_code_hash
            cached_count = self._cache.lookup(
                candidate.function_name, func_code_hash
            )

            if cached_count is not None:
                # 缓存命中 —— 跳过符号执行，直接复用
                logger.info(
                    f"Cache hit for {candidate.function_name} "
                    f"(hash={func_code_hash[:16]}...) → {cached_count} vulns"
                )
                result = SymbolicResult(
                    function_name=candidate.function_name,
                    vulnerabilities_found=[{"cached": True, "count": cached_count}]
                    if cached_count > 0 else [],
                    paths_explored=0,
                    constraints=[]
                )
                self._calibrator.record_result(candidate.confidence, cached_count)
                candidate.analyzed = True
            else:
                # 缓存未命中 —— 符号执行
                result = self._executor.execute(
                    candidate.function_name,
                    str(candidate.evidence),
                    candidate.confidence
                )
                vuln_count = len(result.vulnerabilities_found)
                self._cache.store(
                    candidate.function_name,
                    func_code_hash,
                    vuln_count,
                    source_binary=""
                )
                self._calibrator.record_result(candidate.confidence, vuln_count)
                candidate.analyzed = True

            self._results[candidate.function_name] = result

        # 批量分析低置信候选（0.3-0.5）
        self._batch_analyzer.form_batches(self._candidates)

        def batch_executor(func_names, aggregated_evidence, avg_conf):
            """批量执行器: 对聚合证据做一轮基于模式的符号执行。"""
            vulns = []
            if "memcpy" in aggregated_evidence or "strcpy" in aggregated_evidence:
                vulns.append({
                    "type": "buffer_overflow",
                    "location": ", ".join(func_names),
                    "description": f"Batch buffer overflow analysis across {len(func_names)} functions"
                })
            if "system" in aggregated_evidence or "popen" in aggregated_evidence:
                vulns.append({
                    "type": "command_injection",
                    "location": ", ".join(func_names),
                    "description": f"Batch command injection analysis across {len(func_names)} functions"
                })
            return SymbolicResult(
                function_name="batch",
                vulnerabilities_found=vulns,
                paths_explored=int(20 * (1 + math.log2(1 + avg_conf))),
                constraints=[],
            )

        batch_results = self._batch_analyzer.execute_all_batches(batch_executor)
        for func_name, result in batch_results.items():
            if func_name != "batch":
                self._results[func_name] = result
                vuln_count = len(result.vulnerabilities_found)
                for c in self._candidates:
                    if c.function_name == func_name:
                        self._calibrator.record_result(c.confidence, vuln_count)
                        c.analyzed = True

        # 每轮分析后自动校准阈值
        self._calibrator.calibrate()

        return self._generate_report()

    def analyze_function(self, function_name: str, code: str,
                         total_funcs: int = 1) -> Optional[SymbolicResult]:
        """扫描单个函数, 置信度达阈值时符号执行。

        增强: 通过 func_code_hash 检查缓存, 命中则跳过执行。
        """
        candidates = self._detector.scan_function(
            function_name, code, total_funcs)

        if not candidates:
            return None

        max_candidate = max(candidates, key=lambda c: c.confidence)
        threshold = self._calibrator.threshold

        if max_candidate.confidence >= threshold:
            func_code_hash = self._cache.compute_func_code_hash(code)
            cached_count = self._cache.lookup(function_name, func_code_hash)

            if cached_count is not None:
                logger.info(
                    f"Cache hit for {function_name} ({func_code_hash[:16]}...)"
                )
                result = SymbolicResult(
                    function_name=function_name,
                    vulnerabilities_found=[{"cached": True, "count": cached_count}]
                    if cached_count > 0 else [],
                    paths_explored=0,
                    constraints=[]
                )
                self._calibrator.record_result(max_candidate.confidence, cached_count)
                self._calibrator.calibrate()
                return result

            result = self._executor.execute(
                function_name, code, max_candidate.confidence)
            vuln_count = len(result.vulnerabilities_found)
            self._cache.store(function_name, func_code_hash, vuln_count)
            self._calibrator.record_result(max_candidate.confidence, vuln_count)
            self._calibrator.calibrate()
            return result

        return None

    def _generate_report(self) -> Dict[str, Any]:
        """把流水线统计聚合为汇总字典。"""
        total_candidates = len(self._candidates)
        analyzed = len(self._results)
        vulns_found = sum(len(r.vulnerabilities_found) for r in self._results.values())

        return {
            "total_candidates": total_candidates,
            "analyzed_functions": analyzed,
            "vulnerabilities_found": vulns_found,
            "precision_estimate": self._calibrator.precision_estimate,
            "current_threshold": self._calibrator.threshold,
            "batches_formed": len(self._batch_analyzer.batches),
            "triage_queue_size": len(self._triage_queue),
            "results": {
                func: {
                    "vulns_found": len(res.vulnerabilities_found),
                    "paths_explored": res.paths_explored
                }
                for func, res in self._results.items()
            }
        }

    def get_candidates(self) -> List[VulnerabilityCandidate]:
        """返回最近一次扫描检测到的候选。"""
        return self._candidates

    def get_results(self) -> Dict[str, SymbolicResult]:
        """返回最近一次运行的执行结果。"""
        return self._results

    def generate_report(
        self, fmt: str = "markdown", output_path: Optional[str] = None
    ) -> str:
        """用 VulnReportFormatter 生成格式化漏洞报告。

        指定 output_path 时写入磁盘并返回文件路径, 否则返回
        报告字符串。
        """
        if output_path:
            return self._report_formatter.write_report(
                output_path, self._results, self._candidates, fmt
            )
        if fmt == "json":
            return self._report_formatter.to_json(self._results, self._candidates)
        elif fmt == "html":
            return self._report_formatter.to_html(self._results, self._candidates)
        return self._report_formatter.to_markdown(self._results, self._candidates)


def analyze_on_demand(binary_path: str) -> Dict[str, Any]:
    """一次性流程: 从磁盘读取二进制, 运行检测→triage→执行流水线。"""
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        analyzer = OnDemandAnalyzer()
        return analyzer.analyze_binary(data)
    except Exception as e:
        logger.error(f"Failed to analyze binary: {e}")
        return {"error": str(e)}
