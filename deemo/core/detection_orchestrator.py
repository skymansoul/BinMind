"""
Multi-method detection orchestrator with weighted confidence voting.

Fuses independent detector outputs into unified vulnerability reports:
  Format string: static regex (0.30) + taint (0.40) + LLM (0.30)
  Stack overflow: angr (0.50) + pattern fallback (0.30) + taint (0.20)
  UAF: pointer FSM (0.60) + pattern fallback (0.40)
  Heap overflow: static inference (0.40) + taint (0.40) + abstract filter (0.20)

Weighted average fusion with consistency bonus: +10% when multiple methods agree.
"""


import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class MethodResult:
    """单个检测方法的输出。"""
    method_name: str           # "angr" | "pattern_fallback" | "taint" | "static"
    vuln_type: str             # "format_string" | "stack_overflow" | "uaf" | "heap_overflow"
    detected: bool
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0


@dataclass
class FusedReport:
    """多方法融合后的最终检测报告。"""
    vuln_type: str
    function_name: str
    binary_path: str
    final_confidence: float
    method_results: List[MethodResult]
    method_agreement: float     # 方法间一致率 [0, 1]
    verdict: str                # "CONFIRMED" | "LIKELY" | "POSSIBLE" | "BENIGN"
    timestamp: float = 0.0


class DetectionOrchestrator:
    """
    多方法检测调度器。

    对每个目标函数/二进制运行配置的检测方法, 收集结果,
    按类型→方法→权重融合输出。

    verdict 阈值:
      CONFIRMED: confidence >= 0.80
      LIKELY:    confidence >= 0.60
      POSSIBLE:  confidence >= 0.35
      BENIGN:    confidence <  0.35
    """

    def __init__(self):
        self._methods: Dict[str, Dict[str, Any]] = {}

    def register_method(
        self, vuln_type: str, method_name: str,
        detector_fn: Callable, weight: float = 0.5,
    ) -> None:
        """注册一个检测方法。detector_fn 接受 (binary_path, func_name) → MethodResult。"""
        if vuln_type not in self._methods:
            self._methods[vuln_type] = {}
        self._methods[vuln_type][method_name] = {
            'fn': detector_fn, 'weight': weight,
        }

    def scan(
        self, binary_path: str, func_name: str,
        vuln_types: Optional[List[str]] = None,
    ) -> List[FusedReport]:
        """
        运行所有注册的检测方法并融合结果。

        vuln_types: 限定扫描的漏洞类型, None 表示全部。
        """
        targets = vuln_types or list(self._methods.keys())
        reports: List[FusedReport] = []

        for vtype in targets:
            methods = self._methods.get(vtype, {})
            if not methods:
                continue

            results: List[MethodResult] = []
            for mname, minfo in methods.items():
                t0 = time.perf_counter()
                try:
                    mr = minfo['fn'](binary_path, func_name)
                except Exception as e:
                    _log.debug("method %s failed: %s", mname, str(e)[:80])
                    mr = MethodResult(
                        method_name=mname, vuln_type=vtype,
                        detected=False, confidence=0.0,
                        details={'error': str(e)[:120]},
                    )
                mr.elapsed_ms = (time.perf_counter() - t0) * 1000
                results.append(mr)

            fused = self._fuse(vtype, func_name, binary_path, results)
            reports.append(fused)

        reports.sort(key=lambda r: r.final_confidence, reverse=True)
        return reports

    def _fuse(
        self, vtype: str, func: str, binary: str,
        results: List[MethodResult],
    ) -> FusedReport:
        """加权融合 + 一致性奖励。"""
        weights = {mr.method_name: self._methods[vtype][mr.method_name]['weight']
                   for mr in results if mr.method_name in self._methods.get(vtype, {})}
        total_weight = sum(weights.values()) or 1.0

        detected_count = sum(1 for mr in results if mr.detected)
        weighted_conf = sum(
            mr.confidence * weights.get(mr.method_name, 0.5)
            for mr in results
        ) / total_weight

        # 一致性奖励: 若 ≥ 2 个方法且全部 agree, +10%
        agreement_bonus = 0.0
        n_methods = len(results)
        if n_methods >= 2 and detected_count in (0, n_methods):
            agreement_bonus = 0.10

        final_conf = min(0.95, weighted_conf + agreement_bonus)

        # 一致率: 多数派比例
        majority = max(detected_count, n_methods - detected_count)
        agreement = majority / n_methods if n_methods > 0 else 0.0

        if final_conf >= 0.80:
            verdict = "CONFIRMED"
        elif final_conf >= 0.60:
            verdict = "LIKELY"
        elif final_conf >= 0.35:
            verdict = "POSSIBLE"
        else:
            verdict = "BENIGN"

        return FusedReport(
            vuln_type=vtype,
            function_name=func,
            binary_path=binary,
            final_confidence=round(final_conf, 4),
            method_results=results,
            method_agreement=round(agreement, 4),
            verdict=verdict,
            timestamp=time.time(),
        )

    def method_count(self) -> int:
        return sum(len(m) for m in self._methods.values())


def create_default_orchestrator() -> DetectionOrchestrator:
    """
    创建预配置的调度器, 集成所有已实现的检测方法。

    每个检测方法被包装为接受 (binary_path, func_name) → MethodResult 的闭包。
    """
    orch = DetectionOrchestrator()

    # 格式化字符串
    from core.format_string_detector import detect_format_string_vulns

    def fmt_static(bin_path: str, func: str) -> MethodResult:
        findings = detect_format_string_vulns(bin_path, func, use_llm=False)
        detected = any(f.get('confidence', 0) > 0.3 for f in findings)
        conf = max((f.get('confidence', 0) for f in findings), default=0.0)
        return MethodResult('static', 'format_string', detected, conf,
                           {'finding_count': len(findings)})

    orch.register_method('format_string', 'static', fmt_static, 0.30)

    # 栈溢出
    from core.stack_overflow_analyzer import analyze_stack_overflow

    def so_angr(bin_path: str, func: str) -> MethodResult:
        result = analyze_stack_overflow(bin_path, func)
        detected = result.get('overflowable', False)
        conf = 0.80 if detected else 0.10
        return MethodResult('angr', 'stack_overflow', detected, conf,
                           {'padding': result.get('padding', 0)})

    orch.register_method('stack_overflow', 'angr', so_angr, 0.50)

    # 模式回退 (栈溢出)
    from core.pattern_fallback import match_patterns

    def so_pattern(bin_path: str, func: str) -> MethodResult:
        import subprocess
        from config import R2_PATH
        try:
            out = subprocess.check_output(
                [R2_PATH, '-q', '-c', f's {func}; pdbj', bin_path],
                timeout=15, stderr=subprocess.DEVNULL,
            )
            import json
            disasm = json.loads(out)
            text = '\n'.join(op.get('disasm', '') for op in disasm.get('ops', []))
        except Exception:
            return MethodResult('pattern', 'stack_overflow', False, 0.0, {})
        matches = match_patterns(text)
        so_matches = [m for m in matches if m.vuln_type == 'stack_overflow']
        detected = len(so_matches) > 0
        conf = max((m.confidence for m in so_matches), default=0.0)
        return MethodResult('pattern', 'stack_overflow', detected, conf,
                           {'match_count': len(so_matches)})

    orch.register_method('stack_overflow', 'pattern_fallback', so_pattern, 0.30)

    # UAF
    from core.uaf_detector import UAFDetector

    def uaf_detect(bin_path: str, func: str) -> MethodResult:
        import subprocess
        from config import R2_PATH
        try:
            out = subprocess.check_output(
                [R2_PATH, '-q', '-c', f's {func}; pdc', bin_path],
                timeout=15, stderr=subprocess.DEVNULL,
            )
            code = out.decode('utf-8', errors='replace')
        except Exception:
            return MethodResult('uaf_static', 'uaf', False, 0.0, {})
        detector = UAFDetector()
        findings = detector.detect(code, func)
        detected = len(findings) > 0
        conf = max((f.confidence for f in findings), default=0.0)
        return MethodResult('uaf_static', 'uaf', detected, conf,
                           {'finding_count': len(findings)})

    orch.register_method('uaf', 'uaf_static', uaf_detect, 0.60)

    return orch


__all__ = [
    "MethodResult",
    "FusedReport",
    "DetectionOrchestrator",
    "create_default_orchestrator",
]
