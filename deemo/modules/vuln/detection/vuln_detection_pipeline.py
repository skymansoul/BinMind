# coding: utf-8
#
"""
统一检测管线: 串联堆生命周期分析, 三检测器, 约束过滤, 聚合输出。

管线流程:
  1. HeapLifecycleAnalyzer, 提取alloc_size_map + 时序UAF候选
  2. detect_heap_overflow(alloc_size_map), 堆溢出候选
  3. detect_uaf(temporal_filter=时序UAF), UAF候选
  4. SimplifiedTaintTracker, 污点分析, 格式化字符串候选
  5. ConstraintFilter, 滤除不可行路径
  6. 聚合为统一VulnReport

输出: VulnReport, 按置信度降序, 含漏洞类型/位置/证据/置信度。
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

_log = logging.getLogger(__name__)


@dataclass
class VulnCandidate:
    """统一漏洞候选: 三检测器的公共输出格式。"""
    vuln_type: str            # heap_overflow / uaf / format_string
    function_name: str = ""
    address: int = 0
    confidence: float = 0.0   # [0, 1]
    evidence: List[str] = field(default_factory=list)
    filtered_by_constraint: bool = False


@dataclass
class VulnReport:
    """统一漏洞报告: 聚合三检测器输出。"""
    binary_name: str = ""
    total_functions: int = 0
    candidates: List[VulnCandidate] = field(default_factory=list)
    # 统计
    heap_overflow_count: int = 0
    uaf_count: int = 0
    format_string_count: int = 0
    filtered_count: int = 0     # 被约束过滤器滤除的候选数
    # 性能
    total_elapsed_ms: float = 0.0


class VulnDetectionPipeline:
    """统一检测管线: 编排三个核心检测器+生命周期+约束过滤。"""

    def run(self, function_instructions: Dict[str, List[str]],
             binary_name: str = "",
             enable_constraint_filter: bool = True
             ) -> VulnReport:
        """对二进制所有函数执行联合检测。"""
        import time
        t0 = time.time()
        report = VulnReport(
            binary_name=binary_name,
            total_functions=len(function_instructions))

        all_candidates = []
        total_filtered = 0

        for func_name, insns in function_instructions.items():
            if not insns:
                continue

            # 生命周期分析
            try:
                from .heap_lifecycle import HeapLifecycleAnalyzer
                lifecycle = HeapLifecycleAnalyzer().analyze(
                    insns, func_name)
                alloc_sizes = lifecycle.alloc_sizes
            except ImportError:
                alloc_sizes = {}

            # 堆溢出检测（提取alloc+write size参数）
            try:
                from .heap_overflow_detector import detect_heap_overflow
                consts = {}
                if alloc_sizes:
                    consts['rdi'] = max(alloc_sizes.values())
                # 补充扫描insns中的mov立即数作为写大小参数
                import re
                _REG32_TO_64 = {'edi':'rdi','esi':'rsi','edx':'rdx','ecx':'rcx',
                                'eax':'rax','ebx':'rbx','r8d':'r8','r9d':'r9'}
                for insn in insns:
                    l = insn.lower().strip()
                    if ':' in l[:20]: l = l.split(':',1)[1].strip()
                    m = re.match(r'mov\s+(r?[a-z]+\d*),\s*(\d+)', l)
                    if m:
                        reg = m.group(1)
                        reg64 = _REG32_TO_64.get(reg, reg)
                        consts[reg64] = int(m.group(2))
                ho_findings = detect_heap_overflow(insns, consts)
                for f in ho_findings:
                    conf = 0.85 if f.confidence == 'confirmed' else 0.5
                    all_candidates.append(VulnCandidate(
                        vuln_type='heap_overflow',
                        function_name=func_name,
                        confidence=conf,
                        evidence=[str(f)]))
            except ImportError:
                pass

            # UAF检测（注入时序过滤）
            try:
                from .uaf_detector import detect_uaf
                uaf_findings = detect_uaf(insns)
                temporal_uaf = lifecycle.temporal_uaf if hasattr(
                    lifecycle, 'temporal_uaf') else []
                uaf_pairs = {(f_idx, d_idx) for f_idx, d_idx, _ in
                              temporal_uaf}
                for f in uaf_findings:
                    # 时序过滤：仅保留在temporal_uaf中的
                    key = (f.free_insn_idx, f.use_insn_idx)
                    if temporal_uaf and key not in uaf_pairs:
                        continue
                    conf = 0.8 if f.confidence == 'confirmed' else 0.5
                    all_candidates.append(VulnCandidate(
                        vuln_type='uaf',
                        function_name=func_name,
                        confidence=conf,
                        evidence=[str(f)]))
            except ImportError:
                pass

            # 格式化字符串检测 + FP过滤
            try:
                from .path_taint_simplified import SimplifiedTaintTracker
                taint = SimplifiedTaintTracker().track(insns, func_name)
                from .format_string_detector import FormatStringDetector
                fmt_candidates = FormatStringDetector().detect(insns, func_name)
                from .fmt_fp_filter import FormatStringFpFilter
                fmt_filter = FormatStringFpFilter()
                # 将候选转为过滤器可消费的格式
                class FmtWrap:
                    def __init__(s, fc, ci):
                        s.call_idx = ci; s.call_address = fc.call.address
                        s.is_vulnerable = fc.is_vulnerable; s.confidence = fc.confidence
                        s.fmt_arg = fc.call.format_arg
                fmt_wrapped = []
                for fc in fmt_candidates:
                    ci = self._find_call_idx(insns, fc.call.address, 0x400000)
                    fmt_wrapped.append(FmtWrap(fc, ci))
                filtered = fmt_filter.filter(insns, fmt_wrapped)
                confirmed_set = set(filtered.confirmed)
                for fc in fmt_candidates:
                    ci = self._find_call_idx(insns, fc.call.address, 0x400000)
                    if ci not in confirmed_set: continue
                    taint_confirmed = any(
                        idx == ci and is_t for idx, _, is_t in taint.format_calls)
                    conf = fc.confidence
                    if taint_confirmed: conf = min(1.0, conf + 0.2)
                    all_candidates.append(VulnCandidate(
                        vuln_type='format_string', function_name=func_name,
                        confidence=conf, evidence=fc.evidence))
            except ImportError:
                pass

            # 约束过滤
            if enable_constraint_filter and all_candidates:
                try:
                    from .constraint_filter import ConstraintFilter
                    before = len(all_candidates)
                    func_candidates = [{'type': c.vuln_type,
                                         'function': c.function_name,
                                         'address': c.address}
                                        for c in all_candidates]
                    filtered = ConstraintFilter().filter(
                        func_candidates, insns)
                    after = len(filtered)
                    total_filtered += (before - after)
                    # 移除被滤除的候选
                    kept_types = {f['type'] for f in filtered}
                    all_candidates = [c for c in all_candidates
                                       if c.vuln_type in kept_types]
                except ImportError:
                    pass

        report.candidates = sorted(
            all_candidates, key=lambda c: c.confidence, reverse=True)
        report.heap_overflow_count = sum(
            1 for c in report.candidates if c.vuln_type == 'heap_overflow')
        report.uaf_count = sum(
            1 for c in report.candidates if c.vuln_type == 'uaf')
        report.format_string_count = sum(
            1 for c in report.candidates if c.vuln_type == 'format_string')
        report.filtered_count = total_filtered
        report.total_elapsed_ms = round(
            (time.time() - t0) * 1000, 1)

        return report

    @staticmethod
    def _find_call_idx(insns: List[str], addr: int, base: int) -> int:
        for i, insn in enumerate(insns):
            s = insn.strip()
            if ':' in s[:20]:
                try:
                    if int(s.split(':')[0], 16) == addr: return i
                except ValueError:
                    pass
        return -1


def run_full_detection(functions: Dict[str, List[str]],
                        binary_name: str = ""
                        ) -> VulnReport:
    """便捷入口: 一键运行全部检测器。"""
    return VulnDetectionPipeline().run(functions, binary_name)


__all__ = ["VulnCandidate", "VulnReport",
           "VulnDetectionPipeline", "run_full_detection"]
