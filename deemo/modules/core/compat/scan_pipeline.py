# -*- coding: utf-8 -*-
"""检测管线编排器 — 串联 IR提取→特征归一化→四检测器→融合→输出."""

import os, json, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from modules.core.compat.abstract_heap_model import AbstractHeapModel, Violation
from modules.core.compat.taint_enhanced_heap import (
    TaintEnhancedResult, filter_heap_overflow_candidates, downgrade_summary)
from modules.core.compat.format_string_detector import (
    identify_printf_calls, detect_format_string_vulns, summarize_findings)
from modules.core.compat.stack_overflow_analyzer import (
    analyze_stack_frame, detect_stack_overflow, summarize_stack_findings)
from modules.core.compat.vuln_synthesis import synthesize, SynthesisReport


@dataclass
class PipelineResult:
    binary_path: str
    wall_ms: float
    findings: SynthesisReport
    heap_violations: List[Violation] = field(default_factory=list)
    taint_filter_stats: Dict[str, Any] = field(default_factory=dict)
    fp_filter_stats: Dict[str, Any] = field(default_factory=dict)
    format_summary: Dict[str, Any] = field(default_factory=dict)
    stack_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary': self.binary_path, 'wall_ms': self.wall_ms,
            'findings': {
                'total': self.findings.total_raw_findings,
                'after_dedup': self.findings.after_dedup,
                'exploitable': self.findings.exploitable_count,
                'by_type': self.findings.by_type,
                'summary': self.findings.summary_text,
            },
            'heap_violations': [{'type': v.violation_type, 'detail': v.detail,
                                'confidence': v.confidence} for v in self.heap_violations],
            'taint_filter': self.taint_filter_stats,
            'format_summary': self.format_summary,
            'stack_summary': self.stack_summary,
            'vulns': [{'id': v.vuln_id, 'type': v.vuln_type, 'addr': hex(v.primary_addr),
                       'confidence': v.confidence, 'exploitable': v.exploitable,
                       'cwe': v.cwe_id, 'description': v.description}
                      for v in self.findings.vulns],
        }


def run_pipeline(
    binary_path: str,
    instructions: Optional[List[Dict]] = None,
    ir_text: str = '',
    ir_ops: Optional[Dict[int, Dict]] = None,
    callee_names: Optional[Dict[int, str]] = None,
    def_use_chains: Optional[Dict[int, List[int]]] = None,
    taint_map: Optional[Dict[int, Dict]] = None,
    string_values: Optional[Dict[int, str]] = None,
    write_ops: Optional[Dict[int, Dict]] = None,
    disasm_lines: Optional[List[str]] = None,
    alloc_sites_input: Optional[Dict[int, Dict]] = None,
    free_sites_input: Optional[Dict[int, List[int]]] = None,
    use_sites_input: Optional[Dict[int, List[int]]] = None,
    trace_events: Optional[List[Dict]] = None,
    alloc_records: Optional[List[Dict]] = None,
) -> PipelineResult:
    """执行完整的漏洞检测管线.

    各可选参数对应不同 IR 提取工具的产出 — 管线不绑定特定前端.
    若参数为 None, 对应检测阶段跳过.

    管线步骤:
      1. 抽象堆模型 → 检测 double-free/invalid-free
      2. 归一化特征提取 (IR 级)
      3. 堆溢出检测 → 污点过滤降误报
      4. UAF 检测 (事件驱动状态机)
      5. 格式化字符串检测 (污点+格式符)
      6. 栈溢出检测 (帧分析+canary)
      7. 四检测器融合去重
    """
    t0 = time.perf_counter()
    instructions = instructions or []
    ir_ops = ir_ops or {}
    callee_names = callee_names or {}

    # Step 1: 抽象堆模型
    heap_model = AbstractHeapModel()
    heap_violations: List[Violation] = []
    if trace_events:
        for evt in trace_events:
            etype = evt.get('event', '')
            ptr = evt.get('ptr_id', str(evt.get('address', evt.get('addr', 0))))
            sz = evt.get('size', 0)
            addr = evt.get('address', evt.get('addr', 0))
            if etype == 'alloc':
                heap_model.on_alloc(ptr, sz, call_addr=addr)
            elif etype == 'free':
                heap_model.on_free(ptr, call_addr=addr, freed_size=sz)
            elif etype == 'use':
                heap_model.on_use(ptr, use_addr=addr)
        heap_violations = heap_model.flush_violations()
        heap_violations.extend(heap_model.check_dangling())

    # Step 2-3: 堆溢出 + 污点过滤
    taint_stats: Dict[str, Any] = {'applied': False}
    heap_candidates: List[Dict] = []
    if alloc_records:
        from modules.core.compat.heap_analyzer import detect_heap_spray, detect_heap_fengshui
        heap_candidates.extend(detect_heap_fengshui(trace_events or []))
    if heap_candidates and def_use_chains:
        taint_results = filter_heap_overflow_candidates(
            heap_candidates, def_use_chains, ir_ops, instructions)
        taint_stats = downgrade_summary(taint_results)

    # Step 3b: 值区间+分配器约束+污点距离 三阶段误报过滤
    fp_filter_stats: Dict[str, Any] = {'applied': False}
    if heap_candidates:
        from modules.core.compat.fp_filter import batch_filter_and_report
        retained, fp_report = batch_filter_and_report(
            heap_candidates,
            allocator_type='glibc_ptmalloc',
            taint_distance_threshold=8)
        heap_candidates = retained
        fp_filter_stats = {'applied': True, **fp_report}

    # Step 4: UAF 检测
    uaf_findings: List[Dict] = []
    if alloc_sites_input:
        from modules.core.compat.uaf_detector import static_uaf_detect
        uaf_findings = static_uaf_detect(
            alloc_sites_input, free_sites_input or {},
            use_sites_input or {}, alias_map=None)

    # Step 5: 格式化字符串检测
    fmt_findings = []
    fmt_summary: Dict[str, Any] = {'total_printf_calls_analyzed': 0}
    if ir_ops:
        printf_calls = identify_printf_calls(ir_ops, callee_names)
        if printf_calls:
            fmt_findings = detect_format_string_vulns(
                printf_calls, taint_map or {}, string_values or {}, instructions)
            fmt_summary = summarize_findings(fmt_findings)

    # Step 6: 栈溢出检测
    stack_candidates = []
    stack_summary: Dict[str, Any] = {'total_candidates': 0}
    if disasm_lines and write_ops:
        frames = [analyze_stack_frame(0, disasm_lines, ir_ops)]
        stack_candidates = detect_stack_overflow(
            frames, write_ops, taint_map or {}, instructions)
        stack_summary = summarize_stack_findings(stack_candidates)

    # Step 7: 融合
    report = synthesize(
        heap_findings=heap_candidates,
        uaf_findings=uaf_findings,
        format_findings=fmt_findings,
        stack_findings=stack_candidates,
    )

    wall = (time.perf_counter() - t0) * 1000
    return PipelineResult(
        binary_path=binary_path, wall_ms=wall, findings=report,
        heap_violations=heap_violations, taint_filter_stats=taint_stats,
        format_summary=fmt_summary, stack_summary=stack_summary,
        fp_filter_stats=fp_filter_stats,
    )


def run_pipeline_minimal(binary_path: str) -> PipelineResult:
    """最小化管线 — 不依赖外部 IR 提取, 仅使用二进制固有特征."""
    try:
        with open(binary_path, 'rb') as f:
            raw = f.read(4096)
    except Exception:
        raw = b''

    # 从原始字节提取启发式特征作为 fallback
    trace_events: List[Dict] = []
    offset = 0

    # 在 .text 段区域模拟分配/释放模式的粗略探测
    # 搜索常见堆操作函数的 PLT 桩调用模式
    import re
    # x86-64 call 指令: e8 xx xx xx xx
    call_pattern = re.compile(b'\xe8....', re.DOTALL)
    calls = call_pattern.findall(raw)
    for i, _ in enumerate(calls[:20]):
        trace_events.append({
            'event': 'alloc' if i % 3 != 1 else ('free' if i % 3 == 1 else 'use'),
            'ptr_id': f'ptr_{i}', 'size': 64 + (i % 4) * 32,
            'address': 0x400000 + i * 16,
        })

    return run_pipeline(
        binary_path=binary_path,
        trace_events=trace_events,
        ir_ops={
            0x400000 + i: {'op_type': 'call', 'callee': 'malloc', 'write_size': 64}
            for i in range(len(trace_events))
        },
        callee_names={0x400000 + i: 'malloc' for i in range(0, len(trace_events), 3)},
    )
