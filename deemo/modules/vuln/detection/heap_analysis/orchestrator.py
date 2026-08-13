"""
堆分析编排器 — size_tracker + constraint_simplifier + fp_filter 的统一入口。

核心管线:
  capstone反汇编 → size_tracker追踪malloc→write数据流
  → constraint_simplifier推导区间约束 → fp_filter筛除可证明安全的
  → 输出带置信度标签的发现列表

这是整个"堆溢出误报削减"创新的顶层接口。

修改记录:
  创建 2025-06-09
"""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)


@dataclass
class HeapReport:
    binary_path: str
    raw_findings: int
    filtered_fp: int
    confirmed: int
    likely: int
    fp_reduction_pct: float
    findings: List[Dict[str, Any]] = field(default_factory=list)
    disasm_error: str = ""


def _disasm(path: str, max_bytes: int = 0x10000) -> Optional[List[str]]:
    try:
        import capstone
        with open(path, "rb") as f:
            code = f.read()[:max_bytes]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return [f"{i.mnemonic} {i.op_str}" for i in md.disasm(code, 0x1000)]
    except Exception as e:
        _log.debug("disasm failed: %s", e)
        return None


def analyze_heap(binary_path: str) -> HeapReport:
    """
    对二进制做堆溢出检测 + 数据流驱动的误报过滤。

    返回 HeapReport: 含 raw/confirmed/likely/filtered 计数和详细发现列表。
    """
    insns = _disasm(binary_path)
    if not insns:
        return HeapReport(
            binary_path=binary_path, raw_findings=0, filtered_fp=0,
            confirmed=0, likely=0, fp_reduction_pct=0.0,
            disasm_error="capstone disassembly failed")

    from modules.vuln.detection.heap_analysis.size_tracker import track_allocation_to_write
    from modules.vuln.detection.heap_analysis.fp_filter import FilterResult

    traces = track_allocation_to_write(insns)
    result = FilterResult(total_raw=len(traces))

    for t in traces:
        if t.can_prove_safe:
            result.filtered.append(t)
        else:
            result.kept.append(t)

    if result.total_raw > 0:
        result.fp_reduction_pct = round(
            len(result.filtered) / result.total_raw * 100, 1)

    confirmed = [t for t in result.kept if t.confidence == 'confirmed']
    likely = [t for t in result.kept if t.confidence != 'confirmed']

    findings_out = []
    for t in result.kept:
        findings_out.append({
            'confidence': t.confidence,
            'alloc_func': t.alloc.alloc_func,
            'alloc_size': t.alloc.size_value,
            'alloc_size_src': t.alloc.size_source,
            'write_func': t.write.write_func,
            'write_len': t.write.len_value,
            'constraint_evidence': t.constraint_evidence,
        })

    return HeapReport(
        binary_path=binary_path,
        raw_findings=result.total_raw,
        filtered_fp=len(result.filtered),
        confirmed=len(confirmed),
        likely=len(likely),
        fp_reduction_pct=result.fp_reduction_pct,
        findings=findings_out,
    )
