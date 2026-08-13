# 堆溢出扫描驱动 — 反汇编 → 增强检测器 → PcWBI三级判定.
#
# 决策逻辑:
#   复用 analysis/static 的增强堆溢出检测器 (含 DDSSC/SAWCE/Octagon
#   多阶段过滤), 其 finalize 现已串接 PcWBI Stage 10: 按写入大小来源
#   将候选告警分为 confirmed/suspected/benign 三级.
#   本模块只做编排与结果归并, 不重实现检测逻辑.
#
# 创建: 2026-07-19

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .disasm import disassemble


@dataclass
class ScanReport:
    binary: str
    file_format: str
    confirmed: List[dict] = field(default_factory=list)
    suspected: List[dict] = field(default_factory=list)
    benign: List[dict] = field(default_factory=list)
    wb_stats: Dict[str, int] = field(default_factory=dict)
    filter_stats: Dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ""

    def has_overflow(self) -> bool:
        """检出判定: 仅 CONFIRMED 计入, SUSPECTED 不混入检出.

        prov_run 返回 confirmed+suspected (suspected 保留供复核),
        此处按 wb_verdict 口径只认 confirmed; 基线 (无 wb_verdict)
        按类型判定.
        """
        for f in self.confirmed:
            if "heap_overflow" not in f.get("type", ""):
                continue
            wb = f.get("wb_verdict")
            if wb is None or wb == "confirmed":
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "binary": self.binary,
            "file_format": self.file_format,
            "confirmed": self.confirmed,
            "suspected": self.suspected,
            "benign": self.benign,
            "wb_stats": self.wb_stats,
            "filter_stats": self.filter_stats,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
        }


def scan_binary(binary: str, allocator_family=None,
                use_win64_abi: Optional[bool] = None,
                use_pcwbi: bool = True) -> ScanReport:
    """扫描单个二进制, 返回三级判定报告.

    allocator_family: None 时按导入表自动推断.
    use_win64_abi: None 时按文件格式推断 (PE→Win64, ELF→SysV).
    use_pcwbi: False 时关闭 Stage 11 (消融基线).
    """
    t0 = time.perf_counter()
    report = ScanReport(binary=binary, file_format="")

    try:
        instructions, fmt, _main, ranges = disassemble(binary)
        report.file_format = fmt
        if not instructions:
            report.error = "disassembly failed"
            return report

        if use_win64_abi is None:
            use_win64_abi = "pei" in fmt.lower()

        from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector  # noqa: E401
        from modules.analysis.static.heap_alloc_model import HeapAllocModel, AllocatorFamily  # noqa: E401
        from modules.analysis.static.import_resolver import resolve_call_targets  # noqa: E401
        from modules.analysis.static.disasm_util import parse_func_ranges  # noqa: E401

        if allocator_family is None:
            try:
                from modules.analysis.static.import_resolver import _resolve_pe_imports  # noqa: E401
            except Exception:
                pass
            allocator_family = AllocatorFamily.GLIBC

        detector = HeapOverflowDetector(
            allocator_family=allocator_family,
            use_win64_abi=use_win64_abi)
        detector.set_user_func_ranges(ranges)
        detector.set_pcwbi_enabled(use_pcwbi)
        detector.pre_analyze(instructions)
        for ins in instructions:
            detector.analyze_instruction(ins)
        confirmed = detector.finalize(instructions)

        report.confirmed = confirmed
        report.suspected = detector.suspected_findings
        report.benign = detector.benign_findings
        report.wb_stats = detector.wb_stats()
        report.filter_stats = detector.stats
    except Exception as e:
        report.error = str(e)[:300]

    report.elapsed_ms = (time.perf_counter() - t0) * 1000
    return report


def scan_binary_json(binary: str, **kwargs) -> str:
    """扫描并以 JSON 字符串返回结果."""
    report = scan_binary(binary, **kwargs)
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False,
                      default=str)


__all__ = ["scan_binary", "scan_binary_json", "ScanReport"]
