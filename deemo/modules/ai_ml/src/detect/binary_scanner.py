# 端到端二进制扫描器——反汇编→检测管线→结构化报告
# 输入: ELF二进制路径, 输出: 完整的漏洞检测报告(含新旧管线对比)
#
# 流程: binary → objdump → FunctionInfo列表 → DetectionPipeline × 每个函数
#       → CombinedReport列表 → BinaryScanReport
#
# 性能考虑:
# objdump开销: 通常<100ms(小型二进制), <2s(大型)
# 检测管线: 每函数<10ms(大多数函数<100条指令)
# 总耗时: 典型<500ms for 20 functions

from __future__ import annotations

import sys
import json
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path

# 路径设置
_AI_ML_ROOT = Path(__file__).parent.parent.parent
if str(_AI_ML_ROOT) not in sys.path:
    sys.path.insert(0, str(_AI_ML_ROOT))

from src.disasm.objdump_parser import ObjdumpParser, FunctionInfo
from src.detect.pipeline_bridge import (
    DetectionPipeline, CombinedReport, CombinedVerdict)
from src.detect.analysis.cross_function_tracker import (
    CrossFunctionTracker, CrossFunctionMap)
from src.detect.analysis.cross_function_heap_tracker import (
    CrossFunctionHeapTracker)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class BinaryScanReport:
    """单个二进制文件的完整扫描报告"""
    binary_path: str
    scan_time_ms: float
    total_functions: int
    scanned_functions: int
    total_sinks: int
    # 检测统计
    confirmed: int = 0        # 双管线确认真漏洞
    likely: int = 0           # 单管线确认
    uncertain: int = 0        # 无法确定
    filtered: int = 0         # 确认为误报
    uaf_confirmed: int = 0    # UAF三阶段管线确认
    uaf_likely: int = 0       # UAF两阶段通过
    uaf_cross_func: int = 0   # UAF跨函数检测
    heap_cross_func: int = 0  # 堆跨函数alloc-copy配对检测
    fmt_confirmed: int = 0    # 格式串三阶段管线确认
    fmt_likely: int = 0       # 格式串两阶段通过
    new_findings: int = 0     # 旧管线漏检, 新管线发现
    # 详细结果
    findings: List[Dict] = field(default_factory=list)
    # 元信息
    error: str = ""
    disasm_available: bool = True


class BinaryScanner:
    """端到端二进制扫描器。

    使用方式:
        scanner = BinaryScanner()
        report = scanner.scan_binary("/path/to/binary")
        print(f"Found {report.confirmed} confirmed vulns, "
              f"{report.filtered} false positives filtered")
    """

    def __init__(self, objdump_path: str = 'objdump'):
        self._parser = ObjdumpParser(objdump_path=objdump_path)
        self._pipeline = DetectionPipeline()

    def _resolve_path(self, binary_path: str) -> str:
        """解析二进制路径——处理Windows .exe后缀"""
        import os as _os
        p = str(Path(binary_path).resolve())
        if not _os.path.exists(p) and _os.name == 'nt':
            if _os.path.exists(p + '.exe'):
                return p + '.exe'
        return p

    def scan_binary(self, binary_path: str) -> BinaryScanReport:
        """扫描单个二进制文件——完整管线"""
        t0 = time.perf_counter()
        resolved = self._resolve_path(binary_path)

        if not Path(resolved).exists():
            return BinaryScanReport(
                binary_path=binary_path, scan_time_ms=0,
                total_functions=0, scanned_functions=0, total_sinks=0,
                error=f"file not found: {binary_path}",
                disasm_available=False)

        # 阶段0: 反汇编
        try:
            funcs = self._parser.parse_binary(resolved)
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return BinaryScanReport(
                binary_path=binary_path, scan_time_ms=elapsed,
                total_functions=0, scanned_functions=0, total_sinks=0,
                error=f"disasm failed: {e}", disasm_available=False)

        if not funcs:
            elapsed = (time.perf_counter() - t0) * 1000
            return BinaryScanReport(
                binary_path=binary_path, scan_time_ms=elapsed,
                total_functions=0, scanned_functions=0, total_sinks=0,
                error="no functions extracted", disasm_available=False)

        # 阶段1+2: 对每个函数运行双管线
        all_results = []
        for func in funcs:
            if not func.instructions:
                continue
            try:
                crs = self._pipeline.scan_function(
                    func.instructions, func.bb_boundaries,
                    func.cfg_edges, func.name)
                all_results.extend(crs)
            except Exception as e:
                logger.debug("scan %s failed: %s", func.name, e)
                continue

        # 阶段2.5: 跨函数全局UAF检测
        try:
            tracker = CrossFunctionTracker()
            cross_map = tracker.build_map(funcs)
            cross_results = self._pipeline.scan_cross_function(cross_map)
            all_results.extend(cross_results)
        except Exception as e:
            logger.debug("cross-function scan failed: %s", e)

        # 阶段2.6: 跨函数堆alloc-copy配对检测
        try:
            heap_cross_results = self._pipeline.scan_cross_function_heap(funcs)
            all_results.extend(heap_cross_results)
        except Exception as e:
            logger.debug("cross-function heap scan failed: %s", e)

        # 统计
        stats = self._pipeline.get_statistics(
            [cr for cr in all_results
             if cr.combined_verdict != CombinedVerdict.FILTERED
             or cr.old_verdict.value != 'filtered'])

        confirmed = sum(1 for cr in all_results
                       if cr.combined_verdict == CombinedVerdict.CONFIRMED)
        likely = sum(1 for cr in all_results
                    if cr.combined_verdict == CombinedVerdict.LIKELY)
        uncertain = sum(1 for cr in all_results
                       if cr.combined_verdict == CombinedVerdict.UNCERTAIN)
        filtered = sum(1 for cr in all_results
                      if cr.combined_verdict == CombinedVerdict.FILTERED)
        new_findings = sum(1 for cr in all_results
                          if cr.combined_verdict == CombinedVerdict.NEW_FINDING)
        uaf_confirmed = sum(1 for cr in all_results
                           if cr.combined_verdict == CombinedVerdict.UAF_CONFIRMED)
        uaf_likely = sum(1 for cr in all_results
                        if cr.combined_verdict == CombinedVerdict.UAF_LIKELY)
        uaf_cross_func = sum(1 for cr in all_results
                            if cr.combined_verdict == CombinedVerdict.UAF_CROSS_FUNC)
        heap_cross_func = sum(1 for cr in all_results
                              if cr.combined_verdict == CombinedVerdict.HEAP_CROSS_FUNC)

        fmt_confirmed = sum(1 for cr in all_results
                           if cr.combined_verdict == CombinedVerdict.FMT_CONFIRMED)
        fmt_likely = sum(1 for cr in all_results
                        if cr.combined_verdict == CombinedVerdict.FMT_LIKELY)

        # 构建详细发现列表
        findings = []
        for cr in all_results:
            findings.append({
                'func_name': cr.func_name,
                'sink': cr.sink_func,
                'sink_idx': cr.sink_instr_idx,
                'old_verdict': cr.old_verdict.value,
                'new_decision': cr.new_decision.value,
                'combined': cr.combined_verdict.value,
                'confidence': cr.confidence,
                'reason': cr.reason,
            })

        elapsed = (time.perf_counter() - t0) * 1000

        return BinaryScanReport(
            binary_path=binary_path,
            scan_time_ms=round(elapsed, 1),
            total_functions=len(funcs),
            scanned_functions=len([f for f in funcs if f.instructions]),
            total_sinks=len(all_results),
            confirmed=confirmed,
            likely=likely,
            uncertain=uncertain,
            filtered=filtered,
            uaf_confirmed=uaf_confirmed,
            uaf_likely=uaf_likely,
            uaf_cross_func=uaf_cross_func,
            heap_cross_func=heap_cross_func,
            fmt_confirmed=fmt_confirmed,
            fmt_likely=fmt_likely,
            new_findings=new_findings,
            findings=findings,
            disasm_available=True)

    def scan_batch(self,
                   binary_paths: List[str]
                   ) -> List[BinaryScanReport]:
        """批量扫描多个二进制文件"""
        return [self.scan_binary(p) for p in binary_paths]

    def scan_to_json(self, binary_path: str) -> str:
        """扫描并返回JSON格式报告"""
        report = self.scan_binary(binary_path)
        return json.dumps(asdict(report), indent=2, default=str)


def scan_binary_quick(binary_path: str) -> Dict:
    """便捷函数——扫描二进制并返回字典格式报告"""
    scanner = BinaryScanner()
    report = scanner.scan_binary(binary_path)
    return {
        'binary': binary_path,
        'is_vulnerable': (report.confirmed > 0 or report.likely > 0
                          or report.uaf_confirmed > 0 or report.uaf_likely > 0
                          or report.uaf_cross_func > 0
                          or report.heap_cross_func > 0
                          or report.fmt_confirmed > 0 or report.fmt_likely > 0),
        'vuln_type': _infer_vuln_type(report),
        'confidence': _compute_confidence(report),
        'confirmed': report.confirmed,
        'likely': report.likely,
        'uaf_confirmed': report.uaf_confirmed,
        'uaf_likely': report.uaf_likely,
        'fmt_confirmed': report.fmt_confirmed,
        'fmt_likely': report.fmt_likely,
        'filtered': report.filtered,
        'time_ms': report.scan_time_ms,
        'error': report.error,
    }


def _infer_vuln_type(report: BinaryScanReport) -> str:
    """从报告推断漏洞类型——优先级: 堆溢出>UAF>格式串"""
    if report.confirmed > 0 or report.likely > 0 or report.heap_cross_func > 0:
        return 'buffer_overflow'
    if report.uaf_confirmed > 0 or report.uaf_likely > 0 or report.uaf_cross_func > 0:
        return 'use_after_free'
    if report.fmt_confirmed > 0 or report.fmt_likely > 0:
        return 'format_string'
    sinks = set(f.get('sink', '') for f in report.findings)
    if any('memcpy' in s or 'strcpy' in s or 'memmove' in s
           for s in sinks):
        return 'buffer_overflow'
    if any('free' in s for s in sinks):
        return 'use_after_free'
    if any('printf' in s or 'sprintf' in s or 'fprintf' in s
           for s in sinks):
        return 'format_string'
    return 'unknown'


def _compute_confidence(report: BinaryScanReport) -> float:
    """计算整体检测置信度——含UAF+UAF跨函数+格式串管线"""
    heap_confirmed = report.confirmed + report.likely + report.uncertain + report.filtered + report.heap_cross_func
    uaf_confirmed = report.uaf_confirmed + report.uaf_likely + report.uaf_cross_func
    fmt_confirmed = report.fmt_confirmed + report.fmt_likely
    total = heap_confirmed + uaf_confirmed + fmt_confirmed
    if total == 0:
        return 0.0
    weighted = (report.confirmed * 0.9 + report.likely * 0.6
                + report.uncertain * 0.3
                + report.uaf_confirmed * 0.85 + report.uaf_likely * 0.55
                + report.uaf_cross_func * 0.7
                + report.heap_cross_func * 0.55
                + report.fmt_confirmed * 0.85 + report.fmt_likely * 0.55)
    relevant = (report.confirmed + report.likely + report.uncertain
                + report.uaf_confirmed + report.uaf_likely + report.uaf_cross_func
                + report.heap_cross_func
                + report.fmt_confirmed + report.fmt_likely)
    return weighted / max(1, relevant)
