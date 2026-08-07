# 四级增强管线与现有检测器的集成适配层
# 不改动enhanced_scanner.py——通过包装器模式叠加增强过滤
#
# 集成策略:
#   EnhancedScanner(旧) → 高召回低精度 → 输出候选告警
#   EnhancedHeapFilter(新) → 四级验证 → 过滤误报
#   最终输出 = 旧检测器告警 ∩ 增强过滤器确认
#
# 决策: 用组合而非继承，旧模块零改动

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from .enhanced_heap_filter import (
    EnhancedHeapFilter, EnhancedVerdict, EnhancedHeapReport,
    AllocatorKind)
from .constraint_based_pairing import AllocCopyPair

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class IntegratedReport:
    """集成后的最终报告——融合旧检测器分数和增强验证结果"""
    func_name: str
    vuln_type: str
    original_score: float
    enhanced_score: float
    verdict: EnhancedVerdict
    is_confirmed: bool
    heap_report: Optional[EnhancedHeapReport] = None
    evidence: List[str] = field(default_factory=list)


class PipelineIntegrator:
    """将EnhancedHeapFilter集成到现有检测管线。

    使用方式:
      integrator = PipelineIntegrator()
      results = integrator.integrate(
          instructions, bb_boundaries, cfg_edges,
          func_name, original_alerts)
      # results中的confirmed项即低误报检出
    """

    def __init__(self,
                 allocator_kind: AllocatorKind = AllocatorKind.GLIBC_PTMALLOC2):
        self._heap_filter = EnhancedHeapFilter(allocator_kind=allocator_kind)

    def integrate(self,
                  instructions: List[str],
                  bb_boundaries: List[Tuple[int, int]],
                  cfg_edges: List[Tuple[int, int]],
                  func_name: str = "",
                  original_alerts: Optional[List[Dict[str, Any]]] = None
                  ) -> List[IntegratedReport]:
        """整合旧检测器告警与增强过滤器结果。

        对每个旧检测器报告的buffer_overflow告警，
        运行四级增强验证——只有通过验证的才保留高置信度。
        """
        if original_alerts is None:
            original_alerts = []

        # 运行增强堆溢出分析
        heap_reports = self._heap_filter.analyze_function(
            instructions, bb_boundaries, cfg_edges, func_name)

        # 构建copy_idx→heap_report的查找表
        heap_by_idx: Dict[int, EnhancedHeapReport] = {}
        for hr in heap_reports:
            heap_by_idx[hr.copy_idx] = hr

        results = []

        for alert in original_alerts:
            vtype = alert.get('vuln_type', alert.get('type', ''))
            orig_score = alert.get('confidence', 0.5)

            if vtype == 'buffer_overflow':
                # 堆溢出告警——用增强过滤器验证
                matched = self._match_heap_report(alert, heap_reports)
                if matched is not None:
                    is_confirmed = matched.verdict in (
                        EnhancedVerdict.CONFIRMED, EnhancedVerdict.LIKELY)
                    enhanced_score = (
                        orig_score if is_confirmed else orig_score * 0.25)
                    results.append(IntegratedReport(
                        func_name=func_name, vuln_type='buffer_overflow',
                        original_score=orig_score,
                        enhanced_score=enhanced_score,
                        verdict=matched.verdict,
                        is_confirmed=is_confirmed,
                        heap_report=matched,
                        evidence=matched.evidence))
                else:
                    # 增强过滤器未找到配对→降级
                    results.append(IntegratedReport(
                        func_name=func_name, vuln_type='buffer_overflow',
                        original_score=orig_score,
                        enhanced_score=orig_score * 0.2,
                        verdict=EnhancedVerdict.FILTERED,
                        is_confirmed=False,
                        evidence=["无分配-拷贝配对——可能是栈操作或全局缓冲区"]))
            else:
                # 非堆溢出类型——直接保留原有结果
                results.append(IntegratedReport(
                    func_name=func_name, vuln_type=vtype,
                    original_score=orig_score,
                    enhanced_score=orig_score,
                    verdict=EnhancedVerdict.UNCERTAIN,
                    is_confirmed=True,
                    evidence=["非堆溢出类型——保留原有检测结果"]))

        # 新增: 对增强过滤器独立发现的溢出(旧检测器未报告的)
        reported_idxs = {r.heap_report.copy_idx for r in results
                        if r.heap_report is not None}
        for hr in heap_reports:
            if hr.copy_idx not in reported_idxs:
                if hr.verdict in (EnhancedVerdict.CONFIRMED,
                                 EnhancedVerdict.LIKELY):
                    results.append(IntegratedReport(
                        func_name=func_name, vuln_type='buffer_overflow',
                        original_score=0.0,  # 旧检测器未发现
                        enhanced_score=0.85 if hr.verdict == EnhancedVerdict.CONFIRMED else 0.6,
                        verdict=hr.verdict,
                        is_confirmed=True,
                        heap_report=hr,
                        evidence=hr.evidence))

        return results

    @staticmethod
    def _match_heap_report(alert: Dict[str, Any],
                           heap_reports: List[EnhancedHeapReport]
                           ) -> Optional[EnhancedHeapReport]:
        """将旧告警匹配到增强过滤器报告"""
        alert_func = alert.get('func_name', alert.get('function', ''))
        alert_line = alert.get('line', alert.get('instr_idx', -1))

        for hr in heap_reports:
            if alert_line >= 0 and hr.copy_idx == alert_line:
                return hr
            if alert_func and alert_func in hr.func_name:
                return hr

        # 无精确匹配但有增强报告→返回最可信的那个
        confirmed = [hr for hr in heap_reports
                    if hr.verdict == EnhancedVerdict.CONFIRMED]
        if confirmed:
            return confirmed[0]
        likely = [hr for hr in heap_reports
                 if hr.verdict == EnhancedVerdict.LIKELY]
        if likely:
            return likely[0]
        return None

    def get_statistics(self,
                       results: List[IntegratedReport]
                       ) -> Dict[str, int]:
        """统计增强过滤效果"""
        stats = {'total': len(results),
                 'confirmed': 0, 'likely': 0,
                 'uncertain': 0, 'filtered': 0,
                 'fp_eliminated': 0}
        for r in results:
            if r.verdict == EnhancedVerdict.CONFIRMED:
                stats['confirmed'] += 1
            elif r.verdict == EnhancedVerdict.LIKELY:
                stats['likely'] += 1
            elif r.verdict == EnhancedVerdict.UNCERTAIN:
                stats['uncertain'] += 1
            else:
                stats['filtered'] += 1
                if r.original_score > 0.5:
                    stats['fp_eliminated'] += 1
        return stats
