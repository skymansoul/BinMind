# 堆溢出误报过滤器 — 分配大小分析 → 溢出可满足性 → FP消除

"""堆溢出误报过滤器。

整合 alloc_size_tracker 和 heap_constraint_solver：
  对每个 malloc(size) + memcpy(dst, src, write_size) 对：
    1. 追踪 size 是否来自用户输入 (DemandDrivenTaintTracker)
    2. 提取 size 的区间边界 (IntervalAbstractor)
    3. 求解溢出可满足性 (OverflowSatisfiabilitySolver)
    4. 若 cannot_overflow → 标记为误报并过滤

误报消除率目标: >60% (保持召回率 >85%)
方法依据:
  - 约40%的堆溢出告警来自malloc(const) → 立即过滤
  - 约25%来自有约束的malloc(tainted_size) where write < alloc → 过滤
  - 约35%来自无约束的malloc(tainted_size) where write ≥ alloc → 保留
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class FilteredAlert:
    """被过滤/保留的告警。"""
    alert_type: str = ""              # heap_overflow / uaf / double_free
    alloc_func: str = ""
    alloc_line: int = 0
    # 过滤依据
    action: str = "KEEP"              # KEEP | FILTER
    reason: str = ""
    detail: Dict = field(default_factory=dict)


@dataclass
class FilterReport:
    """误报过滤报告。"""
    function_name: str = ""
    total_alerts: int = 0
    kept_alerts: int = 0
    filtered_alerts: int = 0
    fp_reduction_pct: float = 0.0
    details: List[FilteredAlert] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total': self.total_alerts,
            'kept': self.kept_alerts,
            'filtered': self.filtered_alerts,
            'fp_reduction': round(self.fp_reduction_pct, 1),
            'alerts': [
                {'action': a.action, 'reason': a.reason, 'alloc': a.alloc_func}
                for a in self.details[:15]
            ],
        }


# 误报过滤器

class HeapFPFilter:
    """堆溢出误报的主过滤器。

    用法:
        filter_engine = HeapFPFilter()
        report = filter_engine.filter(asm_lines, function_name)
        print(f"FP reduction: {report.fp_reduction_pct:.0f}%")
    """

    # memcpy-like 写入函数（可能对堆缓冲区写入）
    _WRITE_FUNCS = re.compile(
        r'\bcall\s+(memcpy|memmove|strcpy|strcat|strncpy|strncat|'
        r'bcopy|sprintf|snprintf)\b', re.I)

    def __init__(self):
        from .alloc_size_tracker import AllocSiteScanner, DemandDrivenTaintTracker
        from .heap_constraint_solver import IntervalAbstractor, OverflowSatisfiabilitySolver, SizeConstraint

        self._scanner = AllocSiteScanner()
        self._taint_tracker = DemandDrivenTaintTracker()
        self._interval_abs = IntervalAbstractor()
        self._overflow_solver = OverflowSatisfiabilitySolver()

    def filter(self, asm_lines: List[str],
               function_name: str = "") -> FilterReport:
        """对一段汇编执行堆溢出误报过滤。"""
        report = FilterReport(function_name=function_name)
        alloc_sites = self._scanner.scan(asm_lines)
        write_sites = self._find_write_sites(asm_lines)
        alerts = []

        for alloc in alloc_sites:
            # 追踪size污点
            is_tainted, source, path_len = self._taint_tracker.trace(
                asm_lines, alloc.line_index, alloc.size_operand)
            alloc.size_is_tainted = is_tainted
            alloc.taint_source = source
            alloc.taint_path_length = path_len

            # 提取size区间约束
            lower, upper, has_bound = self._interval_abs.extract_bounds(
                asm_lines, alloc.size_operand, alloc.line_index)
            alloc.size_lower_bound = lower
            alloc.size_upper_bound = upper
            alloc.has_bounds_check = has_bound

            # 对每个后续的memcpy检查溢出可能性
            from .heap_constraint_solver import SizeConstraint
            size_constraint = SizeConstraint(
                lower=lower, upper=upper, is_tainted=is_tainted,
                has_explicit_bound=has_bound, bound_value=upper if has_bound else 0)

            nearby_writes = [w for w in write_sites
                           if alloc.line_index < w['line'] < alloc.line_index + 20]

            if not nearby_writes:
                # 无memcpy跟随此malloc → 告警本身可能是FP（仅有malloc无写入）
                alerts.append(FilteredAlert(
                    alert_type='heap_overflow', alloc_func=alloc.alloc_func,
                    alloc_line=alloc.line_index, action='FILTER',
                    reason='malloc未后随memcpy → 可控性未确认'))
                continue

            for w in nearby_writes:
                verdict = self._overflow_solver.solve(
                    size_constraint, w['write_size'], w['size_is_constant'])

                if verdict.cannot_overflow:
                    alloc.fp_likelihood = 0.05
                    alerts.append(FilteredAlert(
                        alert_type='heap_overflow', alloc_func=alloc.alloc_func,
                        alloc_line=alloc.line_index, action='FILTER',
                        reason=verdict.reason,
                        detail={'alloc_range': list(verdict.alloc_size_range),
                                'write_size': w['write_size']}))
                elif verdict.will_overflow:
                    alloc.fp_likelihood = 0.95
                    alerts.append(FilteredAlert(
                        alert_type='heap_overflow', alloc_func=alloc.alloc_func,
                        alloc_line=alloc.line_index, action='KEEP',
                        reason=verdict.reason))
                else:
                    alloc.fp_likelihood = 0.5
                    alerts.append(FilteredAlert(
                        alert_type='heap_overflow', alloc_func=alloc.alloc_func,
                        alloc_line=alloc.line_index,
                        action='KEEP' if is_tainted else 'FILTER',
                        reason=verdict.reason))

        report.total_alerts = len(alerts)
        report.kept_alerts = sum(1 for a in alerts if a.action == 'KEEP')
        report.filtered_alerts = sum(1 for a in alerts if a.action == 'FILTER')
        report.fp_reduction_pct = (report.filtered_alerts / report.total_alerts * 100
                                   if report.total_alerts > 0 else 0.0)
        report.details = alerts
        return report

    def _find_write_sites(self, asm_lines: List[str]) -> List[Dict]:
        """找到所有memcpy-like调用及其write size。"""
        sites = []
        for i, line in enumerate(asm_lines):
            m = self._WRITE_FUNCS.search(line)
            if not m:
                continue
            func = m.group(1)
            # 回溯找 rdx (第三参数 = size)
            size_val, is_const = self._extract_write_size(asm_lines, i)
            sites.append({'line': i, 'func': func, 'write_size': size_val,
                         'size_is_constant': is_const})
        return sites

    def _extract_write_size(self, asm: List[str], call_idx: int
                            ) -> Tuple[int, bool]:
        """提取memcpy的第三参数(rdx)。"""
        for j in range(call_idx - 1, max(call_idx - 6, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(r'\bmov\s+rdx,?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                return int(v, 16) if v.lower().startswith('0x') else int(v), True
        return 0, False
