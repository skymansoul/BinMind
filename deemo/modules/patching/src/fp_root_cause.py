# 误报根源分类器 — 对FP告警溯源到具体算法缺陷
"""分类器将每个被过滤/保留的告警映射到误报根源类别。

根源类别(基于对既有流水线的缺陷分析):
  FP_NO_ARG_CTRL  — 缺少分配函数参数可控性分析
                    (malloc(常量)被当作溢出)
  FP_NO_ALIGN     — 未考虑ptmalloc块大小对齐
                    (malloc(13)+memcpy(16)实际可用≥16)
  FP_NO_GUARD     — 未考虑守卫条件收紧write上界
                    (cmova cap / and mask / cmp+jcc)
  FP_UNKNOWN_WRITE — write_size未知时求解器误判cannot_overflow
                    (真实溢出被滤为FP → 召回损失)
  FP_PATH_INFEAS  — 路径不可行但未淘汰
  FP_INTERVAL_OVL — 区间重叠的置信度过高

用途:
  1) 统计各根源对FP率/召回率的影响
  2) 验证双向区间交汇对该类告警的修复效果
"""

from typing import Dict, List


class FPRootCauseClassifier:
    """将HeapOverflowFinding映射到误报根源类别。"""

    CATEGORIES = {
        'fp_no_arg_ctrl': '缺少分配参数可控性分析',
        'fp_no_alignment': '未考虑ptmalloc对齐',
        'fp_no_write_guard': '未考虑写侧守卫收紧',
        'fp_unknown_write': '写侧大小未知误判',
        'fp_path_infeasible': '路径不可行未淘汰',
        'fp_interval_overlap': '区间重叠置信度过高',
        'fp_unknown': '未分类',
    }

    def classify(self, finding) -> str:
        """按finding的fp_source与字段归入根源类别。"""
        src = getattr(finding, 'fp_source', '') or ''

        if src == 'constant_alloc_size':
            return 'fp_no_arg_ctrl'
        if src == 'alignment_constraint':
            return 'fp_no_alignment'
        if src == 'path_infeasible':
            return 'fp_path_infeasible'
        if src == 'interval_bound':
            # 写侧未知导致的误滤: write_size==0 且 solved as cannot
            ws = getattr(finding, 'write_size', None)
            if ws == 0:
                return 'fp_unknown_write'
            return 'fp_no_write_guard'
        if src in ('expression_analysis',):
            return 'fp_interval_overlap'
        return 'fp_unknown'

    def aggregate(self, findings: List) -> Dict[str, int]:
        """汇总各根源类别计数。"""
        counts = {k: 0 for k in self.CATEGORIES}
        for f in findings:
            counts[self.classify(f)] += 1
        return counts
