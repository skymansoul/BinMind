"""
统一误报削减积分器 — 七阶段级联FP削减 (论文主表消融研究基础).

GAPSBV 完整管线:
  S1: 分配器语义 (chunk_size ≥ request_size)  → 过滤对齐填充内的写入
  S2: 守卫感知写入 (idx < N → 安全)          → 过滤受保护store
  S3: 上游size约束 (size ≤ MAX → malloc安全) → 过滤受约束分配
  S4: 证明义务引擎 (双向约束传播)             → 过滤可证安全的(alloc,write)对
  S5: Slack空间调整 (offset在chunk尾部填充内) → 置信度软降低
  S6: 值域传播 (区间抽象解释)                 → 置信度软降低
  S7: 非堆写入过滤 (栈/全局变量写入)          → 硬过滤

输出: 每个阶段的统计 + 消融数据, 可直接生成论文Table 2 (Ablation Study).

拆分: 阶段实现 → fp_filter_stages.py (独立函数)
"""


from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StageStats:
    """单个过滤阶段的统计."""
    name: str
    input_count: int = 0
    output_count: int = 0
    hard_filtered: int = 0    # 硬过滤 (确定安全, 移除)
    soft_adjusted: int = 0    # 软调整 (降低置信度, 保留)
    tp_retained: int = 0      # 保留的真阳性 (需ground truth)
    fp_removed: int = 0       # 移除的误报


@dataclass
class AblationReport:
    """完整消融研究报告."""
    pipeline_name: str = "GAPSBV"
    stages: List[StageStats] = field(default_factory=list)
    initial_candidates: int = 0
    final_candidates: int = 0
    total_hard_filtered: int = 0
    total_soft_adjusted: int = 0

    def precision_at_stage(self, stage_idx: int, tp: int) -> float:
        """计算第stage_idx阶段后的精度 (需外部提供TP)."""
        if stage_idx >= len(self.stages):
            return 0.0
        remaining = self.stages[stage_idx].output_count
        return tp / remaining if remaining > 0 else 1.0

    def to_ablation_rows(self, tp_at_stages: List[int]) -> List[Dict[str, Any]]:
        """生成消融表行 (论文Table 2格式).

        Args:
            tp_at_stages: 每阶段后的TP数 (需ground truth).
        """
        rows = []
        for i, s in enumerate(self.stages):
            tp = tp_at_stages[i] if i < len(tp_at_stages) else 0
            fp = s.output_count - tp
            precision = tp / s.output_count if s.output_count > 0 else 0
            recall_denom = tp_at_stages[0] if tp_at_stages else 1
            recall = tp / recall_denom if recall_denom > 0 else 0
            f1 = (2 * precision * recall / (precision + recall)
                  if (precision + recall) > 0 else 0)
            rows.append({
                "stage": s.name, "tp": tp, "fp": fp,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "remaining": s.output_count,
            })
        return rows


class FPReductionIntegrator:
    """七阶段误报削减积分器 — 一键运行完整管线.

    阶段实现委托至 fp_filter_stages 模块.

    使用:
      integrator = FPReductionIntegrator()
      report, filtered = integrator.run(candidates, ir_lines, code_context)
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform

    def run(
        self,
        candidates: List[Any],
        ir_lines: List[str],
        code_context: str = "",
        func_name: str = "",
    ) -> Tuple[AblationReport, List[Any]]:
        """运行完整七阶段削减管线."""
        from analysis.fp_filter_stages import (
            stage1_allocator_semantics, stage2_guard_aware,
            stage3_size_constraints, stage4_proof_obligations,
            stage5_slack_space, stage6_value_range, stage7_non_heap,
        )

        report = AblationReport()
        report.initial_candidates = len(candidates)
        current = list(candidates)

        # S1: 分配器语义
        s1 = StageStats(name="S1_AllocatorSemantics", input_count=len(current))
        current = stage1_allocator_semantics(self, current)
        s1.output_count = len(current)
        s1.hard_filtered = s1.input_count - s1.output_count
        report.stages.append(s1)

        # S2: 守卫感知写入
        s2 = StageStats(name="S2_GuardAwareWrites", input_count=len(current))
        current, s2.hard_filtered = stage2_guard_aware(self, current, ir_lines)
        s2.output_count = len(current)
        report.stages.append(s2)

        # S3: 上游size约束
        s3 = StageStats(name="S3_SizeConstraints", input_count=len(current))
        current, s3.soft_adjusted = stage3_size_constraints(self, current, ir_lines)
        s3.output_count = len(current)
        report.stages.append(s3)

        # S4: 证明义务引擎
        s4 = StageStats(name="S4_ProofObligations", input_count=len(current))
        current, s4.hard_filtered, s4.soft_adjusted = (
            stage4_proof_obligations(self, current, ir_lines))
        s4.output_count = len(current)
        report.stages.append(s4)

        # S5: Slack空间
        s5 = StageStats(name="S5_SlackSpace", input_count=len(current))
        current, s5.soft_adjusted = stage5_slack_space(self, current)
        s5.output_count = len(current)
        report.stages.append(s5)

        # S6: 值域传播
        s6 = StageStats(name="S6_ValueRange", input_count=len(current))
        current, s6.soft_adjusted = stage6_value_range(self, current, ir_lines)
        s6.output_count = len(current)
        report.stages.append(s6)

        # S7: 非堆写入过滤
        s7 = StageStats(name="S7_NonHeapFilter", input_count=len(current))
        current, s7.hard_filtered = stage7_non_heap(self, current, ir_lines)
        s7.output_count = len(current)
        report.stages.append(s7)

        report.final_candidates = len(current)
        report.total_hard_filtered = sum(
            s.hard_filtered for s in report.stages)
        report.total_soft_adjusted = sum(
            s.soft_adjusted for s in report.stages)

        # 按置信度排序
        def _conf(c):
            return getattr(c, 'confidence', 0.5)
        current.sort(key=lambda c: -_conf(c))

        return report, current

    # 辅助方法 (static, 供stage函数通过self调用)

    @staticmethod
    def _get_alloc_size(c) -> int:
        if hasattr(c, 'alloc_site'):
            return getattr(c.alloc_site, 'size_arg', -1)
        return c.get('alloc_size', -1) if isinstance(c, dict) else -1

    @staticmethod
    def _get_write_offset(c) -> int:
        if hasattr(c, 'overflow_store'):
            return getattr(c.overflow_store, 'offset', -1)
        return c.get('write_offset', -1) if isinstance(c, dict) else -1

    @staticmethod
    def _get_write_size(c) -> int:
        if hasattr(c, 'overflow_store'):
            return getattr(c.overflow_store, 'store_size', -1)
        return c.get('write_size', -1) if isinstance(c, dict) else -1

    @staticmethod
    def _get_store_pc(c) -> int:
        if hasattr(c, 'overflow_store'):
            return getattr(c.overflow_store, 'pc', -1)
        return -1

    @staticmethod
    def _get_base_var(c) -> str:
        if hasattr(c, 'overflow_store'):
            return getattr(c.overflow_store, 'base_var', '')
        return c.get('write_var', '') if isinstance(c, dict) else ''

    @staticmethod
    def _get_alloc_var(c) -> str:
        if hasattr(c, 'alloc_site'):
            return getattr(c.alloc_site, 'result_var', '')
        return c.get('alloc_var', '') if isinstance(c, dict) else ''

    @staticmethod
    def _get_size_var(c) -> str:
        # 优先: alloc_site.size_expr (新字段, 保留变量名)
        if hasattr(c, 'alloc_site'):
            expr = getattr(c.alloc_site, 'size_expr', '')
            if expr and expr.isidentifier():
                return expr
            sz = getattr(c.alloc_site, 'size_arg', -1)
            if isinstance(sz, str) and sz.isidentifier():
                return sz
        sz = c.get('alloc_size', '') if isinstance(c, dict) else ''
        return sz if isinstance(sz, str) and not sz.isdigit() else ''

    @staticmethod
    def _get_offset_var(c) -> str:
        if hasattr(c, 'overflow_store'):
            off = getattr(c.overflow_store, 'offset', 0)
            if getattr(c.overflow_store, 'offset_is_dynamic', False):
                return getattr(c.overflow_store, 'base_var', '')
        return ''

    @staticmethod
    def _get_alias_offset(c) -> int:
        if hasattr(c, 'overflow_store'):
            return getattr(c.overflow_store, 'offset', 0)
        return 0

    @staticmethod
    def _adjust_confidence(c, delta: float) -> None:
        if hasattr(c, 'confidence'):
            c.confidence = max(0.01, min(0.99, c.confidence + delta))
        elif isinstance(c, dict):
            c['confidence'] = max(0.01, min(0.99,
                c.get('confidence', 0.5) + delta))

    @staticmethod
    def _add_note(c, note: str) -> None:
        if hasattr(c, 'description'):
            c.description = f"{c.description} [{note}]"
        elif isinstance(c, dict):
            c['description'] = c.get('description', '') + f' [{note}]'
