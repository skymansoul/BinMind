# 结构感知的Concolic分支优先级排序器 — 基于输入字段角色的约束求解调度
#
# 核心问题:
#   concolic_bridge.py 收集路径约束 (PathConstraint) 但不做优先级排序——
#   所有分支被同等对待, 按收集顺序求解。Cottontail (2025) 证明:
#   忽略输入结构的分支选择导致 30-40% 的覆盖损失, 因为求解器将
#   资源浪费在"低价值"约束上 (如数据字段的边界检查), 而忽略了
#   "高价值"约束 (如type字段的switch分发, magic字段的验证绕过)。
#
# 本模块的方法 — 字段角色驱动的分支优先级排序:
#   1. 从 taint_field_segmenter 获取输入字段分割 (InputField列表)
#   2. 对每条 PathConstraint, 根据其 input_offset 确定所属字段
#   3. 按字段角色分配基础优先级:
#      magic/checksum → 最高 (绕过验证 = 解锁新代码块)
#      type → 高 (switch分发 = 多个未探索分支)
#      length → 中 (影响缓冲区操作)
#      flags → 中
#      data/padding → 低
#   4. 约束类型调整: == 比较 → +0.2 (精确匹配, 翻转收益大)
#   5. 最终按 priority 降序排列 → 求解器按序处理
#
# 与现有模块的接合:
#   - taint_field_segmenter.py: 提供 InputField 列表 (字段边界+角色)
#   - concolic_bridge.py: 提供 PathConstraint 列表 (分支约束)
#   - 本模块在两者之间: 接收字段+约束 → 输出排序后的求解队列
#
# 参考文献:
#   Cottontail (Trabish et al. 2025, to appear IEEE S&P 2026)
#     — ESCT结构感知路径约束选择; 本项目取其"结构感知"思想但以
#       污点字段角色替代语法树结构, 适配二进制场景
#   OptSE (Zhu et al. 2025, IEEE TSE) — knapsack归约的最优策略;
#     本项目取其"约束价值"概念但以字段角色权重替代路径概率

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 taint_field_segmenter.py: InputField (含 start/end/role/confidence)
# 和 concolic_bridge.py: PathConstraint (含 branch_addr/input_offset等)。
# 为保持松耦合, 通过 prioritize_from_trace() 接受 FieldSegmentation 对象
# (duck-typed, 只需含 .fields 列表), 内部转换为本模块的 FieldSpec。

# 字段角色权重: 基础优先级 [0, 1]
_FIELD_ROLE_PRIORITY = {
    "magic": 1.0,         # 绕过magic验证 → 解锁所有后续代码
    "checksum": 0.95,     # 校验和 → 同magic, 但可能更复杂
    "type": 0.85,         # type字段 → switch分发, 多目标分支
    "length": 0.70,       # 长度字段 → 影响缓冲区分配
    "flags": 0.60,        # 标志位 → 条件分支
    "offset": 0.55,       # 偏移/指针 → 间接影响
    "data": 0.20,         # 纯数据 → 低价值
    "padding": 0.05,      # 填充 → 几乎无价值
    "unknown": 0.30,
}

# 约束比较类型的额外加成
_CMP_TYPE_BONUS = {
    "==": 0.20,   # 精确等于 → 翻转后可能进入完全不同的路径
    "!=": 0.15,
    "<": 0.10,
    ">": 0.10,
    "<=": 0.08,
    ">=": 0.08,
}


@dataclass
class PrioritizedConstraint:
    """带优先级的分支约束"""
    # 原始约束信息 (来自 concolic_bridge.PathConstraint)
    branch_addr: int
    constraint_expr: str = ""
    input_offset: int = 0
    input_size: int = 4
    comparison: str = "=="
    operand_value: int = 0
    taken: bool = False
    # 优先级
    priority: float = 0.0
    # 关联的字段信息
    field_role: str = "unknown"
    field_start: int = 0
    field_end: int = 0
    # 额外元数据
    is_bottleneck: bool = False     # 是否为瓶颈约束 (magic/type)
    estimated_branch_targets: int = 0  # 翻转后可能到达的新基本块估计


@dataclass
class FieldSpec:
    """输入字段规格——与 taint_field_segmenter.InputField 对齐的简化版"""
    start: int
    end: int
    role: str = "unknown"
    confidence: float = 0.0


@dataclass
class PrioritizationReport:
    """分支优先级排序的完整报告"""
    total_constraints: int
    prioritized: List[PrioritizedConstraint] = field(default_factory=list)
    bottleneck_count: int = 0
    avg_priority: float = 0.0
    summary: str = ""


class StructBranchPrioritizer:
    """结构感知的concolic分支优先级排序器。

    典型用法:
        # 从 taint_field_segmenter 获取字段
        fields = [FieldSpec(0, 4, 'magic'), FieldSpec(4, 8, 'length'), ...]
        # 从 concolic_bridge 获取约束
        constraints = [...]  # PathConstraint 列表

        prioritizer = StructBranchPrioritizer()
        report = prioritizer.prioritize(constraints, fields)
        # 按优先级降序求解:
        for pc in report.prioritized:
            solve_and_flip(pc)
    """

    def __init__(self, default_role_priority: float = 0.3):
        self._default_priority = default_role_priority

    def prioritize(self,
                   constraints: List[Any],  # PathConstraint-like objects
                   fields: Optional[List[FieldSpec]] = None,
                   ) -> PrioritizationReport:
        """主入口: 对约束列表按结构感知优先级排序。

        constraints: 需有 branch_addr, input_offset, input_size,
                      comparison, operand_value, taken, constraint_expr 属性。
        fields: 输入字段列表。若为None则全部按unknown处理。
        """
        if not constraints:
            return PrioritizationReport(total_constraints=0,
                                         summary="无约束")

        # 构建字段查找: offset → FieldSpec
        field_map: Dict[int, FieldSpec] = {}
        if fields:
            for f in fields:
                for off in range(f.start, f.end):
                    field_map[off] = f

        prioritized: List[PrioritizedConstraint] = []
        for c in constraints:
            pc = self._to_prioritized(c, field_map)
            prioritized.append(pc)

        # 按优先级降序
        prioritized.sort(key=lambda p: -p.priority)

        # 标记瓶颈约束 (前20%高优先级)
        cutoff_idx = max(1, len(prioritized) // 5)
        for i in range(min(cutoff_idx, len(prioritized))):
            prioritized[i].is_bottleneck = True

        bottlenecks = sum(1 for p in prioritized if p.is_bottleneck)
        avg_pri = (sum(p.priority for p in prioritized)
                    / max(1, len(prioritized)))

        return PrioritizationReport(
            total_constraints=len(constraints),
            prioritized=prioritized,
            bottleneck_count=bottlenecks,
            avg_priority=avg_pri,
            summary=self._build_summary(prioritized, bottlenecks, avg_pri),
        )

    def _to_prioritized(self, constraint: Any,
                         field_map: Dict[int, FieldSpec],
                         ) -> PrioritizedConstraint:
        """将原始约束转换为带优先级的约束"""
        off = getattr(constraint, 'input_offset', 0)
        size = getattr(constraint, 'input_size', 4)
        cmp_type = getattr(constraint, 'comparison', '==')
        taken = getattr(constraint, 'taken', False)

        # 查找字段
        field = field_map.get(off)
        if field is None:
            # 尝试邻近偏移
            for delta in range(1, 9):
                field = field_map.get(off + delta)
                if field:
                    break

        role = field.role if field else "unknown"
        role_conf = field.confidence if field else 0.0

        # 基础优先级 = 字段角色权重 (考虑置信度折扣)
        base = _FIELD_ROLE_PRIORITY.get(role, self._default_priority)
        base *= 0.5 + 0.5 * role_conf  # 低置信度角色打折扣

        # 约束类型加成
        bonus = _CMP_TYPE_BONUS.get(cmp_type, 0.0)

        # 已走分支微调: 若taken=True, 翻转可探索新路径 → +0.05
        if taken:
            bonus += 0.05

        # 输入大小调整: 多字节约束覆盖面更广 → 小幅加成
        size_factor = min(1.0, math.log2(max(1, size)) / 5.0)

        priority = min(1.0, base + bonus * size_factor)

        # 估计翻转后可达的新分支数
        targets = self._estimate_branch_targets(role, cmp_type)

        return PrioritizedConstraint(
            branch_addr=getattr(constraint, 'branch_addr', 0),
            constraint_expr=getattr(constraint, 'constraint_expr', ''),
            input_offset=off, input_size=size,
            comparison=cmp_type,
            operand_value=getattr(constraint, 'operand_value', 0),
            taken=taken,
            priority=priority,
            field_role=role,
            field_start=field.start if field else off,
            field_end=field.end if field else off + size,
            is_bottleneck=False,
            estimated_branch_targets=targets,
        )

    @staticmethod
    def _estimate_branch_targets(role: str, cmp_type: str) -> int:
        """估算翻转此约束后可能到达的新基本块数"""
        if role == "type":
            return 8    # switch分发通常有多个case
        if role == "magic":
            return 1    # magic检查通常只有通过/不通过
        if role == "checksum":
            return 1
        if role == "length":
            return 3    # 长度检查通常有 <, ==, > 三种路径
        if role == "flags":
            return 4    # 位标志可组合
        if cmp_type in ("==", "!="):
            return 2
        return 1

    @staticmethod
    def _build_summary(prioritized: List[PrioritizedConstraint],
                        bottlenecks: int, avg_pri: float) -> str:
        lines = [
            f"分支优先级: {len(prioritized)} 约束, "
            f"瓶颈 {bottlenecks}, 平均优先级 {avg_pri:.3f}",
        ]
        # 按角色分组统计
        role_counts: Dict[str, int] = {}
        for pc in prioritized:
            role_counts[pc.field_role] = role_counts.get(pc.field_role, 0) + 1
        lines.append("角色分布: " + ", ".join(
            f"{r}×{c}" for r, c in sorted(role_counts.items())))
        # 显示前5个最高优先级约束
        for pc in prioritized[:5]:
            marker = " [瓶颈]" if pc.is_bottleneck else ""
            lines.append(
                f"  {pc.branch_addr:#x} off={pc.input_offset} "
                f"role={pc.field_role} pri={pc.priority:.3f}{marker}")
        return "\n".join(lines)


def prioritize_from_trace(constraints: List[Any],
                           field_segmentation=None,  # FieldSegmentation
                           ) -> PrioritizationReport:
    """便捷入口: 从 taint_field_segmenter 的分割结果直接排序约束。

    field_segmentation: FieldSegmentation 对象 (含 fields 列表)。
    """
    fields = None
    if field_segmentation is not None:
        fields = [
            FieldSpec(f.start, f.end, f.role.value, f.confidence)
            for f in getattr(field_segmentation, 'fields', [])
        ]
    prioritizer = StructBranchPrioritizer()
    return prioritizer.prioritize(constraints, fields)
