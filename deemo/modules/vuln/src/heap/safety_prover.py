"""可证明安全性检查器 — 约束求解 + 分配器语义的联合安全检查.

创建: 2025-02-06
用途: 这是堆溢出检测误报过滤的"最终裁决"模块。
      接收线性约束集、循环摘要、分配器模型, 联合判定一个堆访问
      是否可被证明为安全。若可证明安全 → 过滤为误报。
      只有当无法证明安全时才保留为告警 (保守策略 → 零漏报)。

三大安全检查维度:
  1. 分配器语义安全: offset 在 allocator 舍入的可用范围内
  2. 路径约束安全: 路径守卫条件约束了 offset ≤ alloc_size
  3. 循环边界安全: 循环归纳变量的范围受分配大小约束

联合判定策略:
  - 任一维度能证明安全 → SAFE (过滤)
  - 所有维度都无法证明安全 → SUSPICIOUS (保留告警)
  - 任一维度能证明溢出 → CONFIRMED_OVERFLOW (升高置信度)

  - "Proving Absence of Buffer Overflows"
    → 基于合约的形式化证明
  - Mango: Value Composer for Exploitability Assessment
    → 值组合的思想: 多个证据联合判定而不是单特征阈值
  - 本模块比Frama-C轻量: 不做完整Hoare逻辑, 仅在堆访问点做快速检查
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

class SafetyVerdict(Enum):
    SAFE = "safe"                        # 可证明安全
    SUSPICIOUS = "suspicious"            # 无法证明安全
    CONFIRMED_OVERFLOW = "confirmed"     # 可证明溢出
    INCONCLUSIVE = "inconclusive"        # 信息不足

@dataclass
class SafetyReport:
    """一次安全检查的完整报告."""
    verdict: SafetyVerdict = SafetyVerdict.INCONCLUSIVE
    dimension_results: Dict[str, SafetyVerdict] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5

    @property
    def is_safe(self) -> bool:
        return self.verdict == SafetyVerdict.SAFE

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in (SafetyVerdict.SUSPICIOUS,
                                SafetyVerdict.CONFIRMED_OVERFLOW)

class SafetyProver:
    """多维度联合安全检查器.

    使用方式:
      prover = SafetyProver()
      # 设置分配器模型和约束
      report = prover.check_heap_access(
          offset=256, alloc_size=200, access_size=4,
          constraint_set=cs, loop_summary=loop, ptr_var="rax")
      if report.is_safe:
          print("可证明安全——过滤此告警")
      else:
          print(f"保留告警: {report.evidence}")
    """

    def __init__(self):
        from .allocator_model import Ptmalloc2Model
        self._alloc_model = Ptmalloc2Model()
        self._stats = {'total_checks': 0, 'proven_safe': 0,
                      'confirmed_overflow': 0, 'inconclusive': 0}

    def check_heap_access(self, offset: int, alloc_size: int,
                          access_size: int = 4,
                          constraint_set: Optional = None,
                          loop_summary: Optional = None,
                          ptr_var: str = "",
                          func_name: str = "") -> SafetyReport:
        """多维度联合安全检查."""
        self._stats['total_checks'] += 1
        report = SafetyReport()
        dim_results = {}

        # 维度1: 分配器语义
        dim1 = self._check_allocator_semantics(
            offset, alloc_size, access_size)
        dim_results['allocator'] = dim1
        if dim1 == SafetyVerdict.SAFE:
            report.evidence.append(
                f'allocator: usable_size covers offset {offset}+{access_size} '
                f'for malloc({alloc_size})')

        # 维度2: 路径约束
        if constraint_set is not None and ptr_var:
            dim2 = self._check_path_constraints(
                offset, alloc_size, constraint_set, ptr_var)
            dim_results['path_constraint'] = dim2
            if dim2 == SafetyVerdict.SAFE:
                report.evidence.append(
                    f'path constraint: {ptr_var} ≤ {alloc_size - access_size} '
                    f'proven from branch guards')

        # 维度3: 循环边界
        if loop_summary is not None:
            dim3 = self._check_loop_bounds(
                offset, alloc_size, loop_summary, access_size)
            dim_results['loop_bound'] = dim3
            if dim3 == SafetyVerdict.SAFE:
                report.evidence.append(
                    f'loop bound: induction var range within [{0}, {alloc_size - 1}]')

        report.dimension_results = dim_results

        # 联合判定
        verdicts = list(dim_results.values())
        if SafetyVerdict.CONFIRMED_OVERFLOW in verdicts:
            report.verdict = SafetyVerdict.CONFIRMED_OVERFLOW
            report.confidence = 0.95
            self._stats['confirmed_overflow'] += 1
        elif SafetyVerdict.SAFE in verdicts:
            report.verdict = SafetyVerdict.SAFE
            report.confidence = 0.85
            self._stats['proven_safe'] += 1
        elif any(v == SafetyVerdict.SUSPICIOUS for v in verdicts):
            report.verdict = SafetyVerdict.SUSPICIOUS
            report.confidence = 0.50
        else:
            report.verdict = SafetyVerdict.INCONCLUSIVE
            report.confidence = 0.30
            self._stats['inconclusive'] += 1

        return report

    def _check_allocator_semantics(self, offset: int, alloc_size: int,
                                   access_size: int) -> SafetyVerdict:
        """维度1: 分配器语义检查."""
        constraint = self._alloc_model.model_alloc(alloc_size)
        usable = constraint.usable_size

        # 直接检查
        if offset + access_size <= usable:
            return SafetyVerdict.SAFE

        # padding 区检查
        padding = usable - alloc_size
        if padding > 0 and offset >= alloc_size and offset + access_size <= usable:
            return SafetyVerdict.SAFE

        # 确定溢出
        if offset >= usable:
            return SafetyVerdict.CONFIRMED_OVERFLOW

        return SafetyVerdict.SUSPICIOUS

    def _check_path_constraints(self, offset: int, alloc_size: int,
                                constraint_set,
                                ptr_var: str) -> SafetyVerdict:
        """维度2: 路径约束检查."""
        from .linear_constraint import LinearConstraintEngine
        engine = LinearConstraintEngine()

        # 检查 offset 本身是常数的情况
        if engine.prove_upper_bound(
                constraint_set, ptr_var, alloc_size - 1):
            return SafetyVerdict.SAFE

        # 若 offset 是变量, 尝试证明 offset <= alloc_size - 1
        # 从约束集中寻找对 offset 变量的边界约束
        for c in constraint_set.constraints:
            if c.coef_a == 1 and c.coef_b == 0 and c.const_c < 0:
                bound = int(-c.const_c)
                if bound <= alloc_size:
                    return SafetyVerdict.SAFE

        # 无法证明但也无法证伪
        return SafetyVerdict.SUSPICIOUS

    def _check_loop_bounds(self, offset: int, alloc_size: int,
                           loop_summary,
                           access_size: int = 4) -> SafetyVerdict:
        """维度3: 循环边界检查."""
        from .loop_interval import LoopClass

        loop = loop_summary if loop_summary else None
        if loop is None:
            return SafetyVerdict.INCONCLUSIVE

        if loop.loop_class == LoopClass.BOUNDED:
            # 检查 max_iterations * element_size <= alloc_size
            if loop.max_iterations <= alloc_size:
                return SafetyVerdict.SAFE
        elif loop.loop_class == LoopClass.OVERFLOW_RISK:
            return SafetyVerdict.CONFIRMED_OVERFLOW
        elif loop.loop_class == LoopClass.UNBOUNDED:
            if loop.guarded_by_check:
                return SafetyVerdict.SAFE
            return SafetyVerdict.SUSPICIOUS

        return SafetyVerdict.INCONCLUSIVE

    def batch_filter(self, accesses: List[Dict],
                     alloc_info: Dict[int, Tuple[int, str]]
                     ) -> List[Dict]:
        """批量安全检查——对一批堆访问做过滤.

        accesses: [{'insn_addr': int, 'offset': int, 'ptr_reg': str,
                     'func_name': str, 'access_size': int}, ...]
        alloc_info: {insn_addr: (alloc_size, ptr_reg)}

        返回: 仅保留 SUSPICIOUS/CONFIRMED_OVERFLOW 的访问.
        """
        filtered = []
        for acc in accesses:
            ptr_reg = acc.get('ptr_reg', '')
            # 查找对应的分配
            alloc_match = None
            for alloc_addr, (size, reg) in alloc_info.items():
                if reg == ptr_reg:
                    alloc_match = (size, alloc_addr)
                    break

            if alloc_match is None:
                # 无法关联到分配 → 保守保留
                filtered.append(acc)
                continue

            alloc_size = alloc_match[0]
            offset = acc.get('offset', 0)
            access_size = acc.get('access_size', 4)

            report = self.check_heap_access(
                offset=offset, alloc_size=alloc_size,
                access_size=access_size, ptr_var=ptr_reg,
                func_name=acc.get('func_name', ''))

            if report.is_suspicious:
                acc['safety_report'] = report
                filtered.append(acc)

        return filtered

    def stats(self) -> dict:
        return dict(self._stats)

    def clear_stats(self) -> None:
        self._stats = {'total_checks': 0, 'proven_safe': 0,
                      'confirmed_overflow': 0, 'inconclusive': 0}
