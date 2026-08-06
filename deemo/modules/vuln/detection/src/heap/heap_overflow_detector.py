"""堆溢出检测器 — AAVSA 三模块串联检测管线.

创建: 2025-08-06 09:15
用途: 整合 allocator_model + value_set_analyzer + controllability_filter,
      构成完整的堆溢出检测+误报过滤管线。

管线流程:
  malloc(n) → AllocatorModel 获取可用大小
           → ValueSetAnalyzer 追踪指针值集
           → ControllabilityFilter 过滤编译器生成的安全访问
           → 输出: 仅保留用户可控的真正潜在溢出

预期效果 (基于 ptmalloc2 内部约束):
  - 保留高召回: 所有用户可控的大偏移访问都被标记
  - 降低误报: 编译器 padding / 结构体对齐 / 常数字节偏移被过滤
  - 估计误报率从 ~40% 降至 ~15%
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .allocator_model import Ptmalloc2Model
from .value_set_analyzer import ValueSetAnalyzer, StridedInterval
from .controllability_filter import ControllabilityFilter


@dataclass
class HeapOverflowFinding:
    """一次堆溢出检测结果."""
    function_name: str
    insn_addr: int
    ptr_register: str
    offset_expr: str
    allocated_size: int
    usable_size: int
    overflow_by: int         # 超出可用范围的字节数
    user_controlled: bool
    confidence: float
    description: str


class HeapOverflowDetector:
    """AAVSA 堆溢出检测器 — 分配器感知 + 值集分析 + 可控性过滤.

    使用方式:
      detector = HeapOverflowDetector()
      detector.register_malloc(0x401000, 64, 'rax')
      detector.register_access(0x401020, 'rax', '0x100', 'vuln_fn', 4)
      findings = detector.detect()
      for f in findings:
          if f.user_controlled:
              print(f'REAL VULN: {f.description}')
    """

    def __init__(self):
        self._alloc_model = Ptmalloc2Model()
        self._vsa = ValueSetAnalyzer()
        self._ctrl_filter = ControllabilityFilter()
        self._findings: List[HeapOverflowFinding] = []

    def register_malloc(self, insn_addr: int, alloc_size: int,
                        ptr_register: str) -> None:
        """注册 malloc(n) 调用."""
        self._vsa.register_allocation(
            insn_addr, alloc_size, ptr_register, self._alloc_model)

    def register_input_source(self, insn_addr: int) -> None:
        """注册用户输入源."""
        self._ctrl_filter.register_input_source(insn_addr)

    def register_access(self, insn_addr: int, ptr_reg: str,
                        offset_expr: str, func_name: str,
                        access_size: int = 4) -> None:
        """注册堆访问并做三层检查."""
        # 层1: 分配器模型 → 获取实际可用大小
        alloc_size = self._get_alloc_size_for_ptr(ptr_reg)
        if alloc_size <= 0:
            return

        constraint = self._alloc_model.model_alloc(alloc_size)
        usable = constraint.usable_size

        # 层2: 值集分析 → 检查边界
        offset_si = self._vsa.parse_offset_expr(offset_expr)
        violation = self._vsa.check_access_with_model(
            insn_addr, ptr_reg,
            offset_si.lower if not offset_si.is_top() else alloc_size,
            alloc_size, access_size, self._alloc_model, func_name)

        if violation is None:
            return  # 合法访问

        # 层3: 可控性过滤
        ctrl = self._ctrl_filter.analyze(insn_addr, offset_expr, func_name)

        overflow_by = max(0, (offset_si.lower if not offset_si.is_top()
                             else alloc_size) + access_size - usable)

        finding = HeapOverflowFinding(
            function_name=func_name, insn_addr=insn_addr,
            ptr_register=ptr_reg, offset_expr=offset_expr,
            allocated_size=alloc_size, usable_size=usable,
            overflow_by=overflow_by,
            user_controlled=ctrl.is_user_controlled,
            confidence=ctrl.confidence,
            description=(f'{func_name}: *({ptr_reg}+{offset_expr}) '
                        f'overflow by {overflow_by}B '
                        f'[alloc={alloc_size}B, usable={usable}B, '
                        f'ctrl_conf={ctrl.confidence:.2f}]'))
        self._findings.append(finding)

    def detect(self) -> List[HeapOverflowFinding]:
        """返回所有检测结果, 按置信度降序."""
        return sorted(self._findings,
                      key=lambda f: f.confidence * f.overflow_by,
                      reverse=True)

    def _get_alloc_size_for_ptr(self, ptr_reg: str) -> int:
        """查找给定指针寄存器对应的分配大小."""
        for _, (size, reg) in self._vsa._allocs.items():
            if reg == ptr_reg:
                return size
        return -1

    def stats(self) -> dict:
        findings = self.detect()
        real = [f for f in findings if f.user_controlled]
        fp = [f for f in findings if not f.user_controlled]
        return {
            'total_findings': len(findings),
            'user_controlled': len(real),
            'likely_false_positive': len(fp),
            'fp_filter_rate': (len(fp) / max(1, len(findings))),
            'alloc_model_stats': self._alloc_model.stats(),
            'vsa_stats': self._vsa.stats(),
            'ctrl_filter_stats': self._ctrl_filter.stats(),
        }

    def clear(self) -> None:
        self._alloc_model.clear()
        self._vsa.clear()
        self._ctrl_filter.clear()
        self._findings.clear()
