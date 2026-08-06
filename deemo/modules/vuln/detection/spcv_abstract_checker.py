# -*- coding: utf-8 -*-
# 创建: 2026-07-29  |  抽象解释语义比较
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
语义补丁完备性——基于抽象解释的补丁语义差异比较。

比较原函数与补丁函数的区间抽象语义模型，检测:
  1. nonnull约束违反——补丁后指针区间仍含0
  2. 缓冲区边界未收紧——写入区间仍无上界
  3. 返回值检查缺失——调用方期望的错误处理未保留
"""

import logging
from typing import Dict, List, Optional

from .spcv_contract_inferrer import FunctionContract, ContractViolation
from .spcv_abstract_domain import AbstractValue, AbstractState, AbstractInterpreter

_log = logging.getLogger(__name__)


class SemanticDiffResult:
    """抽象解释产出的语义差异报告"""

    def __init__(self):
        self.original_post_state: Optional[AbstractState] = None
        self.patched_post_state: Optional[AbstractState] = None
        self.violations: List[ContractViolation] = []
        self.abstract_paths_diverged: bool = False
        self.buffer_bounds_tightened: bool = False
        self.error_paths_remaining: int = 0


def check_patch_completeness(original_code: List[str],
                              patched_code: List[str],
                              contract: FunctionContract
                              ) -> SemanticDiffResult:
    """比较原代码与补丁代码的抽象语义——检测不完整修复。

    不完整修复信号:
      - 补丁后仍存在违反nonnull约束的抽象路径
      - 缓冲区区间未收紧（写入大小仍可能超过目标容量）
      - 补丁引入新的无界变量
    """
    interpreter = AbstractInterpreter()
    result = SemanticDiffResult()

    result.original_post_state = interpreter.interpret_sequence(original_code)
    result.patched_post_state = interpreter.interpret_sequence(patched_code)
    patch_state = result.patched_post_state

    # 检查1: nonnull违反
    for param in contract.nonnull_params:
        if param in patch_state.variables:
            v = patch_state.variables[param]
            if v.contains(0.0) and not v.is_top:
                result.violations.append(ContractViolation(
                    contract_entry=f"{param} != NULL",
                    violation_type="precondition_violated",
                    original_behavior=f"调用点要求{param}非空",
                    patched_behavior=f"补丁后{param}可能为NULL ({v})",
                    severity="HIGH", fix_location=f"参数{param}的NULL检查"))

    # 检查2: 缓冲区边界
    buf_vars = [k for k in patch_state.variables
                if any(hint in k.lower() for hint in
                       AbstractInterpreter._BUFFER_HINTS)]
    for bv in buf_vars:
        pv = patch_state.variables[bv]
        if pv.hi == float('inf') and not pv.is_top:
            result.abstract_paths_diverged = True
            result.violations.append(ContractViolation(
                contract_entry=f"缓冲区{bv}边界",
                violation_type="bound_exceeded",
                original_behavior="缓冲区无显式上界",
                patched_behavior=f"补丁后{bv}区间仍无界: {pv}",
                severity="CRITICAL", fix_location=f"变量{bv}的写入约束"))

    # 检查3: 返回值检查
    if contract.return_check_pattern == "always_checked":
        has_check = any('if' in line and ('ret' in line or 'err' in line)
                        for line in patched_code)
        if not has_check:
            result.violations.append(ContractViolation(
                contract_entry="返回值检查", violation_type="postcondition_broken",
                original_behavior="调用方始终检查返回值",
                patched_behavior="补丁未添加返回值检查",
                severity="MEDIUM"))

    result.error_paths_remaining = len(result.violations)
    result.buffer_bounds_tightened = not result.abstract_paths_diverged
    return result


__all__ = [
    "SemanticDiffResult",
    "check_patch_completeness",
]
