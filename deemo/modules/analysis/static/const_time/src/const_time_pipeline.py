#
# 常量时间验证管线 —— 编排秘密源识别→污点传播→三违规检测的完整流程
#
# 预期用途：
#   - CI/CD 安全门禁：对密码库二进制做每次构建的常量时间合规检查
#   - 安全审计：对第三方闭源 crypto 二进制做评估
#   - 固件安全分析：对 IoT 设备固件中的加密实现做检测
#
# 输出格式: ConstTimeReport —— 包含三种违规的分项统计和严重度汇总

import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

from .secret_tracker import (
    SecretSource, SecretClass, SecretTaint,
    identify_secret_sources, propagate_taint_intraprocedural,
)
from .branch_checker import (
    check_secret_dependent_branches, BranchViolation,
)
from .mem_checker import (
    check_secret_dependent_memory, MemoryViolation,
)
from .loop_checker import (
    check_secret_dependent_loops, LoopViolation,
)

logger = logging.getLogger(__name__)


class ViolationSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    NONE = 0

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented


@dataclass
class ConstTimeReport:
    """常量时间验证的完整报告"""
    binary_path: str
    total_functions: int
    functions_with_secrets: int     # 识别到秘密源的函数数
    branch_violations: List[BranchViolation]
    memory_violations: List[MemoryViolation]
    loop_violations: List[LoopViolation]
    overall_severity: ViolationSeverity
    is_constant_time: bool          # 无违规 → True

    def summary(self) -> str:
        """单行摘要"""
        parts = []
        if self.branch_violations:
            parts.append(f"{len(self.branch_violations)} BRANCH")
        if self.memory_violations:
            parts.append(f"{len(self.memory_violations)} MEMORY")
        if self.loop_violations:
            parts.append(f"{len(self.loop_violations)} LOOP")
        if not parts:
            return "CONSTANT-TIME OK"
        return " | ".join(parts)

    def to_dict(self) -> Dict:
        """导出为可序列化字典（用于 JSON 报告）"""
        return {
            'binary': self.binary_path,
            'functions_total': self.total_functions,
            'functions_with_secrets': self.functions_with_secrets,
            'branch_violations': len(self.branch_violations),
            'memory_violations': len(self.memory_violations),
            'loop_violations': len(self.loop_violations),
            'overall_severity': self.overall_severity.name,
            'is_constant_time': self.is_constant_time,
            'branch_details': [
                {'addr': hex(v.insn_address), 'text': v.insn_text,
                 'severity': v.severity} for v in self.branch_violations
            ],
            'memory_details': [
                {'addr': hex(v.insn_address), 'text': v.insn_text,
                 'severity': v.severity} for v in self.memory_violations
            ],
            'loop_details': [
                {'header': hex(v.loop_header_addr),
                 'severity': v.severity} for v in self.loop_violations
            ],
        }


def verify_constant_time(
    binary_path: str,
    func_insns: Dict[str, Tuple[int, List[Tuple[str, List[str]]]]],
    func_params: Dict[str, List[str]] = None,
    imports: List[str] = None,
    global_vars: Dict[str, int] = None,
    ci_fail_on: ViolationSeverity = ViolationSeverity.HIGH,
) -> ConstTimeReport:
    """对二进制文件做常量时间验证
    
    参数:
    binary_path: 二进制文件路径
    func_insns: {name: (addr, [(mnemonic, [operands]),.])}
    func_params: {name: [param_names]} — 从反编译器推断的函数参数
    imports: 导入符号列表
    global_vars: {name: addr} 全局变量
    ci_fail_on: CI 中断的最低严重度
    
    返回 ConstTimeReport
    """
    if func_params is None:
        func_params = {}
    if imports is None:
        imports = []
    if global_vars is None:
        global_vars = {}

    all_branch_violations = []
    all_memory_violations = []
    all_loop_violations = []
    functions_with_secrets = 0
    max_severity = ViolationSeverity.NONE

    for func_name, (func_addr, insns) in func_insns.items():
        params = func_params.get(func_name, [])

        # 阶段 1: 秘密源识别
        sources = identify_secret_sources(
            func_name, func_addr, params, imports, global_vars)
        if not sources:
            continue

        functions_with_secrets += 1
        logger.debug("函数 %s: 识别到 %d 个秘密源", func_name, len(sources))

        # 阶段 2: 污点传播
        taints = propagate_taint_intraprocedural(sources, insns)
        if not taints:
            continue

        # 阶段 3a: 分支检测
        branch_v = check_secret_dependent_branches(
            func_name, insns, taints, func_addr)
        all_branch_violations.extend(branch_v)

        # 阶段 3b: 访存检测
        mem_v = check_secret_dependent_memory(
            func_name, insns, taints, func_addr)
        all_memory_violations.extend(mem_v)

        # 阶段 3c: 循环检测
        loop_v = check_secret_dependent_loops(
            func_name, insns, taints, func_addr)
        all_loop_violations.extend(loop_v)

    # 汇总严重度
    for v in all_branch_violations:
        if v.severity == 'HIGH':
            max_severity = max(max_severity, ViolationSeverity.HIGH)
        elif v.severity == 'MEDIUM':
            max_severity = max(max_severity, ViolationSeverity.MEDIUM)
    for v in all_memory_violations:
        if v.severity == 'HIGH':
            max_severity = max(max_severity, ViolationSeverity.HIGH)
        elif v.severity == 'MEDIUM':
            max_severity = max(max_severity, ViolationSeverity.MEDIUM)
    for v in all_loop_violations:
        max_severity = max(max_severity, ViolationSeverity.HIGH)

    is_ct = (max_severity == ViolationSeverity.NONE)
    total_v = (len(all_branch_violations) + len(all_memory_violations) +
               len(all_loop_violations))

    report = ConstTimeReport(
        binary_path=binary_path,
        total_functions=len(func_insns),
        functions_with_secrets=functions_with_secrets,
        branch_violations=all_branch_violations,
        memory_violations=all_memory_violations,
        loop_violations=all_loop_violations,
        overall_severity=max_severity,
        is_constant_time=is_ct,
    )

    logger.info("常量时间验证: %s (函数=%d 含秘密/%d, 违规=%d)",
                report.summary(), functions_with_secrets,
                len(func_insns), total_v)

    return report
