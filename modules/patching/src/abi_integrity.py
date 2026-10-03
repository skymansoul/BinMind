# 初始实现：栈帧/调用约定/寄存器保存变更检测
# 增加函数序言/尾声的模式分析

"""Binary ABI Integrity Checker — 补丁的二进制接口完整性检查。

现有工具（abi-compliance-checker, libabigail）依赖 DWARF 调试信息
和源码编译产物。对于仅二进制可用的补丁（无 DWARF）不可用。

本模块直接分析补丁前后的汇编指令，检测 ABI 破坏性变更：
  1. 栈帧大小变更：push rbp; sub rsp, N 中的 N 值变化
  2. callee-saved 寄存器使用变更：补丁是否新增了对 rbx/r12-r15 的修改
  3. 返回约定变更：返回值寄存器 (rax) 的语义是否改变
  4. 参数传递变更：函数是否改变了参数寄存器的读取模式
  5. 对齐要求变更：栈对齐 (16-byte boundary) 是否被破坏

检测结果分级：
  CRITICAL: 必定破坏 ABI（如栈帧大小改变但调用者未更新）
  WARNING:  可能破坏 ABI（如新增 callee-saved 寄存器使用但未保存）
  INFO:     ABI 无关的变更（如局部变量操作）

与 FOSDEM 2025 RISC-V ABI 讨论的关系：
  同样的 ABI 概念（caller/callee-saved 寄存器、栈帧管理），
  但本模块针对二进制补丁的差分场景特化。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ABIImpact(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    NONE = "none"


@dataclass
class ABIViolation:
    """单条 ABI 违反。"""
    violation_type: str          # stack_frame | callee_saved | return_value | parameter | alignment
    impact: ABIImpact = ABIImpact.INFO
    description: str = ""
    original_pattern: str = ""
    patched_pattern: str = ""
    affected_callers_estimate: int = 0


@dataclass
class ABIReport:
    """ABI 完整性检查报告。"""
    patch_id: str = ""
    function_name: str = ""
    violations: List[ABIViolation] = field(default_factory=list)
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    abi_compatible: bool = True       # 无 CRITICAL 或 WARNING → True
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'function': self.function_name,
            'abi_compatible': self.abi_compatible,
            'critical': self.critical_count,
            'warning': self.warning_count,
            'violations': [
                {'type': v.violation_type, 'impact': v.impact.value,
                 'desc': v.description}
                for v in self.violations
            ],
            'recommendation': self.recommendation,
        }


# x86-64 ABI 规范 (System V AMD64 ABI)

# callee-saved 寄存器：被调函数必须保存和恢复
CALLEE_SAVED_REGS = {
    'rbx', 'rsp', 'rbp', 'r12', 'r13', 'r14', 'r15',
    'ebx', 'esp', 'ebp', 'r12d', 'r13d', 'r14d', 'r15d',
}

# caller-saved 寄存器：调用者负责保存（被调函数可自由修改）
CALLER_SAVED_REGS = {
    'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11',
}

# 参数传递寄存器（按顺序）
PARAM_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

# 返回值寄存器
RETURN_REG = 'rax'

# 标准函数序言
PROLOGUE_PATTERN = re.compile(
    r'push\s+rbp.*mov\s+rbp,\s*rsp|'
    r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', re.I | re.DOTALL)

# 标准函数尾声
EPILOGUE_PATTERN = re.compile(
    r'(leave|pop\s+rbp|add\s+rsp,\s*(0x[0-9a-f]+|\d+)).*ret', re.I | re.DOTALL)


# ABI 检查器

class ABIIntegrityChecker:
    """二进制补丁 ABI 完整性检查器。

    用法:
        checker = ABIIntegrityChecker()
        report = checker.check(original_asm, patched_asm, func_name='vuln_func')
        if not report.abi_compatible:
            for v in report.violations:
                if v.impact == ABIImpact.CRITICAL:
                    print(f'ABI BREAK: {v.description}')
    """

    def check(self, original_asm: List[str],
              patched_asm: List[str],
              patch_id: str = "",
              function_name: str = "") -> ABIReport:
        """主检查入口。"""
        report = ABIReport(patch_id=patch_id, function_name=function_name)
        violations = []

        # 1. 栈帧大小检查
        v = self._check_stack_frame(original_asm, patched_asm)
        if v:
            violations.append(v)

        # 2. callee-saved 寄存器检查
        vs = self._check_callee_saved_regs(original_asm, patched_asm)
        violations.extend(vs)

        # 3. 返回约定检查
        v = self._check_return_convention(original_asm, patched_asm)
        if v:
            violations.append(v)

        # 4. 参数传递检查
        v = self._check_parameter_passing(original_asm, patched_asm)
        if v:
            violations.append(v)

        # 5. 栈对齐检查
        v = self._check_stack_alignment(original_asm, patched_asm)
        if v:
            violations.append(v)

        report.violations = violations
        report.critical_count = sum(1 for v in violations
                                    if v.impact == ABIImpact.CRITICAL)
        report.warning_count = sum(1 for v in violations
                                   if v.impact == ABIImpact.WARNING)
        report.info_count = sum(1 for v in violations
                                if v.impact == ABIImpact.INFO)
        report.abi_compatible = (report.critical_count == 0 and
                                 report.warning_count == 0)

        if not report.abi_compatible:
            report.recommendation = (
                "补丁破坏了 ABI 兼容性——所有调用者需重新编译或适配")
        elif report.info_count > 0:
            report.recommendation = "ABI 表面兼容，存在信息级差异——建议验证"
        else:
            report.recommendation = "ABI 兼容——补丁未改变函数的外部接口约定"

        return report

# 栈帧检查

    def _check_stack_frame(self, orig: List[str], patched: List[str]
                           ) -> Optional[ABIViolation]:
        """检测栈帧大小是否改变。"""
        orig_frame = self._extract_stack_frame_size(orig)
        patch_frame = self._extract_stack_frame_size(patched)
        if orig_frame is not None and patch_frame is not None:
            if orig_frame != patch_frame:
                return ABIViolation(
                    violation_type='stack_frame',
                    impact=ABIImpact.CRITICAL,
                    description="栈帧大小变更: %d → %d bytes，"
                               "所有调用者的栈布局已失效" % (orig_frame, patch_frame),
                    affected_callers_estimate=-1,  # 未知——需调用图分析
                )
        return None

    def _extract_stack_frame_size(self, asm: List[str]) -> Optional[int]:
        """从函数序言提取栈帧大小。"""
        for line in asm:
            stripped = line.strip().lower()
            # sub rsp, 0xNN
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', stripped)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
            # enter NN, 0
            m = re.search(r'enter\s+(0x[0-9a-f]+|\d+)', stripped)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
        return None

# callee-saved 寄存器检查

    def _check_callee_saved_regs(self, orig: List[str], patched: List[str]
                                 ) -> List[ABIViolation]:
        """检测补丁是否新增了对 callee-saved 寄存器的修改。"""
        violations = []

        orig_writes = self._reg_writes_in_block(orig)
        patch_writes = self._reg_writes_in_block(patched)

        # 提取 callee-saved 寄存器名
        orig_callee_writes = {r for r in orig_writes if r in CALLEE_SAVED_REGS}
        patch_callee_writes = {r for r in patch_writes if r in CALLEE_SAVED_REGS}

        new_callee_writes = patch_callee_writes - orig_callee_writes

        # 检查新增的 callee-saved 写入是否有对应的保存/恢复
        for reg in new_callee_writes:
            saved = any('push ' + reg.replace('d', '') in l.lower()
                       or re.search(r'mov\s+\[rbp.*\],\s*' + reg, l.lower())
                       for l in patched)
            restored = any('pop ' + reg.replace('d', '') in l.lower()
                         or re.search(r'mov\s+' + reg + r',\s*\[rbp.*\]', l.lower())
                         for l in patched)
            if not saved or not restored:
                violations.append(ABIViolation(
                    violation_type='callee_saved',
                    impact=ABIImpact.CRITICAL,
                    description="新增对 callee-saved 寄存器 %s 的修改但未保存/恢复" % reg,
                ))
            else:
                violations.append(ABIViolation(
                    violation_type='callee_saved',
                    impact=ABIImpact.INFO,
                    description="新增 callee-saved 寄存器 %s 使用（已正确保存/恢复）" % reg,
                ))

        return violations

    def _reg_writes_in_block(self, asm: List[str]) -> Set[str]:
        """提取代码块中所有被写入的寄存器。"""
        writes = set()
        for line in asm:
            stripped = line.strip().lower()
            # 大多数双操作数指令: mnemonic dst, src
            parts = stripped.replace(',', ' ').split()
            if len(parts) >= 2:
                mnemonic = parts[0]
                if mnemonic in ('mov', 'lea', 'add', 'sub', 'xor', 'and', 'or',
                               'shl', 'shr', 'mul', 'imul', 'pop', 'inc', 'dec',
                               'xchg', 'ldmxcsr'):
                    dst = parts[1].rstrip(',')
                    if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})$', dst):
                        writes.add(dst.lower())
                # 单操作数: pop reg
                if mnemonic == 'pop' and len(parts) >= 1:
                    dst = parts[-1]
                    if re.match(r'^(r[a-z0-9]{1,3})$', dst):
                        writes.add(dst.lower())
        return writes

# 返回约定检查

    def _check_return_convention(self, orig: List[str], patched: List[str]
                                 ) -> Optional[ABIViolation]:
        """检测返回值约定是否改变。"""
        # 简化：检查 ret 前的 rax 写入模式
        orig_rax_sets = sum(1 for l in orig
                          if re.search(r'\b(rax|eax)\b', l.lower())
                          and re.search(r'\b(mov|lea|xor)\b', l.lower()))
        patch_rax_sets = sum(1 for l in patched
                           if re.search(r'\b(rax|eax)\b', l.lower())
                           and re.search(r'\b(mov|lea|xor)\b', l.lower()))
        # 返回值设置次数显著变化时标记
        if orig_rax_sets == 0 and patch_rax_sets > 0:
            return ABIViolation(
                violation_type='return_value',
                impact=ABIImpact.WARNING,
                description="函数原来不设置返回值 (void)，补丁后新增了 rax 写入",
            )
        if orig_rax_sets > 0 and patch_rax_sets == 0:
            return ABIViolation(
                violation_type='return_value',
                impact=ABIImpact.WARNING,
                description="函数原来有返回值，补丁后移除了 rax 设置——返回值语义可能改变",
            )
        return None

# 参数传递检查

    def _check_parameter_passing(self, orig: List[str], patched: List[str]
                                 ) -> Optional[ABIViolation]:
        """检测参数寄存器使用模式的变更。"""
        orig_param_reads = set()
        patch_param_reads = set()
        for reg in PARAM_REGS:
            for line in orig:
                if re.search(r'\b' + reg + r'\b', line.lower()):
                    orig_param_reads.add(reg)
            for line in patched:
                if re.search(r'\b' + reg + r'\b', line.lower()):
                    patch_param_reads.add(reg)

        new_params = patch_param_reads - orig_param_reads
        removed_params = orig_param_reads - patch_param_reads

        if new_params and not removed_params:
            return ABIViolation(
                violation_type='parameter',
                impact=ABIImpact.WARNING,
                description="补丁新增了对参数寄存器 %s 的读取——"
                           "新参数需调用者配合传递" % ', '.join(new_params),
            )
        return None

# 栈对齐检查

    def _check_stack_alignment(self, orig: List[str], patched: List[str]
                               ) -> Optional[ABIViolation]:
        """检测 16-byte 栈对齐是否被破坏。

        x86-64 ABI 要求 call 指令前 rsp 对齐到 16 bytes。
        补丁新增的 push/call 可能破坏此约束。
        """
        orig_pushes = sum(1 for l in orig if l.strip().lower().startswith('push'))
        patch_pushes = sum(1 for l in patched if l.strip().lower().startswith('push'))
        delta = patch_pushes - orig_pushes
        # push/pop 配对检查
        orig_pops = sum(1 for l in orig if l.strip().lower().startswith('pop'))
        patch_pops = sum(1 for l in patched if l.strip().lower().startswith('pop'))
        net_push = (patch_pushes - patch_pops) - (orig_pushes - orig_pops)
        if net_push % 2 != 0:
            return ABIViolation(
                violation_type='alignment',
                impact=ABIImpact.WARNING,
                description="push/pop 净增量为奇数 (%d) —— "
                           "call 前的 16-byte 栈对齐可能被破坏" % net_push,
            )
        return None
