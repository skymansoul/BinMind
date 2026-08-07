# 修改记录:
# 2025-08-21 09:47 — 初始实现：补丁差分的 UAF/双重释放/溢出模式检测
# 2025-08-22 14:13 — 增加分配-释放配对追踪，检测悬挂指针路径

"""Patch Memory-Safety Certifier — 补丁差分的内存安全认证。

现有 model-checking 方案（将 LTL 性质检查 + concolic 执行结合）
对整个二进制做验证。本模块的差异：
  - 完整二进制验证成本高（符号执行 + SMT 求解）
  - 本模块操作在补丁差分上 → 仅检查补丁引入的新风险，轻量

检测维度（补丁引入的内存安全问题）：
  1. Use-After-Free：补丁是否将 free 调用提前到某指针的最后一次使用之前
  2. 双重释放：补丁是否在已有 free 的路径上新增了 free
  3. 缓冲区溢出：补丁是否新增了无边界检查的内存写入
  4. 内存泄漏：补丁是否移除了 free 调用
  5. 栈变量越界：补丁是否新增了超出栈帧范围的访问

与 patch_safety_verifier (StA properties) 的差异：
  那个模块验证补丁是否保持了原 binary 的功能（safe-to-apply）。
  本模块验证补丁本身是否引入了新的内存安全问题（memory-safe）。
  两者检查的问题类别不同。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class MemorySafetyIssue(str, Enum):
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_LEAK = "memory_leak"
    STACK_OVERFLOW = "stack_overflow"
    NULL_DEREF = "null_deref"


@dataclass
class SafetyFinding:
    """单条内存安全发现。"""
    issue_type: MemorySafetyIssue
    severity: str = "warning"     # info | warning | error
    description: str = ""
    # 关联指令
    original_instruction: str = ""
    patched_instruction: str = ""
    # CVSS 估计
    cvss_estimate: float = 0.0


@dataclass
class MemorySafetyReport:
    """补丁内存安全认证报告。"""
    patch_id: str = ""
    findings: List[SafetyFinding] = field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    certified_safe: bool = False
    certification_note: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'certified_safe': self.certified_safe,
            'errors': self.errors,
            'warnings': self.warnings,
            'findings': [
                {'type': f.issue_type.value, 'severity': f.severity,
                 'desc': f.description}
                for f in self.findings[:10]
            ],
            'note': self.certification_note,
        }


# 内存操作模式识别

class MemoryOperationAnalyzer:
    """汇编级内存操作分析。

    识别 malloc/free/realloc 调用、内存读写指令、栈操作等。
    """

    # 内存分配函数名模式
    _ALLOC_FUNCTIONS = {
        'malloc', 'calloc', 'realloc', 'alloca', 'memalign',
        'posix_memalign', 'aligned_alloc', 'mmap', 'brk', 'sbrk',
        'new', 'operator new', '_Znwm', '_Znam',
    }

    # 内存释放函数名模式
    _FREE_FUNCTIONS = {
        'free', 'delete', 'operator delete', '_ZdlPv', '_ZdaPv',
        'munmap', 'cfree',
    }

    # 危险内存操作（无边界检查）
    _DANGEROUS_MEM_OPS = {
        'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf',
        'scanf', 'memcpy', 'read', 'fread', 'recv', 'recvfrom',
    }

    # 安全内存操作（有边界检查）
    _SAFE_MEM_OPS = {
        'strncpy', 'strncat', 'fgets', 'snprintf', 'vsnprintf',
        'memmove', 'strlcpy', 'strlcat',
    }

    def extract_memory_operations(self, asm_lines: List[str]
                                  ) -> Dict[str, List[int]]:
        """提取所有内存操作及其行号。"""
        ops = {'alloc': [], 'free': [], 'write': [], 'read': []}
        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower()
            # call 目标识别
            if stripped.startswith('call '):
                target = stripped.split()[-1].rstrip(';').lstrip('*')
                if target in self._ALLOC_FUNCTIONS:
                    ops['alloc'].append(i)
                elif target in self._FREE_FUNCTIONS:
                    ops['free'].append(i)
            # 内存写入模式
            if re.search(r'mov\s+\[', stripped):
                ops['write'].append(i)
            # 内存读取模式
            if re.search(r'mov\s+\w+,\s*\[', stripped):
                ops['read'].append(i)
        return ops

    @staticmethod
    def pointer_used_after(asm_lines: List[str], free_line: int,
                          pointer_reg: str) -> bool:
        """检查在 free 之后是否仍有对该指针的使用。"""
        for i in range(free_line + 1, len(asm_lines)):
            line = asm_lines[i].strip().lower()
            if re.search(r'\b' + re.escape(pointer_reg) + r'\b', line):
                # 排除 pop/restore
                if not line.startswith('pop ' + pointer_reg):
                    return True
        return False

    @staticmethod
    def infer_pointer_register(asm_lines: List[str], call_line: int) -> str:
        """推断 call 前传递给对应函数的指针寄存器 (rdi/rdx 等)。"""
        for i in range(max(call_line - 5, 0), call_line):
            line = asm_lines[i].strip().lower()
            # mov rdi, reg → reg 是指针
            m = re.search(r'mov\s+rdi,\s*(\w+)', line)
            if m:
                return m.group(1)
        return 'rdi'  # 默认


# 内存安全认证器

class MemorySafetyCertifier:
    """补丁差分的内存安全认证。

    用法:
        cert = MemorySafetyCertifier()
        report = cert.certify(original_asm, patched_asm, patch_id='CVE-2024-0001')
        if report.certified_safe:
            print('补丁通过内存安全认证')
    """

    def __init__(self):
        self._mem_analyzer = MemoryOperationAnalyzer()

    def certify(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "",
                function_name: str = "") -> MemorySafetyReport:
        """对补丁做内存安全认证。"""
        report = MemorySafetyReport(patch_id=patch_id)
        findings = []

        orig_ops = self._mem_analyzer.extract_memory_operations(original_asm)
        patch_ops = self._mem_analyzer.extract_memory_operations(patched_asm)

        # 1. Use-After-Free：free 调用提前
        findings.extend(self._check_uaf(original_asm, patched_asm,
                                        orig_ops, patch_ops))

        # 2. 双重释放：新增 free 但无对应 alloc
        findings.extend(self._check_double_free(orig_ops, patch_ops))

        # 3. 缓冲区溢出：危险函数的引入
        findings.extend(self._check_buffer_overflow(original_asm, patched_asm,
                                                     orig_ops, patch_ops))

        # 4. 内存泄漏：free 被移除
        findings.extend(self._check_memory_leak(orig_ops, patch_ops))

        # 5. 栈变量越界
        findings.extend(self._check_stack_bounds(original_asm, patched_asm))

        report.findings = findings
        report.errors = sum(1 for f in findings if f.severity == 'error')
        report.warnings = sum(1 for f in findings if f.severity == 'warning')
        report.infos = sum(1 for f in findings if f.severity == 'info')

        if report.errors == 0 and report.warnings == 0:
            report.certified_safe = True
            report.certification_note = "补丁通过了内存安全认证——未引入新的内存安全风险"
        elif report.errors == 0:
            report.certified_safe = True
            report.certification_note = "补丁通过了认证但有 %d 个告警——建议人工审查" % report.warnings
        else:
            report.certified_safe = False
            report.certification_note = "补丁未通过认证——存在 %d 个内存安全错误" % report.errors

        return report

# 各检测器

    def _check_uaf(self, orig_asm: List[str], patched_asm: List[str],
                   orig_ops: Dict, patch_ops: Dict) -> List[SafetyFinding]:
        """检测 Use-After-Free。"""
        findings = []
        # 若 free 被提前到指针最后使用之前 → UAF
        if len(orig_ops['free']) == len(patch_ops['free']):
            for i, free_line in enumerate(patch_ops['free']):
                ptr_reg = self._mem_analyzer.infer_pointer_register(
                    patched_asm, free_line)
                if ptr_reg and self._mem_analyzer.pointer_used_after(
                    patched_asm, free_line, ptr_reg):
                    findings.append(SafetyFinding(
                        issue_type=MemorySafetyIssue.USE_AFTER_FREE,
                        severity='error',
                        description="free 调用后仍存在对指针 %s 的访问——疑似 UAF" % ptr_reg,
                        cvss_estimate=7.5,
                    ))
        return findings

    def _check_double_free(self, orig_ops: Dict, patch_ops: Dict
                           ) -> List[SafetyFinding]:
        """检测双重释放。"""
        findings = []
        new_frees = len(patch_ops['free']) - len(orig_ops['free'])
        new_allocs = len(patch_ops['alloc']) - len(orig_ops['alloc'])
        # 新增 free 但无对应 alloc 增加
        if new_frees > 0 and new_allocs < new_frees:
            findings.append(SafetyFinding(
                issue_type=MemorySafetyIssue.DOUBLE_FREE,
                severity='error',
                description="补丁新增了 %d 个 free 调用但仅新增 %d 个分配——"
                           "存在双重释放或释放未分配内存的风险" % (new_frees, new_allocs),
                cvss_estimate=7.0,
            ))
        return findings

    def _check_buffer_overflow(self, orig_asm: List[str], patched_asm: List[str],
                                orig_ops: Dict, patch_ops: Dict
                                ) -> List[SafetyFinding]:
        """检测缓冲区溢出风险。"""
        findings = []
        orig_set = set(orig_asm)
        patch_set = set(patched_asm)
        added = patch_set - orig_set

        # 新增危险函数调用
        dangerous_added = set()
        for inst in added:
            if inst.strip().lower().startswith('call '):
                target = inst.strip().split()[-1].rstrip(';').lstrip('*').lower()
                if target in self._mem_analyzer._DANGEROUS_MEM_OPS:
                    dangerous_added.add(target)

        if dangerous_added:
            findings.append(SafetyFinding(
                issue_type=MemorySafetyIssue.BUFFER_OVERFLOW,
                severity='error',
                description="补丁引入了危险函数调用: %s——这些函数缺少边界检查" % ', '.join(dangerous_added),
                cvss_estimate=8.0,
            ))

        # 检查安全→危险的替换
        removed = orig_set - patch_set
        safe_removed = set()
        for inst in removed:
            if inst.strip().lower().startswith('call '):
                target = inst.strip().split()[-1].rstrip(';').lstrip('*').lower()
                if target in self._mem_analyzer._SAFE_MEM_OPS:
                    safe_removed.add(target)
        if safe_removed and dangerous_added:
            findings.append(SafetyFinding(
                issue_type=MemorySafetyIssue.BUFFER_OVERFLOW,
                severity='error',
                description="安全函数被替换为危险版本: %s → %s" % (
                    ', '.join(safe_removed), ', '.join(dangerous_added)),
                cvss_estimate=8.5,
            ))

        return findings

    def _check_memory_leak(self, orig_ops: Dict, patch_ops: Dict
                           ) -> List[SafetyFinding]:
        """检测内存泄漏（free 被移除）。"""
        findings = []
        removed_frees = len(orig_ops['free']) - len(patch_ops['free'])
        if removed_frees > 0 and len(orig_ops['alloc']) <= len(patch_ops['alloc']):
            findings.append(SafetyFinding(
                issue_type=MemorySafetyIssue.MEMORY_LEAK,
                severity='warning',
                description="补丁移除了 %d 个 free 调用——可能导致内存泄漏" % removed_frees,
                cvss_estimate=3.0,
            ))
        return findings

    def _check_stack_bounds(self, orig_asm: List[str], patched_asm: List[str]
                            ) -> List[SafetyFinding]:
        """检测栈越界访问。"""
        findings = []
        # 提取栈帧大小
        orig_frame = self._extract_frame(orig_asm)
        patch_frame = self._extract_frame(patched_asm)

        # 检查是否有超出栈帧的访问
        if orig_frame and patch_frame:
            for line in patched_asm:
                stripped = line.strip().lower()
                m = re.search(r'\[rbp\s*[-+]\s*(0x[0-9a-f]+|\d+)\]', stripped)
                if m:
                    val_str = m.group(1)
                    offset = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                    # rbp-X 是栈变量；检查是否超出范围
                    actual_offset = offset  # 相对于 rbp
                    if 'sub rsp' in stripped or actual_offset > patch_frame:
                        if not self._in_original(orig_asm, stripped):
                            findings.append(SafetyFinding(
                                issue_type=MemorySafetyIssue.STACK_OVERFLOW,
                                severity='warning',
                                description="新增的栈访问 rbp-%d 超出栈帧范围 (%d bytes)" % (
                                    offset, patch_frame),
                                cvss_estimate=5.0,
                            ))
        return findings

    @staticmethod
    def _extract_frame(asm: List[str]) -> Optional[int]:
        for line in asm:
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', line, re.I)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
        return None

    @staticmethod
    def _in_original(orig_asm: List[str], inst: str) -> bool:
        norm = inst.strip().lower().replace(',', ' ')
        for o in orig_asm:
            if o.strip().lower().replace(',', ' ') == norm:
                return True
        return False
