# 修改记录:
# 2025-09-11 14:02 — 初始实现：间接跳转/调用目标变更 + CFI 违反检测
# 2025-09-12 08:39 — 增加影子栈假设检测：补丁是否新增了 ret 指令

"""Patch CFI Impact Analyzer — 补丁对控制流完整性的影响分析。

控制流完整性 (CFI, Abadi et al. 2005) 是现代二进制防御的基石。
补丁可能无意中创建新的 CFI 违反——新增的间接跳转/调用目标
可能绕过 CFI 策略。

检测维度：
  1. 间接跳转目标变更：补丁是否改变了 jmp [reg]/call [reg] 目标
  2. 新的间接转移：补丁是否新增了间接跳转/调用
  3. 返回地址覆盖：补丁是否新增了可能覆盖返回地址的内存写入
  4. 影子栈假设：补丁是否新增了 ret 指令（需要影子栈记录）
  5. 函数指针表修改：补丁是否修改了虚函数表或回调表

CFI 兼容性分级：
  COMPATIBLE: 未引入新的 CFI 问题
  NEEDS_VERIFICATION: 引入了新的间接转移，但可能仍兼容
  VIOLATION: 明确违反了 CFI 策略

与 μCFI [2024] 的差异：
  μCFI 形式化验证微架构 CFI。本模块在补丁层面做轻量静态检测。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


class CFICompatibility(str):
    COMPATIBLE = "compatible"
    NEEDS_VERIFICATION = "needs_verification"
    VIOLATION = "violation"


@dataclass
class CFIIssue:
    """单条 CFI 相关问题。"""
    issue_type: str = ""               # indirect_jump | return_hijack | vtable_mod | new_indirect
    severity: str = "warning"
    description: str = ""
    instruction: str = ""
    line_index: int = 0


@dataclass
class CFIReport:
    """补丁的 CFI 影响报告。"""
    patch_id: str = ""
    issues: List[CFIIssue] = field(default_factory=list)
    # 统计
    new_indirect_jumps: int = 0
    new_indirect_calls: int = 0
    new_ret_instructions: int = 0
    vtable_modifications: int = 0
    # 判定
    compatibility: str = CFICompatibility.COMPATIBLE

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'compatibility': self.compatibility,
            'new_indirect_jumps': self.new_indirect_jumps,
            'new_indirect_calls': self.new_indirect_calls,
            'new_rets': self.new_ret_instructions,
            'vtable_mods': self.vtable_modifications,
            'issues': [{'type': i.issue_type, 'severity': i.severity, 'desc': i.description}
                      for i in self.issues[:8]],
        }


# ── CFI 影响检测器 ────────────────────────────────────────────────

class CFIImpactAnalyzer:
    """补丁对控制流完整性的影响检测。"""

    # 间接跳转/调用模式
    _INDIRECT_JMP = re.compile(r'\bjmp\s+(\*?\w+|\[)', re.I)
    _INDIRECT_CALL = re.compile(r'\bcall\s+(\*?\w+|\[)', re.I)
    _RET_INSTRUCTION = re.compile(r'\bret\b', re.I)
    # 返回地址覆盖模式
    _RET_ADDR_WRITE = re.compile(r'\bmov\s+\[rbp\s*[+\-]\s*\d+\]', re.I)

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "") -> CFIReport:
        """分析补丁的 CFI 影响。"""
        report = CFIReport(patch_id=patch_id)
        issues = []

        # 识别新增的间接转移
        orig_set = set(self._norm(original_asm))
        patch_set = set(self._norm(patched_asm))
        added = patch_set - orig_set

        for inst in added:
            if self._INDIRECT_JMP.search(inst):
                report.new_indirect_jumps += 1
                issues.append(CFIIssue(
                    issue_type='new_indirect',
                    severity='warning',
                    description="新增间接跳转: %s" % inst[:50],
                    instruction=inst))

            if self._INDIRECT_CALL.search(inst) and 'call [' in inst:
                report.new_indirect_calls += 1
                issues.append(CFIIssue(
                    issue_type='new_indirect',
                    severity='warning',
                    description="新增间接调用 (通过内存): %s" % inst[:50],
                    instruction=inst))

            if self._RET_INSTRUCTION.search(inst):
                report.new_ret_instructions += 1

        # 检查返回地址覆盖
        for i, line in enumerate(patched_asm):
            if self._RET_ADDR_WRITE.search(line):
                norm_line = self._norm_single(line)
                if norm_line not in orig_set:
                    issues.append(CFIIssue(
                        issue_type='return_hijack',
                        severity='error',
                        description="新增对返回地址区域的写入: %s" % line.strip()[:60],
                        instruction=line.strip(),
                        line_index=i))

        # 检查虚函数表修改（通过 mov [reg+offset], imm 模式）
        for i, line in enumerate(patched_asm):
            norm_line = self._norm_single(line)
            if norm_line in orig_set:
                continue
            m = re.search(r'\bmov\s+\[(\w+)\s*\+\s*(0x[0-9a-f]+|\d+)\]', line, re.I)
            if m:
                offset_str = m.group(2)
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                if offset % 8 == 0 and offset < 256 and offset >= 8:
                    report.vtable_modifications += 1
                    issues.append(CFIIssue(
                        issue_type='vtable_mod',
                        severity='warning',
                        description="疑似虚函数表修改 @ offset %d: %s" % (offset, line.strip()[:60]),
                        instruction=line.strip(),
                        line_index=i))

        report.issues = issues

        # 综合判定
        has_errors = any(i.severity == 'error' for i in issues)
        has_warnings = any(i.severity == 'warning' for i in issues)
        if has_errors:
            report.compatibility = CFICompatibility.VIOLATION
        elif has_warnings:
            report.compatibility = CFICompatibility.NEEDS_VERIFICATION
        else:
            report.compatibility = CFICompatibility.COMPATIBLE

        return report

    @staticmethod
    def _norm(lines: List[str]) -> List[str]:
        return [CFIImpactAnalyzer._norm_single(l) for l in lines]

    @staticmethod
    def _norm_single(line: str) -> str:
        return line.strip().lower().replace(',', ' ').split(';')[0].strip()
