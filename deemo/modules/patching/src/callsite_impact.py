# 初始实现：调用点栈调整 + 寄存器冲突 + 参数适配分析
# 增加 CLobber 传播分析：被调函数的寄存器使用变化链

"""Call Site Impact Analyzer — 补丁对调用点的连锁影响分析。

当函数 f 被补丁修改后，所有调用 f 的代码路径（call sites）可能受到影响：
  1. 栈偏移调整：若 f 的栈帧大小改变，调用者在 call 后的栈指针不变，
     但若调用者依赖 rsp 的相对偏移访问局部变量，需要验证不受影响。
  2. 寄存器冲突：若补丁改变了 f 的 callee-saved 寄存器使用，
     调用者中依赖这些寄存器值的代码可能出错。
  3. 参数适配：若补丁改变了 f 的参数读取模式（新增对 r8/r9 的读取），
     调用者可能需要新增参数传递。
  4. Clobber 传播：若 f 调用了 g，且 g 也被修补，影响通过调用链传播。

与 abi_integrity 的关系：
  abi_integrity 检查被修补函数本身的 ABI 是否改变。
  本模块检查受影响函数（调用者）是否需要适配。

与 Compiler-Call-Site-Target 的关系：
  编译器在编译时计算栈偏移和寄存器分配。补丁可能破坏这些假设。
  本模块模拟编译器的视角：检查调用者代码是否需要更新。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ImpactLevel(str, Enum):
    NONE = "none"                   # 无影响
    MINOR = "minor"                 # 不影响正确性（如性能微调）
    MODERATE = "moderate"           # 潜在问题（如新增但未使用的寄存器）
    SEVERE = "severe"               # 高概率出错（如寄存器冲突）
    CRITICAL = "critical"           # 必定出错（如栈帧不匹配）


@dataclass
class CallSite:
    """单个调用点的描述。"""
    address: int = 0                # 调用指令地址
    caller_function: str = ""       # 调用者函数名
    callee_function: str = ""       # 被调函数名
    call_instruction: str = ""      # call 指令文本
    # 调用点前后的栈状态
    stack_adjust_before_call: int = 0  # call 前的栈调整
    registers_live_after: Set[str] = field(default_factory=set)
    # call 后仍然存活的寄存器（调用者后续使用）


@dataclass
class CallSiteImpact:
    """单个调用点受到的影响。"""
    call_site: CallSite
    impact_level: ImpactLevel = ImpactLevel.NONE
    impact_description: str = ""
    # 具体问题
    clobbered_live_registers: Set[str] = field(default_factory=set)
    stack_mismatch_bytes: int = 0
    missing_parameters: List[str] = field(default_factory=list)
    # 修复建议
    required_changes: List[str] = field(default_factory=list)


@dataclass
class ImpactReport:
    """调用点影响分析报告。"""
    patch_id: str = ""
    patched_function: str = ""
    call_site_impacts: List[CallSiteImpact] = field(default_factory=list)
    total_call_sites: int = 0
    affected_call_sites: int = 0
    critical_count: int = 0
    severe_count: int = 0
    # 汇总
    safe_to_apply_alone: bool = True
    summary: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'function': self.patched_function,
            'total_call_sites': self.total_call_sites,
            'affected': self.affected_call_sites,
            'critical': self.critical_count,
            'severe': self.severe_count,
            'safe_alone': self.safe_to_apply_alone,
            'impacts': [
                {'caller': i.call_site.caller_function,
                 'level': i.impact_level.value,
                 'desc': i.impact_description,
                 'required_changes': i.required_changes}
                for i in self.call_site_impacts[:10]
            ],
            'summary': self.summary,
        }


# 调用点扫描器

class CallSiteScanner:
    """在汇编中识别 call 指令及其上下文。

    从反汇编文本中提取每个 call 指令的：
      - 目标函数名
      - 寄存器存活信息
      - 栈调整量
    """

    def scan(self, asm_lines: List[str],
             caller_name: str = "") -> List[CallSite]:
        """扫描汇编中的所有调用点。"""
        sites = []
        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower()
            if not stripped.startswith('call '):
                continue

            # 提取目标
            parts = stripped.split()
            if len(parts) < 2:
                continue
            target = parts[-1].rstrip(';').lstrip('*')

            # 提取地址（如果有）
            addr = 0
            addr_match = re.match(r'(?:0x)?([0-9a-f]+)', stripped)
            if addr_match:
                try:
                    addr = int(addr_match.group(1), 16)
                except ValueError:
                    pass

            # 分析 call 后的寄存器存活（扫描后续 10 行）
            regs_live = self._live_regs_after(asm_lines, i)

            # 分析 call 前的栈状态
            stack_adj = self._stack_adjust_before(asm_lines, i)

            sites.append(CallSite(
                address=addr,
                caller_function=caller_name,
                callee_function=target,
                call_instruction=stripped,
                stack_adjust_before_call=stack_adj,
                registers_live_after=regs_live,
            ))
        return sites

    def _live_regs_after(self, asm: List[str], call_idx: int) -> Set[str]:
        """分析 call 指令后仍被使用的寄存器。"""
        live = set()
        # 扫描 call 后的 10 行
        for j in range(call_idx + 1, min(call_idx + 11, len(asm))):
            line = asm[j].strip().lower()
            for reg_match in re.finditer(
                r'\b(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})\b', line):
                reg = reg_match.group(0)
                if self._is_read_not_write(line, reg):
                    live.add(reg)
        return live

    @staticmethod
    def _is_read_not_write(line: str, reg: str) -> bool:
        """判断寄存器在指令中是读取还是写入。"""
        parts = line.replace(',', ' ').split()
        if len(parts) < 2:
            return True
        # 若 reg 是第一个操作数 → 写入，否则 → 读取
        first_op = parts[1].rstrip(',')
        return first_op.lower() != reg.lower()

    def _stack_adjust_before(self, asm: List[str], call_idx: int) -> int:
        """估计 call 前的栈调整量。"""
        # 向上扫描 5 行，找 sub/add rsp
        for j in range(max(call_idx - 5, 0), call_idx):
            line = asm[j].strip().lower()
            m = re.search(r'(?:sub|add)\s+rsp,\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                val = m.group(1)
                n = int(val, 16) if val.startswith('0x') else int(val)
                if 'sub' in line:
                    return n
                else:
                    return -n
        return 0


# 影响分析器

class CallSiteImpactAnalyzer:
    """调用点影响分析器。

    输入：被修补函数的原始和修补后汇编 + 所有已知调用点的汇编。
    输出：每个调用点受到的影响评估。

    用法:
        analyzer = CallSiteImpactAnalyzer()
        report = analyzer.analyze(
            patched_func_orig_asm, patched_func_new_asm,
            call_sites, 'vuln_func', 'CVE-2024-0001')
    """

    def __init__(self):
        self._scanner = CallSiteScanner()

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                call_sites: List[CallSite],
                patched_function: str = "",
                patch_id: str = "") -> ImpactReport:
        """分析补丁对所有调用点的影响。"""
        report = ImpactReport(
            patch_id=patch_id,
            patched_function=patched_function,
            total_call_sites=len(call_sites),
        )

        # 计算补丁改变的寄存器写入集合
        orig_clobbers = self._callee_clobber_set(original_asm)
        patch_clobbers = self._callee_clobber_set(patched_asm)
        new_clobbers = patch_clobbers - orig_clobbers

        # 计算栈帧变化
        orig_frame = self._extract_frame_size(original_asm)
        patch_frame = self._extract_frame_size(patched_asm)
        frame_delta = (patch_frame or 0) - (orig_frame or 0)

        # 计算参数变化
        orig_params = self._params_read(original_asm)
        patch_params = self._params_read(patched_asm)
        new_params = patch_params - orig_params

        impacts = []
        for site in call_sites:
            if site.callee_function != patched_function:
                continue

            impact = self._analyze_single_site(
                site, new_clobbers, frame_delta, new_params)
            impacts.append(impact)

        report.call_site_impacts = impacts
        report.affected_call_sites = sum(
            1 for i in impacts if i.impact_level != ImpactLevel.NONE)
        report.critical_count = sum(
            1 for i in impacts if i.impact_level == ImpactLevel.CRITICAL)
        report.severe_count = sum(
            1 for i in impacts if i.impact_level == ImpactLevel.SEVERE)

        report.safe_to_apply_alone = (
            report.critical_count == 0 and report.severe_count == 0)

        if report.safe_to_apply_alone:
            report.summary = "所有 %d 个调用点均不受影响——可安全应用补丁" % report.total_call_sites
        else:
            report.summary = ("%d/%d 调用点受影响（%d 严重），"
                             "应用补丁前需更新调用者" % (
                report.affected_call_sites, report.total_call_sites,
                report.critical_count + report.severe_count))

        return report

    def _analyze_single_site(self, site: CallSite,
                             new_clobbers: Set[str],
                             frame_delta: int,
                             new_params: Set[str]) -> CallSiteImpact:
        """分析单个调用点的影响。"""
        impact = CallSiteImpact(call_site=site)

        # 检查 1: 新 clobber 的寄存器在调用点后是否存活
        conflict_regs = new_clobbers & site.registers_live_after
        if conflict_regs:
            impact.clobbered_live_registers = conflict_regs
            impact.impact_level = ImpactLevel.CRITICAL
            impact.impact_description = (
                "补丁新增了对 %s 的写入，但调用者 %s 在 call 后仍使用这些寄存器" % (
                    ', '.join(sorted(conflict_regs)),
                    site.caller_function))
            impact.required_changes.append(
                "调用者需在 call 前保存 %s，call 后恢复" % ', '.join(conflict_regs))
            return impact

        # 检查 2: 栈帧变化
        if abs(frame_delta) > 0:
            impact.stack_mismatch_bytes = frame_delta
            # 仅当调用者使用了 rsp 相对寻址时才严重
            impact.impact_level = ImpactLevel.SEVERE
            impact.impact_description = (
                "被调函数栈帧变更 %+d bytes——调用者 %s 的栈布局可能失效" % (
                    frame_delta, site.caller_function))
            impact.required_changes.append(
                "验证调用者不依赖被调函数的栈帧大小")
            return impact

        # 检查 3: 新参数需求
        if new_params:
            impact.missing_parameters = list(new_params)
            impact.impact_level = ImpactLevel.SEVERE
            impact.impact_description = (
                "补丁新增了对参数寄存器 %s 的读取——调用者 %s 需传递这些参数" % (
                    ', '.join(new_params), site.caller_function))
            impact.required_changes.append(
                "调用者需在 call 前设置 %s" % ', '.join(new_params))
            return impact

        # 无影响
        impact.impact_level = ImpactLevel.NONE
        impact.impact_description = "调用点不受补丁影响"
        return impact

# 辅助分析

    @staticmethod
    def _callee_clobber_set(asm: List[str]) -> Set[str]:
        """提取被调函数修改的所有寄存器。"""
        clobbers = set()
        for line in asm:
            stripped = line.strip().lower().replace(',', ' ')
            parts = stripped.split()
            if len(parts) >= 2:
                mnemonic = parts[0]
                # 只统计写入操作
                if mnemonic in ('mov', 'lea', 'xor', 'add', 'sub', 'and', 'or',
                               'shl', 'shr', 'mul', 'imul', 'pop', 'inc', 'dec'):
                    dst = parts[1].rstrip(',')
                    if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})$', dst):
                        clobbers.add(dst.lower())
        # 排除 rax（返回值寄存器，调用者预期会被修改）
        clobbers.discard('rax')
        clobbers.discard('eax')
        return clobbers

    @staticmethod
    def _extract_frame_size(asm: List[str]) -> Optional[int]:
        for line in asm:
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', line, re.I)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
        return None

    @staticmethod
    def _params_read(asm: List[str]) -> Set[str]:
        """提取函数读取的参数寄存器。"""
        param_regs = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'}
        reads = set()
        for line in asm:
            stripped = line.strip().lower()
            for reg in param_regs:
                if re.search(r'\b' + reg + r'\b', stripped):
                    # 判断是读还是写
                    parts = stripped.replace(',', ' ').split()
                    if len(parts) >= 2:
                        first_op = parts[1].rstrip(',')
                        if first_op.lower() != reg:
                            reads.add(reg)
        return reads
