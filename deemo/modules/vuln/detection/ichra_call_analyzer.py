# coding: utf-8
# 创建: 2026-06-30  |  间接调用分析器
# 修改: 2026-06-30  |  审计后补充文件头与错误处理
#
"""
间接调用劫持风险评估——间接调用点分析器。

技术问题:
  SACK证明即使在精确静态CFI保护下, 攻击者仍可通过
  函数替换攻击(将合法间接调用目标替换为CFI允许集内的其他函数)
  实现任意命令执行和认证绕过。

  但SACK是攻击框架——缺少防御性工具来回答:
    哪些间接调用点最容易被劫持？
    哪些允许目标函数被替换后危害最大？
    应在哪些调用点优先部署额外防护(FineIBT paranoid/kCFI)？

解决方案:
  对二进制中的每个间接调用点评估三维风险:
    1. 可达性风险: 调用目标是否从外部输入可达(攻击者可控制函数指针)
    2. 替换面风险: CFI允许集内有多少替代目标+其中多少是危险函数
    3. 影响风险: 劫持成功后调用点的后置条件(能否到达execve/mprotect等)

  输出按综合风险排序的间接调用点列表——
  安全团队据此优先加固高风险调用点。

技术依据:
  SACK: 函数替换攻击可绕过精确CFI——419次成功攻击
  FineIBT paranoid: caller-side hash可防御但需选择性部署——需风险优先级
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


# 调用点类型


class CallSiteRisk(str, Enum):
    CRITICAL = "critical"    # 高可达+大替换面+高影响
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class IndirectCallSite:
    """间接调用点——二进制中一个间接call/jmp指令"""
    address: int                   # 调用指令地址
    instruction: str = ""          # 反汇编(call rax / jmp [rdi]等)
    containing_function: str = ""
    # 可达性——调用目标是否从外部输入可控
    is_reachable_from_input: bool = False
    input_source: str = ""         # 哪个参数/全局变量控制此调用目标
    # CFI允许集——哪些函数是此调用点的合法目标
    allowed_targets: List[str] = field(default_factory=list)
    allowed_target_count: int = 0
    # 危险目标——允许集中可导致代码执行的函数
    dangerous_targets: List[str] = field(default_factory=list)
    dangerous_target_count: int = 0


@dataclass
class CallSiteRiskAssessment:
    """单个间接调用点的风险评估"""
    call_site: IndirectCallSite
    # 三维评分[0,1]
    reachability_score: float = 0.0
    substitution_risk_score: float = 0.0   # 替换面风险
    impact_score: float = 0.0
    # 综合风险
    overall_risk: float = 0.0
    risk_level: str = CallSiteRisk.LOW
    # 防护建议
    hardening_priority: int = 999
    recommended_action: str = ""


# 危险函数分类

# 被替换后最危险的函数——控制流劫持的直接载体
_DANGEROUS_TARGETS = {
    'execve', 'execveat', 'system', 'popen',
    'mprotect', 'mmap', 'munmap',
    'ptrace', 'process_vm_writev',
    'setuid', 'setgid', 'setresuid', 'capset',
    'chmod', 'chown', 'unlink', 'rename',
    'fork', 'vfork', 'clone',
    'dlopen', 'dlsym',
    'ioctl', 'fcntl',
    'sendfile', 'splice',
}

# 从调用点能触达危险操作时——后置条件评分
_POSTCONDITION_DANGER = {
    'shell_exec': 0.95,           # 能到达execve→完整代码执行
    'memory_manipulation': 0.7,   # 能到达mprotect→内存布局控制
    'privilege_escalation': 0.85, # 能到达setuid→提权
    'file_manipulation': 0.5,     # 能到达unlink/chmod→文件破坏
    'information_disclosure': 0.4, # 能到达read/open→信息泄露
    'denial_of_service': 0.3,
}


# 调用点分析器


class IndirectCallAnalyzer:
    """间接调用点分析——识别+可达性评估+CFI允许集推断。

    分析方法:
      1. 从反汇编中提取间接call/jmp指令(call rax/jmp [rdi]等)
      2. 对每个调用点溯源其目标寄存器的数据来源
      3. 判断来源是否可被外部输入控制(污点分析——简化)
      4. 基于函数类型签名推断CFI允许集
      5. 在允许集中识别危险目标
    """

    def analyze(self, instructions: List[str],
                 function_name: str = "",
                 base_addr: int = 0x400000,
                 cfi_enabled: bool = False,
                 vtable_info: Dict[int, List[str]] = None
                 ) -> List[IndirectCallSite]:
        """从反汇编指令列表分析间接调用点。

        参数:
          instructions: 反汇编行列表
          function_name: 函数名
          base_addr: 基址(地址计算用)
          cfi_enabled: CFI是否启用(影响允许集推断)

        返回IndirectCallSite列表。
        """
        call_sites = []
        vtable_info = vtable_info or {}

        for i, insn_str in enumerate(instructions):
            # 匹配间接call: call reg / call [reg+offset] / call [mem]
            m = re.search(r'call\s+(\*?\[?)(\w+)', insn_str, re.IGNORECASE)
            if not m:
                # 匹配间接jmp
                m = re.search(r'jmp\s+(\*?\[?)(\w+)', insn_str, re.IGNORECASE)
            if not m:
                continue

            target_reg = m.group(2).lower()
            addr = self._extract_addr(insn_str, base_addr, i)

            # 可达性——简化: 检查目标寄存器是否来自函数参数或全局变量
            reachable, source = self._check_reachability(
                target_reg, instructions, i)

            # CFI允许集推断
            if cfi_enabled:
                allowed = self._infer_allowed_targets(
                    addr, target_reg, vtable_info)
            else:
                allowed = ['*']  # 无CFI——所有函数均为合法目标

            dangerous = [t for t in allowed
                         if any(d in t.lower() for d in _DANGEROUS_TARGETS)]

            call_sites.append(IndirectCallSite(
                address=addr,
                instruction=insn_str.strip(),
                containing_function=function_name,
                is_reachable_from_input=reachable,
                input_source=source,
                allowed_targets=allowed,
                allowed_target_count=len(allowed),
                dangerous_targets=dangerous,
                dangerous_target_count=len(dangerous)))

        return call_sites

    def assess_risk(self, call_sites: List[IndirectCallSite],
                     vulnerability_info: Dict = None
                     ) -> List[CallSiteRiskAssessment]:
        """对间接调用点列表执行风险评估。

        三维评分:
          reachability: 目标可控性——完全可控=1.0, 部分可控=0.5, 不可控=0.0
          substitution: 替换面——危险目标占比×允许集大小归一化
          impact: 后置条件——能否到达危险操作
        """
        assessments = []
        vuln = vulnerability_info or {}

        for rank, cs in enumerate(call_sites):
            # 可达性
            if cs.is_reachable_from_input:
                reach = 0.9 if 'user_input' in cs.input_source else 0.6
            else:
                reach = 0.2

            # 替换面风险——危险目标比例×归一化允许集大小
            if cs.allowed_target_count > 0:
                danger_ratio = cs.dangerous_target_count / cs.allowed_target_count
                size_factor = min(1.0, cs.allowed_target_count / 50.0)
                sub = danger_ratio * 0.7 + size_factor * 0.3
            else:
                sub = 1.0  # 无CFI＝最大替换面

            # 影响——基于危险目标类型
            impact = 0.3  # 基线
            for dt in cs.dangerous_targets:
                for key, score in _POSTCONDITION_DANGER.items():
                    if key in dt.lower() or dt.lower() in key:
                        impact = max(impact, score)

            # 综合——加权平均
            overall = 0.35 * reach + 0.35 * sub + 0.3 * impact
            level = (
                CallSiteRisk.CRITICAL if overall >= 0.7 else
                CallSiteRisk.HIGH if overall >= 0.5 else
                CallSiteRisk.MEDIUM if overall >= 0.3 else
                CallSiteRisk.LOW)

            action = self._recommend_action(cs, overall, level)

            assessments.append(CallSiteRiskAssessment(
                call_site=cs,
                reachability_score=round(reach, 3),
                substitution_risk_score=round(sub, 3),
                impact_score=round(impact, 3),
                overall_risk=round(overall, 3),
                risk_level=level,
                hardening_priority=rank + 1,
                recommended_action=action))

        assessments.sort(key=lambda a: a.overall_risk, reverse=True)
        for i, a in enumerate(assessments):
            a.hardening_priority = i + 1

        return assessments

    def _check_reachability(self, target_reg: str,
                              instructions: List[str],
                              call_idx: int) -> Tuple[bool, str]:
        """检查目标寄存器是否从外部输入可达——简化污点分析。

        在调用点之前的指令中搜索:
          - mov target_reg, [param_offset] → 函数参数可控
          - mov target_reg, [global_var] → 全局变量可控
          - lea target_reg, [vtable] → 虚表条目可控(部分)
        """
        for j in range(max(0, call_idx - 10), call_idx):
            insn = instructions[j].lower()
            if target_reg in insn:
                if '[rbp+' in insn or '[rsp+' in insn:
                    return True, 'stack_param'
                if 'rip+' in insn or 'global' in insn:
                    return True, 'global_variable'
                if 'vtable' in insn or 'vftable' in insn:
                    return True, 'vtable_entry'
        return False, ''

    def _extract_addr(self, insn_str: str, base: int, idx: int) -> int:
        m = re.match(r'\s*(?:0x)?([0-9a-fA-F]+)', insn_str.strip())
        if m:
            return int(m.group(1), 16)
        return base + idx * 4

    def _infer_allowed_targets(self, addr: int, target_reg: str,
                                 vtable: Dict[int, List[str]]) -> List[str]:
        """基于虚表信息推断CFI允许集"""
        return vtable.get(addr, ['unknown_target'])

    def _recommend_action(self, cs: IndirectCallSite, risk: float,
                            level: str) -> str:
        if level in (CallSiteRisk.CRITICAL, CallSiteRisk.HIGH):
            return (f"优先加固: 部署FineIBT paranoid caller-side hash "
                    f"或kCFI类型签名检查。危险目标{cs.dangerous_target_count}个。")
        if level == CallSiteRisk.MEDIUM:
            return "建议加固: 审查CFI允许集, 移除不必要目标。"
        return "低风险: 标准CFI策略已足够。"


__all__ = [
    "CallSiteRisk",
    "IndirectCallSite",
    "CallSiteRiskAssessment",
    "IndirectCallAnalyzer",
]
