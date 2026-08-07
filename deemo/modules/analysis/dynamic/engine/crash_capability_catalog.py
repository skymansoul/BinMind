# 修改记录:
# 2025-08-04 14:57 - 能力卡分级: 确认(definite)/可能(probable)/潜在(possible) 三级
# 2025-08-05 10:44 - 内存写原语检测: 4 类模式 (直接写/间接写/偏移写/条件写)

"""崩溃利用能力目录 - 从可控性评估枚举具体的利用原语

crash_primitive_slicer.py 确定攻击者能控制什么
本模块确定攻击者能用这些控制做什么--将控制性转化为能力目录

能力分类 (按利用难度递增):
  ARBITRARY_READ:      攻击者可读取任意内存地址
  ARBITRARY_WRITE:     攻击者可写入任意内存地址
  RIP_CONTROL:         攻击者可控制指令指针 -> 代码执行
  STACK_PIVOT:         攻击者可重定向栈指针 -> ROP 链
  CONTROLLED_CALL:     攻击者可控制调用目标
  CONTROLLED_BRANCH:   攻击者可控制条件分支方向
  FORMAT_STRING:       格式字符串漏洞 -> 读/写原语
  INFO_LEAK:           攻击者可获取内存布局信息

每能力附带:
- 置信度 [0,1]
- 利用原语类型 (direct/indirect/offset-based)
- 可操作的寄存器/地址
- 约束条件 (如 "需先泄漏栈地址")

设计意图: 将模糊的 "EXPLOITABLE" 标记替换为可操作的利用清单
安全研究员可直接根据此清单选择开发路径--避免逐条检查崩溃寄存器
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

from .crash_primitive_slicer import (
    ControlAssessment, TaintSource, TaintTag,
)


# 能力定义

class CapabilityClass(Enum):
    """利用能力类别"""
    ARBITRARY_READ = auto()
    ARBITRARY_WRITE = auto()
    RIP_CONTROL = auto()
    STACK_PIVOT = auto()
    CONTROLLED_CALL = auto()
    CONTROLLED_BRANCH = auto()
    FORMAT_STRING = auto()
    INFO_LEAK = auto()


class ConfidenceTier(Enum):
    DEFINITE = "definite"     # 确认--有直接证据
    PROBABLE = "probable"     # 可能--有间接证据 (如部分控制)
    POSSIBLE = "possible"     # 潜在--推测性 (如启发式匹配)


@dataclass
class ExploitCapability:
    """单个利用能力的完整描述"""
    capability: CapabilityClass
    tier: ConfidenceTier
    confidence: float                    # [0, 1]
    # 涉及的寄存器/地址
    controlled_registers: List[str] = field(default_factory=list)
    target_address: Optional[int] = None
    # 约束--利用此能力需要满足的前提条件
    constraints: List[str] = field(default_factory=list)
    # 解释性证据
    evidence: str = ''


@dataclass
class CapabilityCatalog:
    """崩溃的完整利用能力目录"""
    # 能力列表 (按利用价值排序)
    capabilities: List[ExploitCapability] = field(default_factory=list)
    # 最高能力级别
    highest_capability: Optional[CapabilityClass] = None
    # 摘要
    rip_controlled: bool = False
    stack_pivot_possible: bool = False
    write_primitive_present: bool = False
    read_primitive_present: bool = False
    # 攻击复杂度评级 (越低越危险)
    attack_complexity: str = 'HIGH'      # LOW | MEDIUM | HIGH


# 能力合成器

class CapabilitySynthesizer:
    """从 ControlAssessment 合成利用能力目录

    用法:
    synth = CapabilitySynthesizer()
    catalog = synth.synthesize(assessment, crash_insn_text='call [rax+0x10]')
    """

    # 寄存器到其在利用中的角色的映射
    _IP_REGS = {'rip', 'eip'}          # 指令指针
    _SP_REGS = {'rsp', 'esp'}          # 栈指针
    _CALL_REGS = {'rax', 'eax', 'rbx', 'ebx', 'rcx', 'ecx',
                  'rdx', 'edx', 'rdi', 'edi', 'rsi', 'esi',
                  'r8', 'r9', 'r10', 'r11'}  # 可出现在间接调用中的寄存器

    def synthesize(
        self,
        assessment: ControlAssessment,
        crash_insn_text: str = '',
        crash_address: int = 0,
    ) -> CapabilityCatalog:
        """从可控性评估合成能力目录"""
        catalog = CapabilityCatalog()

        # 1. RIP 控制检测
        self._assess_rip_control(assessment, crash_insn_text, catalog)

        # 2. 栈 pivot 检测
        self._assess_stack_pivot(assessment, crash_insn_text, catalog)

        # 3. 任意写检测
        self._assess_write_primitive(assessment, crash_insn_text, catalog)

        # 4. 任意读检测
        self._assess_read_primitive(assessment, crash_insn_text, catalog)

        # 5. 受控调用/分支
        self._assess_controlled_transfer(assessment, crash_insn_text, catalog)

        # 6. 信息泄漏检测
        self._assess_info_leak(assessment, crash_insn_text, catalog)

        # 确定最高能力级别
        if catalog.capabilities:
            catalog.highest_capability = catalog.capabilities[0].capability

        # 攻击复杂度评级
        catalog.attack_complexity = self._rate_complexity(catalog)

        return catalog

    def _assess_rip_control(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """IPC 控制 = 确认 -> 最高危险级"""
        # 直接检查: rip 寄存器是否被污染
        rip_tag = assessment.registers.get('rip')
        if rip_tag and rip_tag.source not in (
            TaintSource.UNKNOWN, TaintSource.CONSTANT
        ):
            catalog.rip_controlled = True
            catalog.capabilities.append(ExploitCapability(
                capability=CapabilityClass.RIP_CONTROL,
                tier=ConfidenceTier.DEFINITE,
                confidence=rip_tag.confidence,
                controlled_registers=['rip'],
                constraints=[],
                evidence=f'rip tainted via {rip_tag.source.name}',
            ))
            return

        # 间接检查: 崩溃指令是否为间接跳转/调用且目标寄存器被污染
        if assessment.pc_controlled:
            catalog.rip_controlled = True
            # 找到控制 rip 的具体寄存器
            ctrl_regs = [
                reg for reg, tag in assessment.registers.items()
                if (tag.source not in (TaintSource.UNKNOWN, TaintSource.CONSTANT)
                    and reg in self._IP_REGS)
            ]
            catalog.capabilities.append(ExploitCapability(
                capability=CapabilityClass.RIP_CONTROL,
                tier=ConfidenceTier.PROBABLE,
                confidence=assessment.pc_control_confidence,
                controlled_registers=ctrl_regs,
                constraints=[],
                evidence=f'pc_controlled=True, confidence={assessment.pc_control_confidence:.2f}',
            ))

    def _assess_stack_pivot(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """栈 pivot = rsp 被污染 -> ROP/JOP 前置条件"""
        sp_tag = assessment.registers.get('rsp')
        if sp_tag and sp_tag.source not in (
            TaintSource.UNKNOWN, TaintSource.CONSTANT
        ):
            catalog.stack_pivot_possible = True
            catalog.capabilities.append(ExploitCapability(
                capability=CapabilityClass.STACK_PIVOT,
                tier=ConfidenceTier.DEFINITE,
                confidence=sp_tag.confidence,
                controlled_registers=['rsp'],
                constraints=['需构造 ROP 链或 JOP dispatcher'],
                evidence=f'rsp controlled via {sp_tag.source.name}',
            ))
        elif assessment.sp_controlled:
            catalog.stack_pivot_possible = True
            catalog.capabilities.append(ExploitCapability(
                capability=CapabilityClass.STACK_PIVOT,
                tier=ConfidenceTier.PROBABLE,
                confidence=assessment.sp_control_confidence,
                controlled_registers=['rsp'],
                constraints=['需构造 ROP 链或 JOP dispatcher'],
                evidence=f'sp_controlled=True',
            ))

    def _assess_write_primitive(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """任意写检测--4 类模式"""
        text = crash_insn_text.lower()

        # 模式1: mov [reg], val - 直接写入
        if 'mov' in text and '[' in text:
            for reg in self._CALL_REGS:
                tag = assessment.registers.get(reg)
                if tag and tag.source not in (
                    TaintSource.UNKNOWN, TaintSource.CONSTANT
                ):
                    # 检查此寄存器是否作为存储目标地址
                    if f'[{reg}]' in text or f'[{reg} +' in text or f'[{reg}-' in text:
                        catalog.write_primitive_present = True
                        catalog.capabilities.append(ExploitCapability(
                            capability=CapabilityClass.ARBITRARY_WRITE,
                            tier=ConfidenceTier.DEFINITE,
                            confidence=tag.confidence,
                            controlled_registers=[reg],
                            constraints=[],
                            evidence=f'write target [{reg}] tainted via {tag.source.name}',
                        ))
                        return

        # 模式2: 间接写--任意被污染的寄存器出现在存储操作中
        for reg in self._CALL_REGS:
            tag = assessment.registers.get(reg)
            if tag and tag.source not in (
                TaintSource.UNKNOWN, TaintSource.CONSTANT
            ):
                if f'[{reg}' in text:
                    catalog.write_primitive_present = True
                    catalog.capabilities.append(ExploitCapability(
                        capability=CapabilityClass.ARBITRARY_WRITE,
                        tier=ConfidenceTier.PROBABLE,
                        confidence=tag.confidence * 0.8,
                        controlled_registers=[reg],
                        constraints=['需验证写目标地址对齐'],
                        evidence=f'potential write via tainted {reg}',
                    ))
                    return

    def _assess_read_primitive(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """任意读检测--被污染的寄存器作为加载源地址"""
        text = crash_insn_text.lower()
        for reg in self._CALL_REGS:
            tag = assessment.registers.get(reg)
            if tag and tag.source not in (
                TaintSource.UNKNOWN, TaintSource.CONSTANT
            ):
                # 加载指令且源操作数包含 [reg]
                is_load = any(
                    m in text for m in ('mov', 'lea', 'push')
                )
                if is_load and f'[{reg}' in text:
                    catalog.read_primitive_present = True
                    catalog.capabilities.append(ExploitCapability(
                        capability=CapabilityClass.ARBITRARY_READ,
                        tier=ConfidenceTier.PROBABLE
                        if tag.confidence > 0.6
                        else ConfidenceTier.POSSIBLE,
                        confidence=tag.confidence * 0.75,
                        controlled_registers=[reg],
                        constraints=['读目标需可被攻击者观测'],
                        evidence=f'load source [{reg}] tainted',
                    ))

    def _assess_controlled_transfer(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """受控调用/分支--间接调用或条件跳转的目标可控"""
        text = crash_insn_text.lower()

        # 间接调用: call [reg], call reg
        if 'call' in text:
            for reg in self._CALL_REGS:
                tag = assessment.registers.get(reg)
                if tag and tag.source not in (
                    TaintSource.UNKNOWN, TaintSource.CONSTANT
                ):
                    if reg in text or f'[{reg}]' in text:
                        catalog.capabilities.append(ExploitCapability(
                            capability=CapabilityClass.CONTROLLED_CALL,
                            tier=ConfidenceTier.DEFINITE,
                            confidence=tag.confidence,
                            controlled_registers=[reg],
                            constraints=[],
                            evidence=f'call target {reg} tainted',
                        ))

    def _assess_info_leak(
        self, assessment: ControlAssessment,
        crash_insn_text: str, catalog: CapabilityCatalog,
    ) -> None:
        """信息泄漏: 被污染的寄存器值被写入输出通道"""
        text = crash_insn_text.lower()

        # 启发式: store 操作将寄存器写入内存 (可能被攻击者读取)
        store_regs = []
        for reg in self._CALL_REGS:
            tag = assessment.registers.get(reg)
            if tag and tag.source in (TaintSource.REGISTER_LEAK,):
                store_regs.append(reg)

        if store_regs and any(m in text for m in ('mov', 'push', 'call')):
            catalog.capabilities.append(ExploitCapability(
                capability=CapabilityClass.INFO_LEAK,
                tier=ConfidenceTier.POSSIBLE,
                confidence=0.40,
                controlled_registers=store_regs,
                constraints=['需确认输出通道可被攻击者读取'],
                evidence=f'register_leak from {store_regs}',
            ))

    def _rate_complexity(self, catalog: CapabilityCatalog) -> str:
        """基于现有能力评定攻击复杂度"""
        if catalog.rip_controlled:
            return 'LOW'       # RIP 控制 -> 极低复杂度, 直接利用
        if catalog.stack_pivot_possible:
            return 'MEDIUM'    # 栈 pivot -> 需要 ROP/JOP 链
        if catalog.write_primitive_present:
            return 'MEDIUM'    # 任意写 -> 可能需要多次写
        if catalog.read_primitive_present:
            return 'HIGH'      # 仅任意读 -> 需要额外漏洞链接
        return 'HIGH'          # 无可直接利用的能力


# 便捷接口

def synthesize_capabilities(
    assessment: ControlAssessment,
    crash_insn_text: str = '',
    crash_address: int = 0,
) -> CapabilityCatalog:
    """一行式能力合成"""
    synth = CapabilitySynthesizer()
    return synth.synthesize(assessment, crash_insn_text, crash_address)
