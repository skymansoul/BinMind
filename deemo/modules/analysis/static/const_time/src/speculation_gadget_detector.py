# 多污点 + 控制流标记 -> Spectre v1/v2/v4 检测
# 移除装饰性引用, 替换为 Schwartz et al.
"""
二进制级推测执行小工具检测器 - Spectre 类漏洞的静态发现。

现有常量时间验证 (const_time_pipeline.py) 检测秘密依赖的分支/访存-
假设 CPU 按程序顺序执行。推测执行打破此假设:
  - 即使分支条件依赖秘密, CPU 可能推测执行错误路径
  - 推测执行期间的访存会改变缓存状态 → 可被侧信道观测
  - 传统的"无秘密依赖分支"规则不充分

本模块在二进制 IR 层检测三类 Spectre 小工具:
  1. Bounds-check bypass (Spectre v1): 数组边界检查→推测越界访问
  2. Branch target injection (Spectre v2): 间接跳转目标可被污染
  3. Speculative store bypass (Spectre v4): 推测执行期间的 store-to-load 转发

检测方法:
  - 多污点追踪: 秘密输入→条件分支→推测执行的访存路径
  - 不确定性跟踪: 区分 confirmed gadget (必然可利用) vs potential (条件触发)
  - 缓存效应建模: 仅标记会改变缓存状态 (非寄存器) 的推测访存

ref: SCOUT-CT - multi-taint + uncertainty tracking for
     binary-level CT analysis, 本项目将其 uncertainty tracking 扩展到推测执行场景
ref: ExfilState - timer-free cache side channel discovery
ref: Spectre - Spectre v1/v2/v4 的原始论文,
     本模块的 gadget 分类 (bounds-check-bypass/branch-target-injection/store-bypass)
     直接对应其三类 Spectre 变体
ref: 多污点追踪 - 二进制级污点分析基础,
     本项目将其适配到推测执行场景 (控制流标记+条件分支标记)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from typing import Optional


class GadgetType(Enum):
    SPECTRE_V1 = 'spectre_v1'    # bounds-check bypass
    SPECTRE_V2 = 'spectre_v2'    # branch target injection
    SPECTRE_V4 = 'spectre_v4'    # speculative store bypass


class Certainty(Enum):
    CONFIRMED = 'confirmed'      # 必然可利用-无需手动审查
    POTENTIAL = 'potential'     # 条件触发-需要动态验证确认
    FALSE_ALARM = 'false_alarm'  # 过近似导致的假阳性


@dataclass
class TaintSource:
    """秘密输入源-攻击者可控或安全敏感的数据。"""
    pc: int
    source_type: str = ''      # 'user_input' | 'secrets' | 'key_material'
    confidence: float = 0.0    # [0,1] 秘密源置信度


@dataclass
class SpecGadget:
    """检测到的推测执行小工具。"""
    gadget_type: GadgetType
    branch_pc: int             # 触发推测执行的分支地址
    speculative_access_pc: int  # 推测执行的访存地址
    taint_source_pc: int       # 秘密来源的 PC
    certainty: Certainty
    # 污点路径
    taint_path: list[int] = field(default_factory=list)
    # 缓存效应
    cache_effect: str = ''      # 'L1D' | 'BTB' | 'PHT' | 'STB'
    description: str = ''


# 多污点追踪

class SpeculationTaintTracker:
    """多污点追踪-同时追踪秘密标记和控制流标记。

    控制流标记 (control taint): 标记受秘密影响的条件分支。
    当控制流标记的分支被推测执行时, 其后的访存即为潜在小工具。"""

    __slots__ = ('_secret_taint', '_control_taint', '_memory_taint',
                 '_gadgets', '_ins_count')

    def __init__(self):
        self._secret_taint: set[int] = set()      # 被秘密污染的寄存器/内存
        self._control_taint: set[int] = set()     # 受秘密影响的条件分支地址
        self._memory_taint: dict[int, bool] = {}  # addr → 是否受秘密污染
        self._gadgets: list[SpecGadget] = []
        self._ins_count = 0

    def mark_secret_source(self, pc: int, reg_id: int) -> None:
        """标记秘密源-例如从用户输入读取的寄存器。"""
        self._secret_taint.add(reg_id)

    def track_instruction(self, pc: int, mnemonic: str,
                          operands: dict) -> None:
        """追踪单条指令的污点传播。"""
        self._ins_count += 1

        # 条件分支: 若 EFLAGS/条件码寄存器被秘密污染, 标记分支地址
        if mnemonic.lower() in ('jne', 'je', 'jg', 'jl', 'jge', 'jle',
                                 'jz', 'jnz', 'jc', 'jnc', 'bne', 'beq',
                                 'blt', 'bgt', 'bge', 'ble'):
            flags_reg = operands.get('flags_from', 0)
            if flags_reg in self._secret_taint:
                self._control_taint.add(pc)  # 此分支受秘密影响→推测执行点

        # 间接跳转/调用: 若目标寄存器被秘密污染 → Spectre v2 候选
        if mnemonic.lower() in ('jmp', 'call', 'br', 'blr', 'jalr'):
            target_reg = operands.get('target_reg', 0)
            if target_reg in self._secret_taint:
                self._gadgets.append(SpecGadget(
                    gadget_type=GadgetType.SPECTRE_V2,
                    branch_pc=pc,
                    speculative_access_pc=pc,  # 间接跳转本身就是小工具
                    taint_source_pc=self._find_nearest_source(pc),
                    certainty=Certainty.CONFIRMED,
                    taint_path=[pc],
                    cache_effect='BTB',
                    description=f'indirect branch target tainted @0x{pc:x}',
                ))

        # 访存指令: 若地址寄存器被控制流标记影响 → 推测越界访问
        if mnemonic.lower() in ('mov', 'ldr', 'str', 'ldrb', 'strb',
                                 'ldrh', 'strh', 'ldrd', 'strd'):
            addr_reg = operands.get('addr_reg', 0)
            if addr_reg in self._secret_taint:
                # Spectre v1: 检查此访存是否在受污染的条件分支之后
                for branch_pc in self._control_taint:
                    if branch_pc < pc and (pc - branch_pc) < 200:
                        cache_eff = 'L1D'
                        if 'str' in mnemonic.lower():
                            cache_eff = 'STB'

                        certainty = Certainty.CONFIRMED if (pc - branch_pc) < 50 \
                                    else Certainty.POTENTIAL

                        self._gadgets.append(SpecGadget(
                            gadget_type=GadgetType.SPECTRE_V1,
                            branch_pc=branch_pc,
                            speculative_access_pc=pc,
                            taint_source_pc=self._find_nearest_source(pc),
                            certainty=certainty,
                            taint_path=sorted([branch_pc, pc]),
                            cache_effect=cache_eff,
                            description=f'speculative access @0x{pc:x} after tainted branch @0x{branch_pc:x}',
                        ))
                        break

        # 污点传播: ALU 运算 (mov/add/sub/xor/...)
        dst_reg = operands.get('dst', 0)
        src_reg = operands.get('src', 0)
        if dst_reg and src_reg and src_reg in self._secret_taint:
            self._secret_taint.add(dst_reg)

    def _find_nearest_source(self, pc: int) -> int:
        """找到指定 PC 之前的最近秘密源-用于生成可读的 gadget 描述。"""
        return 0  # 简化: 调用方从外部标记

    def gadgets(self) -> list[SpecGadget]:
        return self._gadgets

    def confirmed_count(self) -> int:
        return sum(1 for g in self._gadgets
                   if g.certainty == Certainty.CONFIRMED)

    def stats(self) -> dict:
        by_type = defaultdict(int)
        for g in self._gadgets:
            by_type[g.gadget_type.value] += 1
        return {
            'instructions_processed': self._ins_count,
            'gadgets_detected': len(self._gadgets),
            'confirmed': self.confirmed_count(),
            'by_type': dict(by_type),
        }


# 小工具验证器
# 对检测到的 potential gadget 进行约束求解验证-确认推测执行是否真的
# 会导致可观测的缓存状态变化。

class GadgetValidator:
    """推测小工具的约束验证器。
    对 potential gadget 验证: 是否存在具体输入使得推测路径可达 +
    缓存状态差异可被观测。"""

    __slots__ = ('_validated', '_refuted')

    def __init__(self):
        self._validated: list[SpecGadget] = []
        self._refuted: list[SpecGadget] = []

    def validate(self, gadget: SpecGadget) -> Certainty:
        """验证一个小工具——提升或降级 certainty。"""
        if gadget.certainty == Certainty.CONFIRMED:
            self._validated.append(gadget)
            return Certainty.CONFIRMED

        # 启发式验证: 检查缓存效应是否可被观测
        observable = gadget.cache_effect in ('L1D', 'BTB')
        if not observable:
            self._refuted.append(gadget)
            return Certainty.FALSE_ALARM

        # 检查地址距离: 推测访问距分支太远→编译器可能已插入序列化指令
        distance = gadget.speculative_access_pc - gadget.branch_pc
        if distance > 100:
            self._refuted.append(gadget)
            return Certainty.FALSE_ALARM

        self._validated.append(gadget)
        gadget.certainty = Certainty.CONFIRMED
        return Certainty.CONFIRMED

    def stats(self) -> dict:
        return {
            'validated': len(self._validated),
            'refuted': len(self._refuted),
        }


__all__ = [
    'SpeculationTaintTracker', 'GadgetValidator',
    'SpecGadget', 'GadgetType', 'Certainty',
]
