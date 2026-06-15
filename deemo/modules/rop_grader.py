#!/usr/bin/env python3
"""
ROP Gadget自动分级与利用潜力评估模块

对发现的ROP gadgets进行自动分类和利用潜力评分，
如是否可用于栈迁移、寄存器清零、参数设置等，
并给出最佳利用链建议，优化漏洞利用生成中的gadget选择。

作者: Deemo Security Team
版本: 1.0.0
"""

import os
import sys
import json
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime
from pathlib import Path
from enum import Enum

from config import Config

logger = logging.getLogger('deemo.rop_grader')


class GadgetCategory(Enum):
    """Gadget类别枚举"""
    STACK_PIVOT = 'stack_pivot'       # 栈迁移
    REG_CONTROL = 'reg_control'       # 寄存器控制
    MEM_ACCESS = 'mem_access'         # 内存访问
    ARITHMETIC = 'arithmetic'         # 算术运算
    LOGIC = 'logic'                   # 逻辑运算
    SYSCALL = 'syscall'               # 系统调用
    CALL = 'call'                     # 函数调用
    RET = 'ret'                       # 返回
    JUMP = 'jump'                     # 跳转
    NOP = 'nop'                       # 空操作
    UNKNOWN = 'unknown'               # 未知


class GadgetQuality(Enum):
    """Gadget质量枚举"""
    EXCELLENT = 'excellent'    # 极好：无副作用，常用功能
    GOOD = 'good'              # 好：轻微副作用，可用
    MODERATE = 'moderate'      # 一般：有副作用，需谨慎
    POOR = 'poor'              # 差：严重副作用，不推荐
    USELESS = 'useless'        # 无用：无法利用


@dataclass
class ROPGadget:
    """
    ROP Gadget数据结构
    
    Attributes:
        address: 地址
        raw_bytes: 原始字节
        instruction: 指令字符串
        category: 类别
        quality: 质量
        affected_regs: 影响的寄存器
        preserved_regs: 保持的寄存器
        stack_consumption: 栈消耗
        side_effects: 副作用
        score: 利用潜力评分
        rank: 排名
        notes: 备注
    """
    address: str = ''
    raw_bytes: str = ''
    instruction: str = ''
    category: GadgetCategory = GadgetCategory.UNKNOWN
    quality: GadgetQuality = GadgetQuality.MODERATE
    affected_regs: List[str] = field(default_factory=list)
    preserved_regs: List[str] = field(default_factory=list)
    stack_consumption: int = 0
    side_effects: List[str] = field(default_factory=list)
    score: float = 0.0
    rank: int = 0
    notes: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'address': self.address,
            'raw_bytes': self.raw_bytes,
            'instruction': self.instruction,
            'category': self.category.value,
            'quality': self.quality.value,
            'affected_regs': self.affected_regs,
            'preserved_regs': self.preserved_regs,
            'stack_consumption': self.stack_consumption,
            'side_effects': self.side_effects,
            'score': self.score,
            'rank': self.rank,
            'notes': self.notes,
        }


@dataclass
class GadgetChain:
    """
    Gadget链数据结构
    
    Attributes:
        gadgets: Gadget列表
        purpose: 目的描述
        total_stack_consumption: 总栈消耗
        overall_score: 总体评分
        feasibility: 可行性
        description: 描述
    """
    gadgets: List[ROPGadget] = field(default_factory=list)
    purpose: str = ''
    total_stack_consumption: int = 0
    overall_score: float = 0.0
    feasibility: float = 0.0
    description: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'gadgets': [g.to_dict() for g in self.gadgets],
            'purpose': self.purpose,
            'total_stack_consumption': self.total_stack_consumption,
            'overall_score': self.overall_score,
            'feasibility': self.feasibility,
            'description': self.description,
        }


@dataclass
class GradingConfig:
    """
    分级配置
    
    Attributes:
        max_gadgets: 最大Gadget数量
        min_score_threshold: 最小评分阈值
        prefer_no_side_effects: 是否优先无副作用
        target_architecture: 目标架构
        important_registers: 重要寄存器列表
        stack_pivot_priority: 栈迁移优先级
    """
    max_gadgets: int = 1000
    min_score_threshold: float = 50.0
    prefer_no_side_effects: bool = True
    target_architecture: str = 'x64'
    important_registers: List[str] = field(default_factory=lambda: ['rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'])
    stack_pivot_priority: bool = True
    
    def validate(self) -> bool:
        """验证配置"""
        return True


class ROPGadgetGrader:
    """
    ROP Gadget分级器
    
    对发现的ROP gadgets进行自动分类和利用潜力评分，
    如是否可用于栈迁移、寄存器清零、参数设置等，
    并给出最佳利用链建议，优化漏洞利用生成中的gadget选择。
    
    Attributes:
        config: 分级配置
        gadgets: Gadget列表
        ranked_gadgets: 排名后的Gadget列表
        suggested_chains: 建议的Gadget链
    """
    
    # Gadget分类模式
    CATEGORY_PATTERNS = {
        GadgetCategory.STACK_PIVOT: [
            r'leave; ret',
            r'mov rsp, rbp; pop rbp; ret',
            r'xchg rsp, r..; ret',
            r'pop rsp; ret',
        ],
        GadgetCategory.REG_CONTROL: [
            r'pop r[a-z0-9]+; ret',
            r'mov r[a-z0-9]+, r[a-z0-9]+; ret',
            r'xor r[a-z0-9]+, r[a-z0-9]+; ret',
        ],
        GadgetCategory.MEM_ACCESS: [
            r'mov \[r[a-z0-9]+\], r[a-z0-9]+; ret',
            r'mov r[a-z0-9]+, \[r[a-z0-9]+\]; ret',
            r'mov qword ptr \[r[a-z0-9]+\], r[a-z0-9]+; ret',
        ],
        GadgetCategory.ARITHMETIC: [
            r'add r[a-z0-9]+, r[a-z0-9]+; ret',
            r'sub r[a-z0-9]+, r[a-z0-9]+; ret',
            r'inc r[a-z0-9]+; ret',
            r'dec r[a-z0-9]+; ret',
        ],
        GadgetCategory.LOGIC: [
            r'and r[a-z0-9]+, r[a-z0-9]+; ret',
            r'or r[a-z0-9]+, r[a-z0-9]+; ret',
            r'xor r[a-z0-9]+, r[a-z0-9]+; ret',
            r'shl r[a-z0-9]+, [0-9]+; ret',
        ],
        GadgetCategory.SYSCALL: [
            r'syscall; ret',
            r'sysenter; ret',
            r'int 0x80; ret',
        ],
        GadgetCategory.CALL: [
            r'call r[a-z0-9]+',
            r'call \[r[a-z0-9]+\]',
            r'call qword ptr \[r[a-z0-9]+\]',
        ],
        GadgetCategory.RET: [
            r'ret',
            r'ret [0x[0-9a-fA-F]+]',
        ],
        GadgetCategory.JUMP: [
            r'jmp r[a-z0-9]+',
            r'jmp \[r[a-z0-9]+\]',
        ],
        GadgetCategory.NOP: [
            r'nop; ret',
            r'nop nop; ret',
        ],
    }
    
    # 评分权重
    SCORE_WEIGHTS = {
        'category': 30,      # 类别权重
        'registers': 25,     # 寄存器控制权重
        'side_effects': 20,  # 副作用权重（负分）
        'stack': 15,         # 栈消耗权重（负分）
        'length': 10,        # 长度权重（短更好）
    }
    
    # 类别评分基础值
    CATEGORY_BASE_SCORES = {
        GadgetCategory.STACK_PIVOT: 90,
        GadgetCategory.REG_CONTROL: 80,
        GadgetCategory.MEM_ACCESS: 75,
        GadgetCategory.SYSCALL: 85,
        GadgetCategory.CALL: 70,
        GadgetCategory.ARITHMETIC: 60,
        GadgetCategory.LOGIC: 55,
        GadgetCategory.RET: 50,
        GadgetCategory.JUMP: 65,
        GadgetCategory.NOP: 40,
        GadgetCategory.UNKNOWN: 30,
    }
    
    # 常见副作用及其惩罚值
    SIDE_EFFECT_PENALTIES = {
        'memory_write': -15,
        'memory_read': -5,
        'register_clobber': -10,
        'stack_modify': -8,
        'syscall': -3,
        'call': -5,
        'jump': -3,
    }
    
    # x64重要寄存器及其重要性
    REGISTER_IMPORTANCE = {
        'rax': 10,   # 返回值，系统调用号
        'rdi': 9,    # 第一个参数
        'rsi': 8,    # 第二个参数
        'rdx': 7,    # 第三个参数
        'rcx': 6,    # 第四个参数
        'r8': 5,     # 第五个参数
        'r9': 4,     # 第六个参数
        'rbp': 8,    # 栈帧基址
        'rsp': 10,   # 栈指针（栈迁移关键）
        'rip': 10,   # 指令指针
        'rbx': 3,
        'r10': 3,
        'r11': 3,
        'r12': 2,
        'r13': 2,
        'r14': 2,
        'r15': 2,
    }
    
    def __init__(self, config: Optional[GradingConfig] = None):
        """
        初始化ROP Gadget分级器
        
        Args:
            config: 分级配置
        """
        self.config = config or GradingConfig()
        self.gadgets: List[ROPGadget] = []
        self.ranked_gadgets: List[ROPGadget] = []
        self.suggested_chains: List[GadgetChain] = []
        
        logger.info("[ROPGrader] 初始化ROP Gadget分级器")
    
    def load_gadgets(self, gadgets: List[Dict[str, Any]]) -> None:
        """
        加载Gadget列表
        
        Args:
            gadgets: Gadget字典列表
        """
        self.gadgets = []
        
        for gadget_data in gadgets:
            gadget = ROPGadget(
                address=gadget_data.get('address', ''),
                raw_bytes=gadget_data.get('raw_bytes', ''),
                instruction=gadget_data.get('instruction', ''),
            )
            self.gadgets.append(gadget)
        
        logger.info(f"[ROPGrader] 加载了 {len(self.gadgets)} 个Gadget")
    
    def load_gadgets_from_file(self, file_path: str) -> bool:
        """
        从文件加载Gadget
        
        Args:
            file_path: 文件路径
            
        Returns:
            加载成功返回True
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            gadgets = data.get('gadgets', [])
            self.load_gadgets(gadgets)
            
            return True
        except Exception as e:
            logger.error(f"[ROPGrader] 加载文件失败: {e}")
            return False
    
    def classify_gadget(self, gadget: ROPGadget) -> GadgetCategory:
        """
        分类单个Gadget
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            Gadget类别
        """
        instruction = gadget.instruction.lower()
        
        for category, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern.lower(), instruction):
                    return category
        
        return GadgetCategory.UNKNOWN
    
    def analyze_registers(self, gadget: ROPGadget) -> Tuple[List[str], List[str]]:
        """
        分析Gadget影响的寄存器
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            (影响的寄存器, 保持的寄存器)
        """
        instruction = gadget.instruction.lower()
        affected = []
        preserved = []
        
        # 提取所有寄存器引用
        all_regs = re.findall(r'r[a-z0-9]+', instruction)
        
        # 分析操作类型
        if 'pop' in instruction:
            # pop操作：修改寄存器
            pop_regs = re.findall(r'pop (r[a-z0-9]+)', instruction)
            affected.extend(pop_regs)
        
        if 'mov' in instruction:
            # mov操作：第一个参数被修改
            mov_match = re.search(r'mov (r[a-z0-9]+),', instruction)
            if mov_match:
                affected.append(mov_match.group(1))
        
        if 'xor' in instruction:
            # xor reg, reg：寄存器清零
            xor_match = re.search(r'xor (r[a-z0-9]+), (r[a-z0-9]+)', instruction)
            if xor_match and xor_match.group(1) == xor_match.group(2):
                affected.append(xor_match.group(1))
        
        # 标记其他寄存器为保持
        for reg in all_regs:
            if reg not in affected:
                preserved.append(reg)
        
        return affected, preserved
    
    def calculate_stack_consumption(self, gadget: ROPGadget) -> int:
        """
        计算栈消耗
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            栈消耗字节数
        """
        instruction = gadget.instruction.lower()
        consumption = 0
        
        # 每个pop消耗8字节（x64）
        pop_count = len(re.findall(r'pop', instruction))
        consumption += pop_count * 8
        
        # ret消耗8字节
        if 'ret' in instruction:
            consumption += 8
        
        # 特殊情况：ret imm16
        ret_imm_match = re.search(r'ret (0x[0-9a-fA-F]+)', instruction)
        if ret_imm_match:
            imm_value = int(ret_imm_match.group(1), 16)
            consumption += imm_value
        
        return consumption
    
    def detect_side_effects(self, gadget: ROPGadget) -> List[str]:
        """
        检测副作用
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            副作用列表
        """
        instruction = gadget.instruction.lower()
        side_effects = []
        
        # 内存写入
        if re.search(r'\[r[a-z0-9]+\]', instruction) and 'mov' in instruction:
            mov_match = re.search(r'mov \[r[a-z0-9]+\]', instruction)
            if mov_match:
                side_effects.append('memory_write')
        
        # 内存读取
        if re.search(r'mov r[a-z0-9]+, \[r[a-z0-9]+\]', instruction):
            side_effects.append('memory_read')
        
        # 寄存器破坏（非目标寄存器被修改）
        affected = gadget.affected_regs
        important_regs = self.config.important_registers
        for reg in affected:
            if reg not in important_regs[:3]:  # 前3个最重要
                side_effects.append('register_clobber')
        
        # 栈修改
        if 'rsp' in affected or 'rbp' in affected:
            side_effects.append('stack_modify')
        
        # 系统调用
        if 'syscall' in instruction or 'sysenter' in instruction:
            side_effects.append('syscall')
        
        # 函数调用
        if 'call' in instruction:
            side_effects.append('call')
        
        # 跳转
        if 'jmp' in instruction:
            side_effects.append('jump')
        
        return side_effects
    
    def calculate_score(self, gadget: ROPGadget) -> float:
        """
        计算利用潜力评分
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            评分（0-100）
        """
        score = 0.0
        
        # 类别基础分（直接使用基础分，不乘权重）
        category_score = self.CATEGORY_BASE_SCORES.get(gadget.category, 30)
        score += category_score
        
        # 寄存器控制奖励
        reg_score = 0
        for reg in gadget.affected_regs:
            reg_score += self.REGISTER_IMPORTANCE.get(reg, 1)
        # 每个重要寄存器控制奖励2分，上限20分
        score += min(reg_score * 2, 20)
        
        # 副作用惩罚（直接减分）
        side_effect_penalty = 0
        for effect in gadget.side_effects:
            side_effect_penalty += abs(self.SIDE_EFFECT_PENALTIES.get(effect, -5))
        score -= side_effect_penalty
        
        # 栈消耗惩罚（每8字节减1分，上限10分）
        stack_penalty = min(gadget.stack_consumption / 8, 10)
        score -= stack_penalty
        
        # 长度奖励（短指令奖励）
        length = len(gadget.instruction)
        if length < 15:
            score += 5
        elif length < 25:
            score += 2
        
        # 确保评分在0-100范围内
        score = max(0, min(100, score))
        
        return score
    
    def determine_quality(self, gadget: ROPGadget) -> GadgetQuality:
        """
        确定Gadget质量
        
        Args:
            gadget: ROP Gadget
            
        Returns:
            Gadget质量
        """
        score = gadget.score
        
        if score >= 80:
            return GadgetQuality.EXCELLENT
        elif score >= 60:
            return GadgetQuality.GOOD
        elif score >= 40:
            return GadgetQuality.MODERATE
        elif score >= 20:
            return GadgetQuality.POOR
        else:
            return GadgetQuality.USELESS
    
    def grade_all_gadgets(self) -> List[ROPGadget]:
        """
        对所有Gadget进行分级
        
        Returns:
            分级后的Gadget列表
        """
        for gadget in self.gadgets:
            # 分类
            gadget.category = self.classify_gadget(gadget)
            
            # 分析寄存器
            affected, preserved = self.analyze_registers(gadget)
            gadget.affected_regs = affected
            gadget.preserved_regs = preserved
            
            # 计算栈消耗
            gadget.stack_consumption = self.calculate_stack_consumption(gadget)
            
            # 检测副作用
            gadget.side_effects = self.detect_side_effects(gadget)
            
            # 计算评分
            gadget.score = self.calculate_score(gadget)
            
            # 确定质量
            gadget.quality = self.determine_quality(gadget)
        
        # 排名
        self.ranked_gadgets = sorted(self.gadgets, key=lambda g: g.score, reverse=True)
        
        for i, gadget in enumerate(self.ranked_gadgets):
            gadget.rank = i + 1
        
        logger.info(f"[ROPGrader] 完成分级，最高评分: {self.ranked_gadgets[0].score if self.ranked_gadgets else 0}")
        
        return self.ranked_gadgets
    
    def suggest_chains(self) -> List[GadgetChain]:
        """
        建议Gadget链
        
        Returns:
            建议的Gadget链列表
        """
        self.suggested_chains = []
        
        # 筛选可用Gadget（包括EXCELLENT, GOOD, MODERATE）
        excellent_gadgets = [g for g in self.ranked_gadgets if g.quality == GadgetQuality.EXCELLENT]
        good_gadgets = [g for g in self.ranked_gadgets if g.quality == GadgetQuality.GOOD]
        moderate_gadgets = [g for g in self.ranked_gadgets if g.quality == GadgetQuality.MODERATE]
        
        usable_gadgets = excellent_gadgets + good_gadgets + moderate_gadgets
        
        if not usable_gadgets:
            # 如果没有可用gadget，尝试使用所有ranked_gadgets
            usable_gadgets = self.ranked_gadgets[:5] if self.ranked_gadgets else []
            if not usable_gadgets:
                return self.suggested_chains
        
        # 建议栈迁移链
        stack_pivots = [g for g in usable_gadgets if g.category == GadgetCategory.STACK_PIVOT]
        if stack_pivots:
            chain = GadgetChain(
                gadgets=[stack_pivots[0]],
                purpose='栈迁移',
                total_stack_consumption=stack_pivots[0].stack_consumption,
                overall_score=stack_pivots[0].score,
                feasibility=0.9,
                description='使用栈迁移Gadget将栈指针指向可控区域',
            )
            self.suggested_chains.append(chain)
        
        # 建议寄存器控制链
        reg_controls = [g for g in usable_gadgets if g.category == GadgetCategory.REG_CONTROL]
        if len(reg_controls) >= 1:
            # 选择控制重要寄存器的Gadget
            important_regs = self.config.important_registers[:3]
            selected = []
            for reg in important_regs:
                for g in reg_controls:
                    if reg in g.affected_regs and g not in selected:
                        selected.append(g)
                        break
            
            if selected:
                chain = GadgetChain(
                    gadgets=selected,
                    purpose='寄存器控制',
                    total_stack_consumption=sum(g.stack_consumption for g in selected),
                    overall_score=sum(g.score for g in selected) / len(selected),
                    feasibility=0.8,
                    description=f'设置关键寄存器: {", ".join(important_regs[:len(selected)])}',
                )
                self.suggested_chains.append(chain)
        
        # 建议系统调用链
        syscalls = [g for g in usable_gadgets if g.category == GadgetCategory.SYSCALL]
        if syscalls:
            # 需要配合寄存器控制
            chain = GadgetChain(
                gadgets=syscalls[:1],
                purpose='系统调用',
                total_stack_consumption=syscalls[0].stack_consumption,
                overall_score=syscalls[0].score,
                feasibility=0.7,
                description='执行系统调用，需要预先设置rax（调用号）和参数寄存器',
            )
            self.suggested_chains.append(chain)
        
        # 建议内存写入链
        mem_writes = [g for g in usable_gadgets if g.category == GadgetCategory.MEM_ACCESS]
        if mem_writes:
            chain = GadgetChain(
                gadgets=mem_writes[:1],
                purpose='内存写入',
                total_stack_consumption=mem_writes[0].stack_consumption,
                overall_score=mem_writes[0].score,
                feasibility=0.6,
                description='向指定内存地址写入数据',
            )
            self.suggested_chains.append(chain)
        
        logger.info(f"[ROPGrader] 生成了 {len(self.suggested_chains)} 个建议链")
        
        return self.suggested_chains
    
    def get_top_gadgets(self, n: int = 10) -> List[ROPGadget]:
        """
        获取评分最高的N个Gadget
        
        Args:
            n: 数量
            
        Returns:
            Top N Gadget列表
        """
        return self.ranked_gadgets[:n]
    
    def get_gadgets_by_category(self, category: GadgetCategory) -> List[ROPGadget]:
        """
        获取指定类别的Gadget
        
        Args:
            category: Gadget类别
            
        Returns:
            该类别的Gadget列表
        """
        return [g for g in self.ranked_gadgets if g.category == category]
    
    def get_gadgets_by_register(self, register: str) -> List[ROPGadget]:
        """
        获取控制指定寄存器的Gadget
        
        Args:
            register: 寄存器名称
            
        Returns:
            控制该寄存器的Gadget列表
        """
        return [g for g in self.ranked_gadgets if register in g.affected_regs]
    
    def generate_report(self) -> Dict[str, Any]:
        """
        生成分级报告
        
        Returns:
            报告字典
        """
        report = {
            'analysis_time': datetime.now().isoformat(),
            'total_gadgets': len(self.gadgets),
            'graded_gadgets': len(self.ranked_gadgets),
            'quality_distribution': self._get_quality_distribution(),
            'category_distribution': self._get_category_distribution(),
            'top_gadgets': [g.to_dict() for g in self.get_top_gadgets(10)],
            'suggested_chains': [c.to_dict() for c in self.suggested_chains],
            'statistics': self._get_statistics(),
            'recommendations': self._generate_recommendations(),
        }
        
        return report
    
    def _get_quality_distribution(self) -> Dict[str, int]:
        """
        获取质量分布
        
        Returns:
            质量分布字典
        """
        distribution = {}
        for quality in GadgetQuality:
            count = sum(1 for g in self.ranked_gadgets if g.quality == quality)
            distribution[quality.value] = count
        return distribution
    
    def _get_category_distribution(self) -> Dict[str, int]:
        """
        获取类别分布
        
        Returns:
            类别分布字典
        """
        distribution = {}
        for category in GadgetCategory:
            count = sum(1 for g in self.ranked_gadgets if g.category == category)
            distribution[category.value] = count
        return distribution
    
    def _get_statistics(self) -> Dict[str, Any]:
        """
        获取统计数据
        
        Returns:
            统计数据字典
        """
        if not self.ranked_gadgets:
            return {}
        
        scores = [g.score for g in self.ranked_gadgets]
        
        return {
            'avg_score': sum(scores) / len(scores),
            'max_score': max(scores),
            'min_score': min(scores),
            'avg_stack_consumption': sum(g.stack_consumption for g in self.ranked_gadgets) / len(self.ranked_gadgets),
        }
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 检查栈迁移Gadget
        stack_pivots = self.get_gadgets_by_category(GadgetCategory.STACK_PIVOT)
        if not stack_pivots:
            recommendations.append("缺少栈迁移Gadget，可能需要寻找其他方式控制栈指针")
        else:
            recommendations.append(f"发现 {len(stack_pivots)} 个栈迁移Gadget，优先使用评分最高的")
        
        # 检查系统调用Gadget
        syscalls = self.get_gadgets_by_category(GadgetCategory.SYSCALL)
        if syscalls:
            recommendations.append(f"发现 {len(syscalls)} 个系统调用Gadget，可用于构造系统调用利用链")
        
        # 检查重要寄存器控制
        for reg in self.config.important_registers[:3]:
            reg_gadgets = self.get_gadgets_by_register(reg)
            if not reg_gadgets:
                recommendations.append(f"缺少控制 {reg} 寄存器的Gadget，可能影响参数设置")
        
        # 检查整体质量
        excellent_count = sum(1 for g in self.ranked_gadgets if g.quality == GadgetQuality.EXCELLENT)
        if excellent_count < 5:
            recommendations.append("高质量Gadget数量较少，可能需要扩大搜索范围")
        
        return recommendations
    
    def save_report(self, output_path: Optional[str] = None) -> str:
        """
        保存分级报告
        
        Args:
            output_path: 输出路径
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            output_dir = './reports/rop'
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"rop_grading_report_{timestamp}.json"
            output_path = os.path.join(output_dir, filename)
        
        report = self.generate_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[ROPGrader] 报告已保存: {output_path}")
        return output_path
    
    def analyze(self, gadgets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行完整分析
        
        Args:
            gadgets: Gadget列表
            
        Returns:
            分析结果
        """
        # 加载Gadget
        self.load_gadgets(gadgets)
        
        # 分级
        self.grade_all_gadgets()
        
        # 建议链
        self.suggest_chains()
        
        # 生成报告
        report = self.generate_report()
        
        return report


def create_rop_grader(**kwargs) -> ROPGadgetGrader:
    """
    创建ROP Gadget分级器的便捷函数
    
    Args:
        **kwargs: 配置参数
        
    Returns:
        ROPGadgetGrader实例
    """
    config = GradingConfig(**kwargs)
    return ROPGadgetGrader(config)