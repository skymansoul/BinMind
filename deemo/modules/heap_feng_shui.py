"""
自动化堆风水策略生成模块

针对堆漏洞（堆溢出、UAF等）和不同分配器（ptmalloc/jemalloc），自动生成堆风水操作序列，
操纵堆布局至利于利用的状态，提升复杂堆漏洞利用成功率。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import random
import string
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class AllocatorType(Enum):
    """分配器类型枚举"""
    PTMALLOC = "ptmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_POINTER_DEREF = "null_pointer_deref"
    USE_AFTER_REALLOC = "use_after_realloc"


class FengShuiAction(Enum):
    """堆风水操作类型"""
    ALLOC = "alloc"
    FREE = "free"
    WRITE = "write"
    FILL_TCACHE = "fill_tcache"
    CONSOLIDATE = "consolidate"
    SPLIT = "split"


@dataclass
class HeapChunk:
    """堆块信息"""
    size: int
    address: Optional[int] = None
    in_use: bool = True
    fd: Optional[int] = None
    bk: Optional[int] = None
    tcache_next: Optional[int] = None
    arena: Optional[int] = None
    content: bytes = b""


@dataclass
class FengShuiStep:
    """堆风水步骤"""
    action: FengShuiAction
    size: Optional[int] = None
    content: Optional[str] = None
    comment: str = ""
    chunk_id: Optional[int] = None


@dataclass
class FengShuiStrategy:
    """堆风水策略结果"""
    steps: List[FengShuiStep] = field(default_factory=list)
    target_layout: str = ""
    success_probability: float = 0.0
    estimated_time: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class FengShuiConfig:
    """堆风水配置"""
    allocator: AllocatorType = AllocatorType.PTMALLOC
    libc_version: str = "2.31"
    target_size: int = 0
    overflow_size: int = 0
    num_frees: int = 0
    enable_tcache: bool = True
    tcache_count: int = 7
    arena_count: int = 1
    use_fastbin: bool = True


class HeapFengShuiStrategist:
    """
    堆风水策略生成器
    
    根据漏洞类型和分配器特点，自动生成堆风水操作序列。
    """
    
    def __init__(self, config: Optional[FengShuiConfig] = None):
        """
        初始化策略生成器
        
        Args:
            config: 堆风水配置，若为None则使用默认配置
        """
        self.config = config or FengShuiConfig()
        self.chunks: List[HeapChunk] = []
        self.current_chunk_id = 0
        
    def generate_strategy(self, vuln_type: VulnerabilityType, 
                         target_struct_size: int,
                         additional_constraints: Optional[Dict[str, Any]] = None) -> FengShuiStrategy:
        """
        生成堆风水策略
        
        Args:
            vuln_type: 漏洞类型
            target_struct_size: 目标结构体大小
            additional_constraints: 额外约束条件
            
        Returns:
            堆风水策略对象
        """
        if vuln_type == VulnerabilityType.USE_AFTER_FREE:
            strategy = self._generate_uaf_strategy(target_struct_size, additional_constraints)
        elif vuln_type == VulnerabilityType.HEAP_OVERFLOW:
            strategy = self._generate_overflow_strategy(target_struct_size, additional_constraints)
        elif vuln_type == VulnerabilityType.DOUBLE_FREE:
            strategy = self._generate_double_free_strategy(target_struct_size, additional_constraints)
        else:
            strategy = self._generate_generic_strategy(target_struct_size, additional_constraints)
        
        # 添加元信息到notes（在策略生成之后添加，避免被覆盖）
        strategy.notes.insert(0, f"漏洞类型: {vuln_type.value}")
        strategy.notes.insert(1, f"目标结构体大小: {target_struct_size} bytes")
        strategy.notes.insert(2, f"分配器: {self.config.allocator.value}")
        strategy.notes.insert(3, f"libc版本: {self.config.libc_version}")
            
        strategy.success_probability = self._calculate_success_probability(strategy)
        strategy.target_layout = self._describe_target_layout(target_struct_size)
        
        return strategy
    
    def _generate_uaf_strategy(self, target_size: int, constraints: Optional[Dict[str, Any]]) -> FengShuiStrategy:
        """
        生成UAF漏洞的堆风水策略
        
        UAF漏洞需要：
        1. 分配目标chunk
        2. 释放该chunk（触发漏洞条件）
        3. 在该chunk被重用前进行风水操作
        4. 确保malloc返回已释放的chunk
        """
        strategy = FengShuiStrategy()
        steps = []
        
        # 步骤1: 填充tcache防止目标chunk进入tcache
        if self.config.enable_tcache:
            steps.append(FengShuiStep(
                action=FengShuiAction.FILL_TCACHE,
                size=target_size,
                comment="填充tcache防止目标chunk被快速重用"
            ))
        
        # 步骤2: 分配目标chunk
        chunk_id = self._next_chunk_id()
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=target_size,
            chunk_id=chunk_id,
            comment=f"分配目标chunk #{chunk_id}"
        ))
        
        # 步骤3: 分配guard chunk保护目标chunk
        guard_id = self._next_chunk_id()
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=target_size,
            chunk_id=guard_id,
            comment=f"分配guard chunk #{guard_id}保护目标chunk"
        ))
        
        # 步骤4: 释放guard chunk（可能放入tcache）
        steps.append(FengShuiStep(
            action=FengShuiAction.FREE,
            chunk_id=guard_id,
            comment=f"释放guard chunk #{guard_id}"
        ))
        
        # 步骤5: 释放目标chunk（触发UAF条件）
        steps.append(FengShuiStep(
            action=FengShuiAction.FREE,
            chunk_id=chunk_id,
            comment=f"释放目标chunk #{chunk_id} - 触发UAF条件"
        ))
        
        # 步骤6: 调整堆布局，使目标chunk进入unsorted bin或fastbin
        if target_size <= 0x80 and self.config.use_fastbin:
            steps.append(FengShuiStep(
                action=FengShuiAction.ALLOC,
                size=0x90,
                comment="分配大chunk触发fastbin整理"
            ))
        
        strategy.steps = steps
        strategy.notes.append("策略: UAF标准风水流程")
        strategy.notes.append("目标: 将释放的chunk控制到可预测位置")
        
        return strategy
    
    def _generate_overflow_strategy(self, target_size: int, constraints: Optional[Dict[str, Any]]) -> FengShuiStrategy:
        """
        生成堆溢出漏洞的堆风水策略
        
        堆溢出需要：
        1. 控制相邻chunk的元数据
        2. 可能需要绕过tcache的double free检测
        3. 构造fake chunk
        """
        strategy = FengShuiStrategy()
        steps = []
        
        # 步骤1: 分配溢出目标chunk
        target_chunk = self._next_chunk_id()
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=target_size,
            chunk_id=target_chunk,
            comment=f"分配目标chunk #{target_chunk}"
        ))
        
        # 步骤2: 分配相邻chunk（将被溢出覆盖）
        victim_chunk = self._next_chunk_id()
        victim_size = self._get_optimal_victim_size(target_size)
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=victim_size,
            chunk_id=victim_chunk,
            comment=f"分配相邻victim chunk #{victim_chunk}"
        ))
        
        # 步骤3: 如果启用tcache，可能需要填充tcache
        if self.config.enable_tcache:
            for i in range(self.config.tcache_count):
                filler_chunk = self._next_chunk_id()
                steps.append(FengShuiStep(
                    action=FengShuiAction.ALLOC,
                    size=victim_size,
                    chunk_id=filler_chunk,
                    comment=f"分配tcache填充chunk #{filler_chunk}"
                ))
        
        # 步骤4: 释放victim chunk使其进入tcache
        steps.append(FengShuiStep(
            action=FengShuiAction.FREE,
            chunk_id=victim_chunk,
            comment=f"释放victim chunk #{victim_chunk}到tcache"
        ))
        
        # 步骤5: 执行溢出操作（由漏洞触发）
        steps.append(FengShuiStep(
            action=FengShuiAction.WRITE,
            content="overflow_payload",
            chunk_id=target_chunk,
            comment=f"通过漏洞溢出覆盖victim chunk元数据"
        ))
        
        # 步骤6: 分配新chunk获取控制
        new_chunk = self._next_chunk_id()
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=victim_size,
            chunk_id=new_chunk,
            comment=f"分配新chunk #{new_chunk}获取控制"
        ))
        
        strategy.steps = steps
        strategy.notes.append("策略: 堆溢出标准风水流程")
        strategy.notes.append("目标: 控制victim chunk的fd指针")
        
        return strategy
    
    def _generate_double_free_strategy(self, target_size: int, constraints: Optional[Dict[str, Any]]) -> FengShuiStrategy:
        """
        生成double free漏洞的堆风水策略
        
        Double free需要：
        1. 绕过tcache的检测（tcache会检测double free）
        2. 构造循环链表
        """
        strategy = FengShuiStrategy()
        steps = []
        
        # 步骤1: 如果启用tcache，先填充tcache
        if self.config.enable_tcache:
            for i in range(self.config.tcache_count):
                filler_chunk = self._next_chunk_id()
                steps.append(FengShuiStep(
                    action=FengShuiAction.ALLOC,
                    size=target_size,
                    chunk_id=filler_chunk,
                    comment=f"分配tcache填充chunk #{filler_chunk}"
                ))
        
        # 步骤2: 分配目标chunk
        target_chunk = self._next_chunk_id()
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=target_size,
            chunk_id=target_chunk,
            comment=f"分配目标chunk #{target_chunk}"
        ))
        
        # 步骤3: 第一次释放（如果tcache已满，进入unsorted bin）
        steps.append(FengShuiStep(
            action=FengShuiAction.FREE,
            chunk_id=target_chunk,
            comment=f"第一次释放chunk #{target_chunk}"
        ))
        
        # 步骤4: 第二次释放（double free）
        steps.append(FengShuiStep(
            action=FengShuiAction.FREE,
            chunk_id=target_chunk,
            comment=f"第二次释放chunk #{target_chunk} - double free"
        ))
        
        # 步骤5: 分配两次获取控制
        for i in range(2):
            new_chunk = self._next_chunk_id()
            steps.append(FengShuiStep(
                action=FengShuiAction.ALLOC,
                size=target_size,
                chunk_id=new_chunk,
                comment=f"第{i+1}次分配获取chunk #{new_chunk}"
            ))
        
        strategy.steps = steps
        strategy.notes.append("策略: Double Free标准风水流程")
        strategy.notes.append("目标: 构造循环链表实现任意地址写")
        
        return strategy
    
    def _generate_generic_strategy(self, target_size: int, constraints: Optional[Dict[str, Any]]) -> FengShuiStrategy:
        """
        生成通用堆风水策略
        """
        strategy = FengShuiStrategy()
        steps = []
        
        # 基础风水操作
        steps.append(FengShuiStep(
            action=FengShuiAction.ALLOC,
            size=target_size,
            chunk_id=self._next_chunk_id(),
            comment="分配目标chunk"
        ))
        
        strategy.steps = steps
        strategy.notes.append("策略: 通用堆风水流程")
        
        return strategy
    
    def _calculate_success_probability(self, strategy: FengShuiStrategy) -> float:
        """
        计算策略成功概率
        
        Returns:
            成功概率（0-1）
        """
        base_prob = 0.7
        
        # 根据步骤复杂度调整
        if len(strategy.steps) <= 5:
            base_prob += 0.15
        elif len(strategy.steps) <= 10:
            base_prob += 0.05
        else:
            base_prob -= 0.1
            
        # 根据分配器类型调整
        if self.config.allocator == AllocatorType.PTMALLOC:
            base_prob += 0.1
        elif self.config.allocator == AllocatorType.JEMALLOC:
            base_prob -= 0.1
            
        # 根据libc版本调整（新版本更难利用）
        version_num = float(self.config.libc_version.split(".")[1])
        if version_num >= 34:
            base_prob -= 0.1
            
        return min(1.0, max(0.0, base_prob))
    
    def _describe_target_layout(self, target_size: int) -> str:
        """
        描述目标堆布局
        
        Returns:
            布局描述字符串
        """
        layouts = []
        
        if self.config.enable_tcache:
            layouts.append(f"tcache[{target_size}]: 已填充")
        
        layouts.append(f"目标chunk: {target_size} bytes")
        layouts.append(f"arena数量: {self.config.arena_count}")
        
        return "; ".join(layouts)
    
    def _next_chunk_id(self) -> int:
        """获取下一个chunk ID"""
        self.current_chunk_id += 1
        return self.current_chunk_id
    
    def _get_optimal_victim_size(self, target_size: int) -> int:
        """
        获取最优的victim chunk大小
        
        通常选择与target_size相同或相近的大小，便于溢出覆盖
        """
        # 选择相近的bin大小
        bin_sizes = [0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0]
        for size in bin_sizes:
            if size >= target_size:
                return size
        return target_size
    
    def generate_c_code(self, strategy: FengShuiStrategy, variable_prefix: str = "heap") -> str:
        """
        生成C代码实现堆风水策略
        
        Args:
            strategy: 堆风水策略
            variable_prefix: 变量名前缀
            
        Returns:
            C代码字符串
        """
        code_lines = []
        code_lines.append("// 自动生成的堆风水代码")
        code_lines.append("// 策略成功率: {:.1%}".format(strategy.success_probability))
        code_lines.append("")
        code_lines.append("#include <stdlib.h>")
        code_lines.append("#include <string.h>")
        code_lines.append("")
        code_lines.append("// 全局指针数组")
        code_lines.append(f"void *{variable_prefix}_chunks[64] = {{NULL}};")
        code_lines.append(f"int {variable_prefix}_idx = 0;")
        code_lines.append("")
        code_lines.append("// 辅助函数")
        code_lines.append(f"static void *{variable_prefix}_alloc(size_t size) {{")
        code_lines.append(f"    void *ptr = malloc(size);")
        code_lines.append(f"    if (ptr) {{")
        code_lines.append(f"        {variable_prefix}_chunks[{variable_prefix}_idx++] = ptr;")
        code_lines.append(f"    }}")
        code_lines.append(f"    return ptr;")
        code_lines.append(f"}}")
        code_lines.append("")
        code_lines.append(f"static void {variable_prefix}_free(int idx) {{")
        code_lines.append(f"    if ({variable_prefix}_chunks[idx]) {{")
        code_lines.append(f"        free({variable_prefix}_chunks[idx]);")
        code_lines.append(f"        {variable_prefix}_chunks[idx] = NULL;")
        code_lines.append(f"    }}")
        code_lines.append(f"}}")
        code_lines.append("")
        code_lines.append("// 堆风水主函数")
        code_lines.append(f"void {variable_prefix}_fengshui(void) {{")
        
        chunk_map = {}
        for step in strategy.steps:
            if step.chunk_id and step.chunk_id not in chunk_map:
                chunk_map[step.chunk_id] = len(chunk_map)
            
            if step.action == FengShuiAction.ALLOC:
                if step.chunk_id:
                    var_idx = chunk_map[step.chunk_id]
                    code_lines.append(f"    // {step.comment}")
                    code_lines.append(f"    {variable_prefix}_alloc({step.size});")
            elif step.action == FengShuiAction.FREE:
                if step.chunk_id:
                    var_idx = chunk_map.get(step.chunk_id, 0)
                    code_lines.append(f"    // {step.comment}")
                    code_lines.append(f"    {variable_prefix}_free({var_idx});")
            elif step.action == FengShuiAction.WRITE:
                if step.chunk_id:
                    var_idx = chunk_map.get(step.chunk_id, 0)
                    code_lines.append(f"    // {step.comment}")
                    code_lines.append(f"    // memcpy({variable_prefix}_chunks[{var_idx}], payload, size);")
            elif step.action == FengShuiAction.FILL_TCACHE:
                code_lines.append(f"    // {step.comment}")
                code_lines.append(f"    for (int i = 0; i < 7; i++) {{")
                code_lines.append(f"        {variable_prefix}_alloc({step.size});")
                code_lines.append(f"    }}")
        
        code_lines.append(f"}}")
        
        return "\n".join(code_lines)
    
    def generate_python_code(self, strategy: FengShuiStrategy) -> str:
        """
        生成Python代码实现堆风水策略（用于pwntools）
        
        Args:
            strategy: 堆风水策略
            
        Returns:
            Python代码字符串
        """
        code_lines = []
        code_lines.append("# 自动生成的堆风水代码")
        code_lines.append("# 策略成功率: {:.1%}".format(strategy.success_probability))
        code_lines.append("# 建议使用pwntools的malloc/free包装")
        code_lines.append("")
        code_lines.append("def fengshui(io):")
        code_lines.append("    \"\"\"堆风水操作序列\"\"\"")
        code_lines.append("    chunks = []")
        code_lines.append("")
        
        for step in strategy.steps:
            if step.action == FengShuiAction.ALLOC:
                code_lines.append(f"    # {step.comment}")
                code_lines.append(f"    ptr = malloc({step.size})")
                code_lines.append(f"    chunks.append(ptr)")
            elif step.action == FengShuiAction.FREE:
                code_lines.append(f"    # {step.comment}")
                code_lines.append(f"    free(chunks[{step.chunk_id - 1}])")
            elif step.action == FengShuiAction.WRITE:
                code_lines.append(f"    # {step.comment}")
                code_lines.append(f"    # io.sendafter('>', p64(payload))")
            elif step.action == FengShuiAction.FILL_TCACHE:
                code_lines.append(f"    # {step.comment}")
                code_lines.append(f"    for _ in range(7):")
                code_lines.append(f"        malloc({step.size})")
        
        code_lines.append("")
        code_lines.append("    return chunks")
        
        return "\n".join(code_lines)
    
    def simulate_heap_layout(self, strategy: FengShuiStrategy) -> str:
        """
        模拟堆布局变化
        
        Args:
            strategy: 堆风水策略
            
        Returns:
            布局描述字符串
        """
        layout = ["堆布局模拟:"]
        
        current_addr = 0x555555554000  # 虚拟地址起始
        for step in strategy.steps:
            if step.action == FengShuiAction.ALLOC and step.size:
                layout.append(f"  [ALLOC] 地址: 0x{current_addr:012x}, 大小: 0x{step.size:x}, ID: #{step.chunk_id}")
                current_addr += step.size + 0x10  # 加上chunk头
            elif step.action == FengShuiAction.FREE and step.chunk_id:
                layout.append(f"  [FREE] 释放 chunk #{step.chunk_id}")
        
        return "\n".join(layout)


def generate_fengshui_strategy(vuln_type: str, 
                              allocator: str = "ptmalloc",
                              libc_version: str = "2.31",
                              target_size: int = 0x80) -> FengShuiStrategy:
    """
    便捷函数：生成堆风水策略
    
    Args:
        vuln_type: 漏洞类型字符串
        allocator: 分配器类型
        libc_version: libc版本
        target_size: 目标大小
        
    Returns:
        堆风水策略对象
    """
    config = FengShuiConfig(
        allocator=AllocatorType(allocator),
        libc_version=libc_version,
        target_size=target_size
    )
    
    strategist = HeapFengShuiStrategist(config)
    
    vuln_enum = VulnerabilityType(vuln_type)
    return strategist.generate_strategy(vuln_enum, target_size)
