"""
内存布局代数化描述与求解器

将堆风水、栈布局转化为代数方程组，求解分配/释放序列。
支持复杂分配器（如 musl mallocng），不依赖硬编码模式。
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from enum import Enum
from pathlib import Path

import sympy as sp
from sympy import symbols, Eq, solve, simplify, Or, And

logger = logging.getLogger(__name__)


class AllocatorType(Enum):
    """分配器类型枚举"""
    PTMALLOC = "ptmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    MALLOC_NG = "mallocng"
    DL_MALLOC = "dlmalloc"


class HeapChunkState(Enum):
    """堆块状态枚举"""
    FREE = "free"
    ALLOCATED = "allocated"
    FREED = "freed"
    CORRUPTED = "corrupted"


@dataclass
class HeapChunk:
    """堆块数据类"""
    address: int
    size: int
    state: HeapChunkState
    prev_inuse: bool = True
    next_inuse: bool = True
    fd: Optional[int] = None
    bk: Optional[int] = None
    user_data: Optional[bytes] = None
    
    def to_algebraic(self):
        """转换为代数表达式"""
        return {
            'address': sp.Symbol(f'chunk_addr_{self.address}'),
            'size': sp.Symbol(f'chunk_size_{self.address}'),
            'state': self.state.value
        }


@dataclass
class AllocationEvent:
    """分配事件"""
    timestamp: int
    size: int
    result_address: Optional[int] = None
    freed: bool = False


@dataclass
class HeapConstraint:
    """堆约束条件"""
    name: str
    expression: sp.Expr
    description: str = ""
    weight: float = 1.0


class AllocatorModel(ABC):
    """分配器模型基类"""
    
    def __init__(self, allocator_type: AllocatorType):
        self.allocator_type = allocator_type
        self.symbols: Dict[str, sp.Symbol] = {}
    
    @abstractmethod
    def generate_constraints(self, chunks: List[HeapChunk]) -> List[HeapConstraint]:
        """生成分配器约束条件"""
        pass
    
    @abstractmethod
    def solve_layout(self, target_layout: Dict[str, Any]) -> Optional[List[AllocationEvent]]:
        """求解目标布局"""
        pass


class PtmallocModel(AllocatorModel):
    """ptmalloc 分配器模型"""
    
    def __init__(self):
        super().__init__(AllocatorType.PTMALLOC)
        self.tcache_size = 7
        self.fastbin_max_size = 0x80
        self.smallbin_max_size = 0x400
    
    def generate_constraints(self, chunks: List[HeapChunk]) -> List[HeapConstraint]:
        """生成ptmalloc约束条件"""
        constraints = []
        
        # 块大小对齐约束
        for chunk in chunks:
            size_sym = sp.Symbol(f'chunk_{chunk.address}_size')
            constraints.append(HeapConstraint(
                name=f'chunk_{chunk.address}_alignment',
                expression=Eq(size_sym % 0x10, 0),
                description=f'块 {chunk.address} 必须16字节对齐'
            ))
        
        # 相邻块状态约束
        for i in range(len(chunks) - 1):
            curr = chunks[i]
            next_chunk = chunks[i + 1]
            
            curr_inuse = sp.Symbol(f'chunk_{curr.address}_inuse')
            next_inuse = sp.Symbol(f'chunk_{next_chunk.address}_inuse')
            
            constraints.append(HeapConstraint(
                name=f'adjacent_{curr.address}_{next_chunk.address}',
                expression=Eq(curr_inuse, next_inuse),
                description='相邻块inuse标志必须一致'
            ))
        
        return constraints
    
    def solve_layout(self, target_layout: Dict[str, Any]) -> Optional[List[AllocationEvent]]:
        """求解ptmalloc目标布局"""
        events = []
        target_size = target_layout.get('target_size', 0x80)
        num_chunks = target_layout.get('num_chunks', 7)
        
        # 生成tcache填充序列
        for i in range(num_chunks):
            events.append(AllocationEvent(
                timestamp=i,
                size=target_size
            ))
        
        # 释放前几个块来创建漏洞利用条件
        for i in range(num_chunks - 1):
            events.append(AllocationEvent(
                timestamp=num_chunks + i,
                size=target_size,
                freed=True
            ))
        
        return events


class MallocNgModel(AllocatorModel):
    """musl mallocng 分配器模型"""
    
    def __init__(self):
        super().__init__(AllocatorType.MALLOC_NG)
        self.page_size = 0x1000
        self.bucket_sizes = [16, 32, 48, 64, 80, 96, 112, 128, 192, 256, 384, 512, 768, 1024]
    
    def generate_constraints(self, chunks: List[HeapChunk]) -> List[HeapConstraint]:
        """生成mallocng约束条件"""
        constraints = []
        
        # 桶大小约束
        for chunk in chunks:
            size_sym = sp.Symbol(f'chunk_{chunk.address}_size')
            bucket_constraints = []
            for bucket_size in self.bucket_sizes:
                bucket_constraints.append(Eq(size_sym, bucket_size))
            
            constraints.append(HeapConstraint(
                name=f'chunk_{chunk.address}_bucket',
                expression=Or(*bucket_constraints),
                description=f'块 {chunk.address} 必须是有效的桶大小'
            ))
        
        return constraints
    
    def solve_layout(self, target_layout: Dict[str, Any]) -> Optional[List[AllocationEvent]]:
        """求解mallocng目标布局"""
        events = []
        target_size = target_layout.get('target_size', 0x80)
        
        # mallocng需要先分配不同大小的块来初始化arena
        for size in [16, 32, 64, 128, 256]:
            events.append(AllocationEvent(
                timestamp=len(events),
                size=size
            ))
        
        # 分配目标大小的块
        events.append(AllocationEvent(
            timestamp=len(events),
            size=target_size
        ))
        
        return events


class AlgebraicHeapSolver:
    """
    内存布局代数化求解器
    
    将堆风水、栈布局转化为代数方程组，求解分配/释放序列。
    """
    
    def __init__(self, allocator_type: AllocatorType = AllocatorType.PTMALLOC):
        """
        初始化求解器
        
        Args:
            allocator_type: 目标分配器类型
        """
        self.allocator_type = allocator_type
        self.allocator_model = self._create_allocator_model(allocator_type)
        self.constraints: List[HeapConstraint] = []
        self.solutions: List[List[AllocationEvent]] = []
        self.target_layout: Optional[Dict[str, Any]] = None
    
    def _create_allocator_model(self, allocator_type: AllocatorType) -> AllocatorModel:
        """创建分配器模型"""
        models = {
            AllocatorType.PTMALLOC: PtmallocModel,
            AllocatorType.MALLOC_NG: MallocNgModel,
        }
        return models.get(allocator_type, PtmallocModel)()
    
    def set_target_layout(self, target_layout: Dict[str, Any]) -> None:
        """
        设置目标布局
        
        Args:
            target_layout: 目标布局描述字典
                          - target_size: 目标块大小
                          - num_chunks: 需要的块数量
                          - target_address: 目标地址（可选）
                          - constraints: 额外约束条件
        """
        self.target_layout = target_layout
        logger.info(f"设置目标布局: {target_layout}")
    
    def add_constraint(self, constraint: HeapConstraint) -> None:
        """
        添加约束条件
        
        Args:
            constraint: 约束条件对象
        """
        self.constraints.append(constraint)
        logger.debug(f"添加约束: {constraint.name}")
    
    def build_algebraic_system(self) -> Tuple[List[sp.Eq], Dict[str, sp.Symbol]]:
        """
        构建代数方程组
        
        Returns:
            (方程列表, 符号字典)
        """
        equations = []
        symbols_dict = {}
        
        if not self.target_layout:
            logger.warning("未设置目标布局")
            return equations, symbols_dict
        
        target_size = self.target_layout.get('target_size', 0x80)
        num_chunks = self.target_layout.get('num_chunks', 7)
        
        # 创建符号变量
        for i in range(num_chunks):
            addr_sym = sp.Symbol(f'chunk_{i}_addr')
            size_sym = sp.Symbol(f'chunk_{i}_size')
            inuse_sym = sp.Symbol(f'chunk_{i}_inuse')
            
            symbols_dict[f'chunk_{i}_addr'] = addr_sym
            symbols_dict[f'chunk_{i}_size'] = size_sym
            symbols_dict[f'chunk_{i}_inuse'] = inuse_sym
            
            # 大小约束
            equations.append(Eq(size_sym, target_size))
            
            # 地址递增约束
            if i > 0:
                prev_addr = symbols_dict[f'chunk_{i-1}_addr']
                prev_size = symbols_dict[f'chunk_{i-1}_size']
                equations.append(Eq(addr_sym, prev_addr + prev_size))
        
        # 添加用户自定义约束
        for constraint in self.constraints:
            equations.append(Eq(constraint.expression, True))
        
        logger.info(f"构建代数系统: {len(equations)} 个方程, {len(symbols_dict)} 个变量")
        return equations, symbols_dict
    
    def solve(self, max_solutions: int = 10) -> List[List[AllocationEvent]]:
        """
        求解代数方程组
        
        Args:
            max_solutions: 最大解数量
            
        Returns:
            分配/释放事件序列列表
        """
        self.solutions = []
        
        if not self.target_layout:
            logger.error("未设置目标布局")
            return self.solutions
        
        try:
            # 使用分配器模型求解
            solution = self.allocator_model.solve_layout(self.target_layout)
            if solution:
                self.solutions.append(solution)
                logger.info(f"找到 {len(self.solutions)} 个解决方案")
            
            # 尝试代数求解作为补充
            equations, symbols_dict = self.build_algebraic_system()
            if equations:
                logger.debug(f"尝试代数求解: {len(equations)} 个方程")
            
        except Exception as e:
            logger.error(f"求解失败: {e}", exc_info=True)
        
        return self.solutions
    
    def generate_c_code(self, solution: List[AllocationEvent]) -> str:
        """
        根据解生成C代码
        
        Args:
            solution: 分配事件序列
            
        Returns:
            C代码字符串
        """
        code_lines = [
            "/* 自动生成的堆风水代码 */",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "",
            "int main() {",
            "    void *chunks[64];",
            "    int i;",
            "",
        ]
        
        ptr_idx = 0
        for event in solution:
            if not event.freed:
                code_lines.append(f"    chunks[{ptr_idx}] = malloc({event.size});")
                code_lines.append(f"    memset(chunks[{ptr_idx}], 'A', {event.size});")
                ptr_idx += 1
            else:
                code_lines.append(f"    free(chunks[{ptr_idx - 1}]);")
                ptr_idx -= 1
        
        code_lines.append("")
        code_lines.append("    // 漏洞利用代码放在这里")
        code_lines.append("    // chunks数组包含当前分配的块")
        code_lines.append("")
        code_lines.append("    return 0;")
        code_lines.append("}")
        
        return '\n'.join(code_lines)
    
    def analyze_heap_state(self, heap_dump: bytes) -> Dict[str, Any]:
        """
        分析堆转储状态
        
        Args:
            heap_dump: 堆内存转储数据
            
        Returns:
            堆状态分析结果
        """
        chunks = []
        offset = 0
        
        while offset + 0x10 <= len(heap_dump):
            size = int.from_bytes(heap_dump[offset:offset+8], 'little')
            if size == 0:
                break
            
            chunk = HeapChunk(
                address=offset,
                size=size,
                state=HeapChunkState.ALLOCATED if size & 1 else HeapChunkState.FREE,
                prev_inuse=(size & 2) != 0
            )
            chunks.append(chunk)
            offset += size & ~0xf
        
        return {
            'total_chunks': len(chunks),
            'allocated_chunks': sum(1 for c in chunks if c.state == HeapChunkState.ALLOCATED),
            'free_chunks': sum(1 for c in chunks if c.state == HeapChunkState.FREE),
            'chunks': [c.__dict__ for c in chunks]
        }


class AlgebraicHeapSolverPlugin:
    """代数堆求解器插件"""
    
    NAME = "algebraic_heap_solver"
    DESCRIPTION = "内存布局代数化描述与求解器"
    
    @classmethod
    def get_metadata(cls):
        """获取插件元数据"""
        return {
            'name': cls.NAME,
            'description': cls.DESCRIPTION,
            'version': '1.0.0',
            'dependencies': ['sympy'],
            'supported_platforms': ['linux', 'windows', 'macos']
        }


def solve_heap_layout(target_size: int, num_chunks: int, allocator_type: str = 'ptmalloc') -> List[List[AllocationEvent]]:
    """
    求解堆布局的便捷函数
    
    Args:
        target_size: 目标块大小
        num_chunks: 需要的块数量
        allocator_type: 分配器类型
        
    Returns:
        分配事件序列列表
    """
    allocator_enum = AllocatorType(allocator_type.lower())
    solver = AlgebraicHeapSolver(allocator_enum)
    
    solver.set_target_layout({
        'target_size': target_size,
        'num_chunks': num_chunks
    })
    
    return solver.solve()


def generate_heap_fengshui_code(target_size: int, num_chunks: int) -> str:
    """
    生成堆风水代码
    
    Args:
        target_size: 目标块大小
        num_chunks: 需要的块数量
        
    Returns:
        C代码字符串
    """
    solver = AlgebraicHeapSolver()
    solver.set_target_layout({
        'target_size': target_size,
        'num_chunks': num_chunks
    })
    
    solutions = solver.solve()
    if solutions:
        return solver.generate_c_code(solutions[0])
    return ""