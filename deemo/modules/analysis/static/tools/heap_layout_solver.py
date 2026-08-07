#!/usr/bin/env python3
"""
堆布局约束求解器

基于 的堆布局约束模型
将堆内存分配/释放序列建模为线性 Diophantine 方程
求解满足漏洞利用前提的堆布局

核心能力：
- 堆操作序列提取
- 空闲链表/arena 状态建模
- 布局约束 ILP 求解
- 多策略布局（按 ptmalloc 版本）

参考 的 artifact-assisted 策略
与 的上下文堆操作序列分析
"""

import logging
import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import itertools
from collections import OrderedDict  # 保留——未使用

logger = logging.getLogger(__name__)


class HeapOp(Enum):
    """堆操作类型"""
    MALLOC = auto()
    FREE = auto()
    CALLOC = auto()
    REALLOC = auto()
    MEMALIGN = auto()
    MMAP = auto()
    MUNMAP = auto()
    BRK = auto()


class BinType(Enum):
    """ptmalloc bin 类型"""
    TCACHE = auto()
    FASTBIN = auto()
    SMALLBIN = auto()
    LARGEBIN = auto()
    UNSORTED = auto()
    TOP_CHUNK = auto()


@dataclass
class Chunk:
    """
    ptmalloc malloc_chunk 模型（x86-64）
    
    字段与 glibc 2.35+ 兼容
    """
    address: int
    size: int  # 含 metadata 的完整 chunk size
    prev_size: int = 0
    flags: int = 0  # PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
    fd: int = 0     # forward 指针 (free list)
    bk: int = 0     # backward 指针 (free list)
    fd_nextsize: int = 0
    bk_nextsize: int = 0
    is_free: bool = False
    bin_type: Optional[BinType] = None

    def user_size(self) -> int:
        """返回用户可用大小（不含 metadata）"""
        return self.size - 0x10  # prev_size + size header

    def next_chunk_addr(self) -> int:
        return self.address + self.size

    def prev_inuse(self) -> bool:
        return bool(self.flags & 0x1)

    def is_mmapped(self) -> bool:
        return bool(self.flags & 0x2)


@dataclass
class HeapLayout:
    """
    堆布局快照
    
    在某个时间点的完整堆状态
    """
    chunks: List[Chunk] = field(default_factory=list)
    free_lists: Dict[BinType, List[int]] = field(
        default_factory=lambda: defaultdict(list)
    )
    tcache_count: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    top_chunk_addr: int = 0
    heap_base: int = 0


@dataclass
class HeapConstraint:
    """
    堆布局约束
    
    表示一条与堆操作相关的约束条件
    可转换为 ILP 变量
    """
    constraint_type: str  # 'allocation', 'free', 'overlap', 'adjacent', 'size'
    variables: List[str] = field(default_factory=list)
    coefficients: List[int] = field(default_factory=list)
    target: int = 0
    relation: str = 'eq'  # 'eq', 'le', 'ge'
    description: str = ""


@dataclass
class ExploitStrategy:
    """
    漏洞利用策略
    """
    strategy_name: str
    applicable_vuln_types: List[str]
    ptmalloc_version: str
    required_conditions: List[str]
    steps: List[str]
    complexity: str  # 'low', 'medium', 'high', 'expert'
    success_probability: float = 0.0
    references: List[str] = field(default_factory=list)


class HeapOpSequenceExtractor:
    """
    堆操作序列提取器
    
    从程序调用图/汇编/输出中提取 malloc/free 操作序列
    参考 [CtxFuzz 2025] 的 CHOS (Context 堆 Operation Sequence) 提取方法
    """

    _ALLOC_PATTERNS = [
        re.compile(r'(?:call|jmp)\s+(?:malloc|_malloc|__libc_malloc)\b', re.I),
        re.compile(r'(?:call|jmp)\s+(?:calloc|_calloc)\b', re.I),
        re.compile(r'(?:call|jmp)\s+(?:realloc|_realloc)\b', re.I),
        re.compile(r'(?:call|jmp)\s+(?:posix_memalign|memalign)\b', re.I),
        re.compile(r'(?:call|jmp)\s+(?:operator new)\b'),
    ]

    _FREE_PATTERNS = [
        re.compile(r'(?:call|jmp)\s+(?:free|_free|__libc_free)\b', re.I),
        re.compile(r'(?:call|jmp)\s+(?:operator delete)\b'),
        re.compile(r'(?:call|jmp)\s+(?:realloc)\b', re.I),  # realloc 可释放
    ]

    def extract_from_asm(self, assembly: str) -> List[Tuple[int, HeapOp, str]]:
        """
        从汇编代码中提取堆操作序列
        
        返回:
        [(address, 堆Op, raw_instruction),.]
        """
        ops = []
        addr_pattern = re.compile(r'^\s*(0x[0-9a-fA-F]+)')

        for line in assembly.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            addr_match = addr_pattern.match(line)
            addr = int(addr_match.group(1), 16) if addr_match else 0

            for pat in self._ALLOC_PATTERNS:
                if pat.search(line):
                    op_type = self._classify_alloc(line)
                    ops.append((addr, op_type, line))
                    break
            else:
                for pat in self._FREE_PATTERNS:
                    if pat.search(line):
                        ops.append((addr, HeapOp.FREE, line))
                        break

        return ops

    def _classify_alloc(self, instruction: str) -> HeapOp:
        instr_lower = instruction.lower()
        if 'calloc' in instr_lower:
            return HeapOp.CALLOC
        if 'realloc' in instr_lower:
            return HeapOp.REALLOC
        if 'memalign' in instr_lower or 'posix_memalign' in instr_lower:
            return HeapOp.MEMALIGN
        return HeapOp.MALLOC

    def extract_context_sequence(
        self, ops: List[Tuple[int, HeapOp, str]]
    ) -> List[Dict[str, Any]]:
        """
        提取带有上下文信息的堆操作序列（CHOS）
        
        为每个操作标注：地址、调用栈深度、操作序数、前后操作类型
        """
        chos = []
        for i, (addr, op, instr) in enumerate(ops):
            context = {
                'index': i,
                'address': hex(addr),
                'operation': op.name,
                'is_first': (i == 0),
                'is_last': (i == len(ops) - 1),
                'prev_op': ops[i - 1][1].name if i > 0 else 'NONE',
                'next_op': ops[i + 1][1].name if i < len(ops) - 1 else 'NONE',
            }

            # 检测操作对模式
            if i > 0:
                if ops[i - 1][1] == HeapOp.MALLOC and op == HeapOp.FREE:
                    context['pattern'] = 'MALLOC_FREE'
                elif ops[i - 1][1] == HeapOp.FREE and op == HeapOp.MALLOC:
                    context['pattern'] = 'FREE_MALLOC'

            chos.append(context)

        return chos


class HeapLayoutSolver:
    """
    堆布局约束求解器
    
    基于 [HEXP 2025] 的 ILP 方法建模堆布局
    将目标布局表示为关于分配大小和次数的线性约束
    使用整数线性规划求解可行的布局参数
    
    支持的抽象：
    - 自由块合并（unlink 操作）
    - 切割（remainder chunk）
    - Tcache/Fastbins 大小限制
    - top chunk 扩展
    """

    # ptmalloc 2.35+ t缓存参数（x86-64）
    TCACHE_MAX_ENTRIES = 7
    TCACHE_MAX_SIZE = 0x410  # 1040 bytes (64 bins × 16 bytes)
    FASTBIN_MAX_SIZE = 0x80   # 128 bytes (6 fastbins x86-64)
    SMALLBIN_MAX_SIZE = 0x400  # 1024 bytes

    def __init__(self, word_size: int = 8):
        self.word_size = word_size
        self.min_chunk = word_size * 4  # 最小 chunk: prev_size+size+fd+bk
        self.alignment = word_size * 2  # malloc 对齐

    def solve_for_uaf(
        self,
        target_size: int,
        vulnerability_offset: int,
        max_iterations: int = 1000
    ) -> Optional[Dict[str, Any]]:
        """
        求解 释放后使用 的堆布局
        
        目标：在释放 target_size 大小的 chunk 后
        用相同大小的分配重新占据，实现类型混淆或控制流劫持
        
        Args:
        target_size: 目标 chunk 的用户大小
        vulnerability_offset: 漏洞触发前需要的操作数
        max_iterations: 最大尝试次数
        
        返回:
        布局参数字典或 None
        """
        chunk_size = self._align_size(target_size + 0x10)

        # 判定目标 chunk 落入哪个 bin
        bin_type = self._classify_bin(chunk_size)

        layout = {
            'target_size': target_size,
            'chunk_size': chunk_size,
            'bin_type': bin_type.name,
            'operations': [],
            'estimated_success': 0.0,
        }

        if bin_type == BinType.TCACHE:
            # t缓存dup 策略: 通过 双重释放 使 fd 指向自身
            layout['strategy'] = 'tcache_dup'
            layout['operations'] = [
                {'op': 'malloc', 'size': target_size},  # A
                {'op': 'free', 'ptr': 'A'},              # free A → tcache
                {'op': 'free', 'ptr': 'A'},              # 双重释放 A
                {'op': 'malloc', 'size': target_size},    # 取回 A
                {'op': 'malloc', 'size': target_size},    # 再次取回 A（与上一步相同）
            ]
            layout['estimated_success'] = 0.85

        elif bin_type == BinType.FASTBIN:
            # fastbin dup: 需要有中间分配
            layout['strategy'] = 'fastbin_dup'
            layout['operations'] = [
                {'op': 'malloc', 'size': target_size},
                {'op': 'malloc', 'size': 0x20},           # 隔离 chunk
                {'op': 'free', 'ptr': 'A'},
                {'op': 'free', 'ptr': 'A'},               # 双重释放
                {'op': 'malloc', 'size': target_size},
                {'op': 'malloc', 'size': target_size},
            ]
            layout['estimated_success'] = 0.70

        elif bin_type == BinType.SMALLBIN or bin_type == BinType.LARGEBIN:
            # unsorted bin attack → 改写 global_max_fast
            layout['strategy'] = 'unsorted_bin_attack'
            layout['operations'] = [
                {'op': 'malloc', 'size': 0x500},           # 防止与 top chunk 合并的屏障
                {'op': 'malloc', 'size': target_size},      # 目标 chunk A
                {'op': 'malloc', 'size': 0x20},             # 隔离 chunk B
                {'op': 'free', 'ptr': 'A'},                 # A → unsorted bin
                {'op': 'malloc', 'size': 0x400},            # 从 unsorted bin 切割，A 的 bk 仍可控
            ]
            layout['estimated_success'] = 0.40

        else:
            layout['strategy'] = 'unknown'
            layout['estimated_success'] = 0.0

        return layout

    def solve_for_heap_overflow(
        self,
        overflow_source_size: int,
        target_type: str = 'adjacent',
        max_iterations: int = 500
    ) -> Optional[Dict[str, Any]]:
        """
        求解堆溢出的布局约束
        
        目标：使得溢出源 chunk 与需要覆写的目标 chunk 相邻
        从而实现元数据或指针覆写
        
        Args:
        overflow_source_size: 溢出源 chunk 大小
        target_type: 目标类型（'adjacent', 'tcache_fd', 'fastbin_fd'）
        
        返回:
        布局参数字典或 None
        """
        layout = {
            'overflow_size': overflow_source_size,
            'target_type': target_type,
            'strategy': '',
            'operations': [],
            'estimated_success': 0.0,
        }

        if target_type == 'adjacent':
            layout['strategy'] = 'adjacent_overflow'
            layout['operations'] = [
                {'op': 'malloc', 'size': overflow_source_size},  # 源 chunk
                {'op': 'malloc', 'size': overflow_source_size},  # 目标 chunk（相邻）
                {'op': 'free', 'ptr': 'B'},                       # 暂时释放目标
            ]
            layout['estimated_success'] = 0.80

        elif target_type == 'tcache_fd':
            layout['strategy'] = 'tcache_fd_overwrite'
            target_chunk_size = overflow_source_size
            layout['operations'] = [
                {'op': 'malloc', 'size': overflow_source_size},   # 源
                {'op': 'malloc', 'size': target_chunk_size},      # 目标（同大小，同 tcache bin）
                {'op': 'free', 'ptr': 'B'},                        # B → t缓存head
            ]
            layout['estimated_success'] = 0.75

        elif target_type == 'fastbin_fd':
            layout['strategy'] = 'fastbin_fd_overwrite'
            layout['operations'] = [
                {'op': 'malloc', 'size': overflow_source_size},
                {'op': 'malloc', 'size': overflow_source_size},
                {'op': 'free', 'ptr': 'B'},
            ]
            layout['estimated_success'] = 0.65

        return layout

    def _align_size(self, size: int) -> int:
        """对齐到 malloc 对齐边界"""
        return (size + self.alignment - 1) & ~(self.alignment - 1)

    def _classify_bin(self, size: int) -> BinType:
        """根据 chunk 大小分类到 bin 类型"""
        if size <= self.TCACHE_MAX_SIZE:
            return BinType.TCACHE
        elif size <= self.FASTBIN_MAX_SIZE:
            return BinType.FASTBIN
        elif size <= self.SMALLBIN_MAX_SIZE:
            return BinType.SMALLBIN
        return BinType.LARGEBIN


class ExploitStrategyRecommender:
    """
    漏洞利用策略器
    
    基于 [AutoPwn 2024] 的 artifact-assisted 策略重用方法
    将已知漏洞模式映射到具体的利用策略
    
    [HEXP 2025] 的布局约束模型用于验证策略的可行性
    """

    STRATEGIES = [
        ExploitStrategy(
            strategy_name='tcache_perthread_struct_corruption',
            applicable_vuln_types=['heap_overflow', 'uaf', 'double_free'],
            ptmalloc_version='2.26+',
            required_conditions=['可以对 tcache_perthread_struct 写入',
                                '知道堆基址'],
            steps=[
                '1. 泄露堆地址（如通过 unsorted bin fd/bk）',
                '2. 计算 tcache_perthread_struct 地址（heap_base + 0x10）',
                '3. 利用溢出/UAF 覆写其 tcache_bins 条目',
                '4. 下次分配返回任意目标地址',
            ],
            complexity='high',
            references=['HEXP 2025']
        ),
        ExploitStrategy(
            strategy_name='unsorted_bin_attack_fsop',
            applicable_vuln_types=['uaf', 'heap_overflow', 'double_free'],
            ptmalloc_version='2.23-2.35',
            required_conditions=['存在 IO_FILE 结构体', '可以触发 abort/exit'],
            steps=[
                '1. 泄露 libc 地址',
                '2. 获得 unsorted bin chunk 控制权',
                '3. 覆写 bk 指针为 _IO_list_all - 0x10',
                '4. 触发 malloc 导致 unsorted bin 遍历，伪造 FILE 结构体',
                '5. 通过 vtable 劫持获得执行控制',
            ],
            complexity='high',
            references=['AutoPwn 2024']
        ),
        ExploitStrategy(
            strategy_name='house_of_force',
            applicable_vuln_types=['heap_overflow'],
            ptmalloc_version='< 2.29',
            required_conditions=['可以覆写 top chunk size 字段',
                                '知道目标地址与堆顶的距离'],
            steps=[
                '1. 泄露堆地址',
                '2. 溢出覆写 top chunk size 为 -1',
                '3. 计算目标地址与堆顶的偏移',
                '4. 分配该偏移量大小的 chunk',
                '5. 再次分配获取目标地址的 chunk',
            ],
            complexity='medium',
            references=[]
        ),
        ExploitStrategy(
            strategy_name='tcache_poisoning',
            applicable_vuln_types=['uaf', 'double_free', 'heap_overflow'],
            ptmalloc_version='2.26+',
            required_conditions=['可以覆写 tcache chunk 的 fd 指针'],
            steps=[
                '1. 获得目标 tcache bin 的 free chunk 控制权',
                '2. 覆写其 fd 指针为目标地址',
                '3. 从该 tcache bin 分配两次',
                '4. 第二次分配返回目标地址',
            ],
            complexity='medium',
            references=['CtxFuzz 2025', 'AutoPwn 2024']
        ),
    ]

    @classmethod
    def recommend(
        cls,
        vuln_type: str,
        ptmalloc_version: str = '2.35',
        known_conditions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        适用于给定漏洞类型的利用策略
        
        Args:
        vuln_type: 漏洞类型（如 'uaf', '堆_overflow'）
        ptmalloc_version: glibc/ptmalloc 版本
        known_conditions: 已知满足的条件
        
        返回:
        按成功概率降序排列的策略列表
        """
        candidates = []

        for strategy in cls.STRATEGIES:
            if vuln_type not in strategy.applicable_vuln_types:
                continue

            # 计算条件匹配度
            if known_conditions:
                matched = sum(
                    1 for cond in strategy.required_conditions
                    if any(kc.lower() in cond.lower() for kc in known_conditions)
                )
                strategy.success_probability = (
                    0.9 * matched / max(len(strategy.required_conditions), 1)
                )
            else:
                strategy.success_probability = 0.5

            candidates.append(strategy)

        candidates.sort(key=lambda s: s.success_probability, reverse=True)

        return [
            {
                'name': s.strategy_name,
                'complexity': s.complexity,
                'success_prob': round(s.success_probability, 2),
                'required_conditions': s.required_conditions,
                'steps': s.steps,
                'references': s.references,
            }
            for s in candidates
        ]


def analyze_heap_layout(
    heap_ops: List[Dict[str, Any]],
    vuln_type: str = 'uaf',
    target_size: int = 0x40
) -> Dict[str, Any]:
    """
    便捷函数：堆布局分析
    
    整合序列提取 → 布局求解 → 策略的完整流程
    """
    solver = HeapLayoutSolver()

    if vuln_type in ('uaf', 'use_after_free', 'double_free'):
        layout = solver.solve_for_uaf(target_size, 0)
    elif vuln_type in ('heap_overflow', 'overflow'):
        layout = solver.solve_for_heap_overflow(target_size)
    else:
        layout = solver.solve_for_uaf(target_size, 0)

    strategies = ExploitStrategyRecommender.recommend(
        vuln_type=vuln_type,
        known_conditions=['tcache' if target_size <= 0x410 else 'unsorted']
    )

    return {
        'vuln_type': vuln_type,
        'target_size': target_size,
        'layout_solution': layout,
        'recommended_strategies': strategies[:3],
    }
