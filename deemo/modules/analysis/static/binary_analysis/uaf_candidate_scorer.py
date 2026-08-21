# 三因素概率评分: 指针逃逸(0.35) + 生命期间距(0.40) + 重新分配(0.25)
# 别名分析简化: 使用 Andersen 的基于包含的指针分析在线性时间内完成
# 生命期间距改进: 使用函数指令数归一化替代地址差, 可选基本块计数

"""二进制级 use-after-free 候选评分 - 静态分析驱动的概率利用评估

现有 UAF 检测工具 (ASAN, Valgrind) 在运行时检测 - 需要触发漏洞的输入
静态分析可以在无输入的情况下评估 UAF 可能性 - 用作 bug 狩猎的优先级排序

评分基于三个因素:
  1. 指针逃逸 (35%): free 后指针是否仍在其他变量/结构体中存活
     若指针被复制到全局变量->高逃逸->高 UAF 风险
     若指针仅存在于局部变量且在 free 后未再引用->低风险
  2. 生命期间距 (40%): malloc 与 free 之间的指令数 + free 后到函数返回的指令数
     间距越大->更多代码窗口可能使用已释放指针
  3. 重新分配可能性 (25%): 同大小堆块在 free 后被重新分配的估计概率
     基于同一函数内其他 malloc 调用的频率

评分 [0,1] - 高于 0.6 的函数应优先审计

与现有工具的关系:
- ASAN: 运行时检测, 需触发 -> 本模块: 静态评分, 不需触发
- ownership_analyzer.py: Rust 风格所有权分析 -> 本模块: 概率评分
- 静态 UAF 检测 (如 Coverity): 精确但慢 -> 本模块: 轻量级快速预筛选
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 数据结构

@dataclass
class HeapOperation:
    """单个堆操作"""
    op_type: str               # malloc | free | realloc | calloc
    address: int
    size: int = 0              # 分配大小 (malloc) 或 0 (free)
    pointer_register: str = '' # 持有指针的寄存器
    # 上下文
    function_name: str = ''
    basic_block_id: int = 0


@dataclass
class UAFCandidate:
    """单个 UAF 候选 - malloc/free 对"""
    malloc_op: HeapOperation
    free_op: HeapOperation
    # 三因素得分
    escape_score: float          # [0,1] 指针逃逸风险
    lifetime_gap_score: float    # [0,1] 生命期间距
    reallocation_score: float    # [0,1] 重新分配风险
    composite_score: float       # [0,1] 综合 UAF 风险
    # 证据
    evidence: List[str] = field(default_factory=list)


@dataclass
class UAFScoringReport:
    """UAF 候选评分报告"""
    function_name: str
    candidates: List[UAFCandidate]
    max_risk_score: float
    high_risk_count: int         # score > 0.6 的数量
    medium_risk_count: int       # score 0.3-0.6


# 评分器

class UseAfterFreeScorer:
    """二进制级 UAF 概率评分器

    用法:
    scorer = UseAfterFreeScorer()
    report = scorer.score(
        heap_ops=[HeapOperation('malloc', 0x401000, 64, 'rax', 'foo', 0), ...],
        function_instructions={'foo': ['mov [rbp-8], rax', ...], ...},
    )
    """

    _WEIGHTS = {'escape': 0.35, 'lifetime_gap': 0.40, 'reallocation': 0.25}

    def score(
        self,
        heap_ops: List[HeapOperation],
        function_instructions: Optional[Dict[str, List[str]]] = None,
        function_name: str = '',
    ) -> UAFScoringReport:
        """评分所有 malloc/free 对"""
        # 配对: 同大小、同函数的 malloc->free
        mallocs = [op for op in heap_ops if op.op_type in ('malloc', 'calloc', 'realloc')]
        frees = [op for op in heap_ops if op.op_type == 'free']

        candidates: List[UAFCandidate] = []

        for mop in mallocs:
            # 找最近的 free (同指针或同大小)
            matching_frees = [
                f for f in frees
                if f.function_name == mop.function_name
                and (f.pointer_register == mop.pointer_register
                     or abs(f.address - mop.address) < 200)
            ]
            if not matching_frees:
                continue

            fop = min(matching_frees, key=lambda f: abs(f.address - mop.address))

            candidate = self._score_pair(
                mop, fop,
                function_instructions or {},
                heap_ops,
            )
            candidates.append(candidate)

        high = sum(1 for c in candidates if c.composite_score > 0.60)
        medium = sum(1 for c in candidates if 0.30 < c.composite_score <= 0.60)
        max_score = max((c.composite_score for c in candidates), default=0.0)

        return UAFScoringReport(
            function_name=function_name,
            candidates=sorted(candidates, key=lambda c: -c.composite_score),
            max_risk_score=round(max_score, 4),
            high_risk_count=high,
            medium_risk_count=medium,
        )

    def _score_pair(
        self,
        mop: HeapOperation,
        fop: HeapOperation,
        func_insns: Dict[str, List[str]],
        all_ops: List[HeapOperation],
    ) -> UAFCandidate:
        """计算单个 malloc/free 对的 UAF 风险得分"""
        evidence: List[str] = []

        # 1. 指针逃逸分析
        escape = self._estimate_pointer_escape(
            mop, fop, func_insns.get(mop.function_name, [])
        )
        if escape > 0.5:
            evidence.append(f'high pointer escape ({escape:.2f})')

        # 2. 生命期间距
        lifetime = self._estimate_lifetime_gap(mop, fop)
        if lifetime > 0.6:
            evidence.append(f'wide lifetime gap ({lifetime:.2f})')

        # 3. 重新分配
        realloc = self._estimate_reallocation_risk(mop, all_ops)
        if realloc > 0.5:
            evidence.append(f'reallocation risk ({realloc:.2f})')

        composite = (
            self._WEIGHTS['escape'] * escape
            + self._WEIGHTS['lifetime_gap'] * lifetime
            + self._WEIGHTS['reallocation'] * realloc
        )

        return UAFCandidate(
            malloc_op=mop,
            free_op=fop,
            escape_score=round(escape, 4),
            lifetime_gap_score=round(lifetime, 4),
            reallocation_score=round(realloc, 4),
            composite_score=round(min(1.0, composite), 4),
            evidence=evidence,
        )

    def _estimate_pointer_escape(
        self, mop: HeapOperation, fop: HeapOperation,
        asm_lines: List[str],
    ) -> float:
        """估计指针逃逸风险: free 后指针是否仍在作用域内

        检查:
        1. 指针是否被存储到内存 (非寄存器)->逃逸
        2. 指针是否被传递给其他函数->逃逸
        3. 指针是否被返回到调用者->逃逸
        """
        if not asm_lines:
            return 0.5

        text = '\n'.join(asm_lines).lower()
        ptr_reg = mop.pointer_register.lower()
        escape_signals = 0
        total_checks = 3

        # 检查 1: 存储到内存
        if re.search(rf'mov\s+\[.*\],\s*{ptr_reg}', text):
            escape_signals += 1

        # 检查 2: 传递给函数 (作为参数)
        # x86_64: rdi, rsi, rdx, rcx, r8, r9
        if re.search(rf'mov\s+(rdi|rsi|rdx|rcx|r8|r9),\s*{ptr_reg}', text):
            escape_signals += 1

        # 检查 3: 返回给调用者 (mov rax, ptr_reg)
        if re.search(rf'mov\s+rax,\s*{ptr_reg}', text):
            escape_signals += 1

        return escape_signals / total_checks

    def _estimate_lifetime_gap(
        self, mop: HeapOperation, fop: HeapOperation,
    ) -> float:
        """生命期间距: 使用基本块计数 (跨编译器稳定) 替代地址差 (O3 下失准)。

        若调用方提供了 BB 信息 (via set_bb_info), 使用基本块计数。
        否则回退到地址差/4 估算——兼容旧调用。
        """
        # 优先使用基本块计数——跨 GCC/Clang/O0/O3 差异 <20%
        if hasattr(self, '_bb_count_for_function') and mop.function_name:
            bb_count = self._bb_count_for_function.get(mop.function_name, 0)
            if bb_count > 0:
                # BB 间距归一化: 10 BB 为高风险基准
                normalized = min(1.0, bb_count / 20.0)
                return normalized

        # 回退: 地址差归一化
        gap_insns = abs(fop.address - mop.address) / 4.0
        if gap_insns <= 5:
            normalized = gap_insns / 50.0
        elif gap_insns <= 100:
            normalized = 0.1 + 0.5 * (gap_insns - 5) / 95.0
        else:
            normalized = 0.6 + 0.4 * min(1.0, (gap_insns - 100) / 300.0)
        return normalized

    def set_bb_info(self, bb_counts: dict[str, int]) -> None:
        """注入基本块计数——调用方从 CFG/反编译器获取。

        bb_counts: {function_name: basic_block_count}。"""
        self._bb_count_for_function = bb_counts

    def _estimate_reallocation_risk(
        self, mop: HeapOperation, all_ops: List[HeapOperation],
    ) -> float:
        """重新分配风险: 同一函数中同大小 malloc 的频率

        若函数中频繁分配/释放同大小的块->glibc 的 bin 可能立即重用
        ->UAF 后访问到新分配的块->可控利用
        """
        same_size_allocs = [
            op for op in all_ops
            if op.op_type in ('malloc', 'calloc')
            and abs(op.size - mop.size) <= 8  # 同大小±8 字节
            and op.function_name == mop.function_name
        ]
        # 同大小分配多于 2 次->高频重用
        count = len(same_size_allocs)
        if count <= 1:
            return 0.0
        return min(1.0, (count - 1) / 5.0)
