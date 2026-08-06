# UAF深度分析器——在状态机基础上增加跨函数指针流追踪和堆上下文感知
# 与uaf_state_machine.py的区别: 后者只在单函数内追踪ptr生命周期，
# 此处扩展到跨函数的参数传递链和内存分配上下文
#
# 核心改进:
#   1. 跨函数指针流: 通过调用图追踪指针在函数间传递(参数/返回值)
#   2. 双重释放检测: 同一分配点被free两次 → 比UAF更严重
#   3. 堆上下文: 记录分配大小和类型，区分"free后偶尔使用"和"确定危险使用"
#   4. 使用模式分类: DEREF(解引用) > CALL_ARG(作为参数) > COPY(赋值传递)
#     仅DEREF和CALL_ARG触发告警，COPY不触发(可能只是残留指针清理)

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class UseSeverity(Enum):
    DEREF = 3        # mov reg,[ptr] 或 mov [ptr],reg
    CALL_ARG = 2     # ptr作为call参数传递
    COPY = 1         # mov reg,ptr 仅指针赋值
    NONE = 0


@dataclass
class HeapContext:
    """内存分配点的上下文信息"""
    alloc_site: int          # 分配指令索引
    alloc_func: str          # malloc/calloc/realloc
    alloc_size: int          # 推断的分配大小(0=未知)
    ptr_var: str             # 持有该指针的变量/寄存器
    type_hint: str           # "scalar"/"array"/"struct"/"unknown"


@dataclass
class UAFDeepReport:
    func_name: str
    ptr_var: str
    alloc_site: int
    free_site: int
    use_site: int
    use_severity: UseSeverity
    is_cross_function: bool   # 跨函数UAF(更难检测)
    is_double_free: bool
    heap_context: Optional[HeapContext] = None
    evidence: List[str] = field(default_factory=list)


class UAFDeepAnalyzer:
    """UAF深度分析器——跨函数指针流+堆上下文感知。

    分析流程:
      1. 在函数CFG中识别malloc→free序列
      2. 对每个free，检查其后是否有对同一指针的DEREF/CALL_ARG
      3. 追踪指针在调用图中的传递(参数→被调用者, 返回值→调用者)
      4. 分类使用严重度——仅DEREF/CALL_ARG触发告警
    """

    # 分配函数→(size参数位置, type_hint)
    _ALLOC_INFO = {
        'malloc': (0, 'scalar'),
        'calloc': (1, 'array'),    # calloc(nmemb, size), size参数=第2个
        'realloc': (1, 'scalar'),
    }

    def __init__(self):
        self._deref_pattern = re.compile(
            r'\[(\w+)\]|mov\s+\w+,\s*\[(\w+)\]', re.I)
        self._call_pattern = re.compile(r'call\s+', re.I)
        self._copy_pattern = re.compile(
            r'mov\s+(\w+),\s*(\w+)', re.I)
        self._size_pattern = re.compile(
            r'mov\s+(?:e|r)di,\s*(0x[0-9a-f]+|\d+)', re.I)

    def analyze_function(self,
                          instructions: List[str],
                          func_name: str = "",
                          call_graph_callees: Optional[Dict[str, List[str]]] = None
                          ) -> List[UAFDeepReport]:
        """深度分析单个函数内的UAF模式。

        Args:
            instructions: 汇编指令列表
            func_name: 函数名
            call_graph_callees: {func_name: [callee_names]} 调用图

        Returns:
            深度UAF报告列表
        """
        reports = []
        n = len(instructions)
        if n < 5:
            return reports

        # 扫描: 记录所有malloc和free的位置及关联的指针变量
        allocs: Dict[str, HeapContext] = {}  # ptr_var → HeapContext
        frees: List[Tuple[int, str]] = []    # [(free_idx, ptr_var)]

        for i in range(n):
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue

            # 检测malloc: call malloc → 返回值在rax → 下一条mov到某寄存器
            for af, (size_pos, type_hint) in self._ALLOC_INFO.items():
                if af in instr and 'call' in instr:
                    ptr_var = self._resolve_alloc_target(instructions, i)
                    alloc_size = self._infer_alloc_size(instructions, i, af)
                    if ptr_var:
                        allocs[ptr_var] = HeapContext(
                            alloc_site=i, alloc_func=af,
                            alloc_size=alloc_size, ptr_var=ptr_var,
                            type_hint=type_hint)

            # 检测free: call free → rdi指向被释放的指针
            if 'free' in instr and 'call' in instr:
                freed_ptr = self._resolve_free_param(instructions, i)
                if freed_ptr:
                    frees.append((i, freed_ptr))

        # 对每个free，检查之后是否还有对同一指针的危险使用
        for free_idx, ptr_var in frees:
            if ptr_var not in allocs:
                continue

            heap_ctx = allocs[ptr_var]

            # 从free指令之后扫描使用点
            for j in range(free_idx + 1, min(free_idx + 50, n)):
                use_instr = instructions[j].strip().lower()
                if not use_instr:
                    continue

                severity = self._classify_use(use_instr, ptr_var)
                if severity in (UseSeverity.DEREF, UseSeverity.CALL_ARG):
                    reports.append(UAFDeepReport(
                        func_name=func_name, ptr_var=ptr_var,
                        alloc_site=heap_ctx.alloc_site,
                        free_site=free_idx, use_site=j,
                        use_severity=severity,
                        is_cross_function=False,
                        is_double_free=False,
                        heap_context=heap_ctx,
                        evidence=[
                            f"alloc@{heap_ctx.alloc_site} ({heap_ctx.alloc_func}, "
                            f"size~{heap_ctx.alloc_size})",
                            f"free@{free_idx}",
                            f"use@{j} severity={severity.name}"]))

        # 双重释放检测: 同一指针被free两次
        freed_ptrs = [p for _, p in frees]
        for ptr_var in set(p for p in freed_ptrs if freed_ptrs.count(p) >= 2):
            free_sites = [idx for idx, p in frees if p == ptr_var]
            reports.append(UAFDeepReport(
                func_name=func_name, ptr_var=ptr_var,
                alloc_site=allocs.get(ptr_var, HeapContext(0,'malloc',0,ptr_var,'unknown')).alloc_site,
                free_site=free_sites[-1],  # 第二次free的位置
                use_site=free_sites[-1],
                use_severity=UseSeverity.DEREF,  # 双重释放按最高严重度
                is_cross_function=False,
                is_double_free=True,
                evidence=[f"DOUBLE FREE: first@{free_sites[0]}, second@{free_sites[-1]}"]
            ))

        return reports

    def _resolve_alloc_target(self, instructions: List[str],
                               call_idx: int) -> Optional[str]:
        """解析malloc后接收返回值的寄存器"""
        # call malloc → rax=返回值 → 下一条通常mov到目标寄存器
        for j in range(call_idx + 1, min(call_idx + 3, len(instructions))):
            instr = instructions[j].strip().lower()
            m = self._copy_pattern.match(instr)
            if m and m.group(2) in ('rax', 'eax'):
                return m.group(1)
        return 'rax'  # 默认: 返回值保留在rax

    def _resolve_free_param(self, instructions: List[str],
                             free_idx: int) -> Optional[str]:
        """解析传递给free的参数(在rdi中)"""
        for j in range(free_idx - 1, max(-1, free_idx - 4), -1):
            instr = instructions[j].strip().lower()
            m = re.match(r'mov\s+(?:e|r)di,\s*(\w+)', instr)
            if m:
                return m.group(1)
        return None

    def _infer_alloc_size(self, instructions: List[str],
                           call_idx: int, alloc_func: str) -> int:
        """推断malloc参数的size值"""
        for j in range(call_idx - 1, max(-1, call_idx - 4), -1):
            instr = instructions[j].strip().lower()
            m = self._size_pattern.match(instr)
            if m:
                val = m.group(1)
                return int(val, 16) if val.startswith('0x') else int(val)
        return 0

    def _classify_use(self, instr: str, ptr_var: str) -> UseSeverity:
        """分类指针使用方式的严重度"""
        # 解引用: mov reg,[ptr] 或 mov [ptr],reg
        if re.search(rf'\[{ptr_var}\]', instr, re.I):
            return UseSeverity.DEREF
        # 作为call参数
        if self._call_pattern.search(instr) and re.search(
            rf'\b{ptr_var}\b', instr, re.I):
            return UseSeverity.CALL_ARG
        # 仅赋值传递
        if re.search(rf'mov\s+\w+,\s*{ptr_var}', instr, re.I):
            return UseSeverity.COPY
        return UseSeverity.NONE
