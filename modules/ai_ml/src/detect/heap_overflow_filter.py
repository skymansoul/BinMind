# 堆溢出误报过滤器-通过三阶段验证压低误报率
# 不是简单地标记所有memcpy/strcpy为漏洞，
# 而是对每个sink执行: (1)源参数可控性验证 (2)分配大小vs拷贝大小比较
# (3)路径可达性确认。三层过滤后仅保留真正的溢出。
#
# 与现有方案的关键区别:
#   - Mango: 做value analysis但面向IoT固件，不做缓冲区尺寸推断
#   - IntTracer: 做区间抽象但仅针对整数溢出，不覆盖堆分配模式
# 本方案: 在二进制层面做三阶段链式过滤，每阶段可独立启用/禁用

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

from ..taint.backward_taint import (
    BackwardTaintEngine, TaintLevel, TaintResult)
from .buffer_size_infer import (
    BufferSizeInferer, OverflowVerdict, IntervalValue)

logger = logging.getLogger(__name__)


class FilterVerdict(Enum):
    CONFIRMED = 'confirmed'       # 三层验证全部通过-确定漏洞（口径: 验证层校验语义, 非测试结果宣称）
    LIKELY = 'likely'             # 两层通过-高概率漏洞
    UNCERTAIN = 'uncertain'       # 仅一层通过-需人工审查
    FILTERED = 'filtered'         # 全部未通过-误报已排除


@dataclass
class HeapOverflowReport:
    func_name: str
    sink_instr_idx: int
    sink_func: str
    alloc_site: Optional[int]      # malloc调用位置
    copy_site: int                 # memcpy/strcpy调用位置
    verdict: FilterVerdict
    taint_passed: bool             # 阶段1: 源参数可控
    size_passed: bool              # 阶段2: 分配大小 < 拷贝大小
    path_passed: bool              # 阶段3: sink在可达路径上
    alloc_size: Optional[IntervalValue] = None
    copy_size: Optional[IntervalValue] = None
    evidence: List[str] = field(default_factory=list)


class HeapOverflowFilter:
    """堆溢出三阶段过滤器。

    阶段1 (TAINT): 拷贝目标缓冲区是否来自外部输入
      源参数不受控的memcpy→排除(如memcpy(全局buf,常量,size))

    阶段2 (SIZE): 分配大小是否小于拷贝大小
      比较最近的malloc(size)参数与memcpy(dst,src,n)的n参数
      n <= size → 排除(合法拷贝)
    阶段3 (PATH): sink是否在从入口可达的执行路径上
      CFG中从函数入口基本块出发BFS-不可达的sink→排除
      (排除死代码中的危险函数调用)
    """

    # 拷贝类危险函数-需要验证参数
    _COPY_SINKS = {'memcpy', 'memmove', 'strcpy', 'strncpy',
                   'sprintf', 'snprintf', 'gets', 'read',
                   'fread', 'recv'}
    # 分配函数
    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}

    def __init__(self):
        self._taint = BackwardTaintEngine(max_trace_depth=5)
        self._size_infer = BufferSizeInferer(safety_margin=8)

    def analyze_function(self,
                          instructions: List[str],
                          bb_boundaries: List[Tuple[int, int]],
                          cfg_edges: List[Tuple[int, int]],
                          func_name: str = ""
                          ) -> List[HeapOverflowReport]:
        """对单个函数执行三阶段堆溢出过滤。

        仅CONFIRMED/LIKELY的值得关注，UNCERTAIN建议人工审查
        """
        n = len(instructions)
        if n < 3:
            return []

        # 预计算: 构建CFG邻接表用于BFS可达性
        reachable = self._compute_reachable(bb_boundaries, cfg_edges)

        reports = []
        for i in range(n):
            instr = instructions[i].strip().lower()
            if not instr or 'call' not in instr:
                continue

            # 识别sink
            sink = None
            for sf in self._COPY_SINKS:
                if sf in instr:
                    sink = sf
                    break
            if sink is None:
                continue

            # 阶段1: 污点验证-拷贝目标是用户可控的?
            taint_r = self._taint.trace_param(i, 'rdi', instructions)
            taint_ok = self._taint.is_vulnerable_sink(taint_r)

            # 阶段2: 大小验证-分配大小 < 拷贝大小?
            size_ok = False
            alloc_idx = self._find_nearest_alloc(instructions, i)
            alloc_size = None
            copy_size = None

            if alloc_idx >= 0:
                for af in self._ALLOC_FUNCS:
                    if af in instructions[alloc_idx].lower():
                        alloc_size = self._size_infer.infer_alloc_size(
                            alloc_idx, instructions)
                        copy_size = self._size_infer.infer_copy_size(
                            i, sink, instructions)
                        if (alloc_size.is_exact() and copy_size.is_exact()
                            and copy_size.lo > alloc_size.lo):
                            size_ok = True
                        elif copy_size.hi > alloc_size.lo + 8:
                            size_ok = True  # 区间重叠→潜在溢出
                        break

            # 阶段3: 路径可达性-sink所在基本块是否从入口可达?
            path_ok = self._is_reachable_block(i, bb_boundaries, reachable)

            # 综合判定
            passed = sum([taint_ok, size_ok, path_ok])
            if passed == 3:
                verdict = FilterVerdict.CONFIRMED
            elif passed == 2:
                verdict = FilterVerdict.LIKELY
            elif passed == 1:
                verdict = FilterVerdict.UNCERTAIN
            else:
                verdict = FilterVerdict.FILTERED

            evidence = []
            if taint_ok:
                evidence.append(f"taint: {taint_r.source_origin}")
            else:
                evidence.append(f"taint: FAILED (level={taint_r.taint_level.value})")
            if size_ok and alloc_size and copy_size:
                evidence.append(
                    f"size: alloc={alloc_size.lo}-{alloc_size.hi} < copy={copy_size.lo}-{copy_size.hi}")
            elif not size_ok:
                evidence.append("size: UNVERIFIED (insufficient constant info)")
            if path_ok:
                evidence.append("path: reachable from entry")
            else:
                evidence.append("path: UNREACHABLE (dead code or isolated block)")

            reports.append(HeapOverflowReport(
                func_name=func_name, sink_instr_idx=i,
                sink_func=sink, alloc_site=alloc_idx,
                copy_site=i, verdict=verdict,
                taint_passed=taint_ok, size_passed=size_ok,
                path_passed=path_ok,
                alloc_size=alloc_size, copy_size=copy_size,
                evidence=evidence))

        return reports

    def _find_nearest_alloc(self, instructions: List[str],
                             copy_idx: int) -> int:
        """在copy之前最近30条指令内查找malloc调用"""
        for j in range(copy_idx - 1, max(-1, copy_idx - 30), -1):
            if j < 0:
                continue
            instr = instructions[j].lower()
            if 'call' in instr:
                for af in self._ALLOC_FUNCS:
                    if af in instr:
                        return j
        return -1

    def _compute_reachable(self,
                            bb_boundaries: List[Tuple[int, int]],
                            cfg_edges: List[Tuple[int, int]]
                            ) -> Set[int]:
        """从入口块(bb 0) BFS-返回所有可达的基本块索引"""
        if not bb_boundaries:
            return set()
        reachable = {0}
        q = [0]
        adj = defaultdict(list)
        for src, dst in cfg_edges:
            adj[src].append(dst)

        while q:
            u = q.pop(0) if isinstance(q, list) else q.popleft()
            for v in adj.get(u, []):
                if v not in reachable:
                    reachable.add(v)
                    q.append(v)
        return reachable

    def _is_reachable_block(self,
                             instr_idx: int,
                             bb_boundaries: List[Tuple[int, int]],
                             reachable: Set[int]) -> bool:
        """判断指令所在基本块是否从入口可达"""
        for bb_id, (start, end) in enumerate(bb_boundaries):
            if start <= instr_idx < end:
                return bb_id in reachable
        return True  # 无法确定时保守认为可达

    def filter_batch(self,
                      reports: List[HeapOverflowReport],
                      min_level: FilterVerdict = FilterVerdict.LIKELY
                      ) -> List[HeapOverflowReport]:
        """批量过滤-仅保留指定级别以上的报告"""
        levels = {FilterVerdict.CONFIRMED: 3, FilterVerdict.LIKELY: 2,
                 FilterVerdict.UNCERTAIN: 1, FilterVerdict.FILTERED: 0}
        threshold = levels.get(min_level, 2)
        return [r for r in reports if levels.get(r.verdict, 0) >= threshold]
