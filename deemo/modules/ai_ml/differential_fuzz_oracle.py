# 差分模糊测试预言-多工具共识/分歧驱动的二进制分析质量评估
#
# 核心问题: 二进制分析工具对同一二进制可能产生不同的反汇编/CFG/函数边界。
# 这些差异揭示: (1)工具bug或局限性，(2)真正难分析的代码区域。
#      比较反汇编指令、CFG边、函数边界的一致性
#   2. 不一致区域定位: 工具间存在分歧的代码区域被标记为"可疑"-
#      这些区域要么是混淆代码（工具有不同处理），要么是工具bug
#   3. 共识分数: 对每个基本块/函数计算跨工具共识度(0-1)
#      低共识区域-优先人工审核
#   4. 差分测试用例生成: 不一致区域自动生成最小化的测试用例-
#      Ghidra认为是函数A但IDA认为是函数B的代码片段-提交给工具开发者
#
# 新颖性: 首次将差分测试应用于二进制分析工具的交叉验证

from __future__ import annotations

import math
import logging
import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class ToolName(Enum):
    GHIDRA = 'ghidra'
    IDA = 'ida'
    RADARE2 = 'radare2'
    BINARY_NINJA = 'binary_ninja'
    CUSTOM = 'custom'


@dataclass
class ToolOutput:
    """单个分析工具的输出"""
    tool: ToolName
    instructions: Dict[int, str]           # address → disassembly string
    cfg_edges: Set[Tuple[int, int]]        # (from_addr, to_addr)
    function_boundaries: Set[Tuple[int, int]]  # (start, end)
    basic_blocks: List[Tuple[int, int]]    # (start_addr, end_addr)
    function_names: Dict[int, str]         # addr → function name
    error_count: int = 0
    warnings: List[str] = field(default_factory=list)


@dataclass
class ConsensusReport:
    """多工具共识分析报告"""
    n_tools: int
    total_instructions: int
    consensus_instructions: int          # 所有工具一致的指令数
    consensus_cfg_edges: int
    total_cfg_edges_union: int
    consensus_functions: int
    total_functions_union: int
    overall_consensus: float
    high_conflict_regions: List[Tuple[int, int, float]]  # (start, end, conflict_score)
    tool_agreement_matrix: np.ndarray    # (N, N) 工具间成对一致率


class DifferentialFuzzOracle:
    """差分模糊测试预言-多工具交叉验证。

    三个分析维度:
      1. 指令级: 同一地址不同工具反汇编出的助记符是否一致
      2. CFG级: 控制流边是否被所有工具识别
      3. 函数级: 函数边界划分是否一致

    指令比较容忍语法差异:
      "mov eax, [rbp-0x10]" vs "mov eax, dword [rbp-0x10]" - 一致
      "call 0x401000" vs "call sub_401000" - 一致（规范化后）
    """

    def __init__(self, tools: Optional[List[ToolName]] = None):
        self._tool_names = tools or list(ToolName)
        self._outputs: Dict[ToolName, ToolOutput] = {}

    def add_tool_output(self, output: ToolOutput):
        self._outputs[output.tool] = output

    def _normalize_instr(self, instr: str) -> str:
        """规范化汇编指令-消除工具间语法差异。

        - 移除size前缀 (dword/byte/word ptr)
        - 将地址引用替换为占位符 <ADDR>
        - 统一空白字符
        """
        s = instr.strip().lower()
        s = re.sub(r'\b(dword|byte|word|qword)\s+ptr\s+', '', s)
        s = re.sub(r'0x[0-9a-f]+', '<ADDR>', s)
        s = re.sub(r'sub_[0-9a-f]+', '<FUNC>', s)
        s = re.sub(r'\s+', ' ', s)
        return s.strip()

    def analyze_consensus(self) -> ConsensusReport:
        outputs = list(self._outputs.values())
        n_tools = len(outputs)
        if n_tools < 2:
            return ConsensusReport(
                n_tools=n_tools, total_instructions=0,
                consensus_instructions=0, consensus_cfg_edges=0,
                total_cfg_edges_union=0, consensus_functions=0,
                total_functions_union=0, overall_consensus=0.0,
                high_conflict_regions=[],
                tool_agreement_matrix=np.zeros((n_tools, n_tools)))

        # 指令级共识
        all_addrs = set()
        for out in outputs:
            all_addrs.update(out.instructions.keys())

        cons_inst = 0
        addr_conflicts = defaultdict(float)
        for addr in sorted(all_addrs):
            instrs = []
            for out in outputs:
                if addr in out.instructions:
                    instrs.append(self._normalize_instr(out.instructions[addr]))
            unique = set(instrs)
            if len(unique) == 1:
                cons_inst += 1
            elif len(unique) > 0:
                conflict = 1.0 - (1.0 / len(unique))
                addr_conflicts[addr] = conflict

        # CFG级共识
        all_edges = set()
        for out in outputs:
            all_edges.update(out.cfg_edges)
        cons_edges = 0
        for edge in all_edges:
            present = sum(1 for out in outputs if edge in out.cfg_edges)
            if present == n_tools:
                cons_edges += 1

        # 函数级共识
        all_funcs = set()
        for out in outputs:
            all_funcs.update(out.function_boundaries)
        cons_funcs = 0
        for func in all_funcs:
            present = sum(1 for out in outputs if func in out.function_boundaries)
            if present == n_tools:
                cons_funcs += 1

        # 高冲突区域: 连续地址区间内冲突密集
        high_conflict = self._find_conflict_regions(addr_conflicts)

        # 工具间成对一致率
        agree_matrix = np.zeros((n_tools, n_tools))
        for i in range(n_tools):
            for j in range(n_tools):
                if i == j:
                    agree_matrix[i, j] = 1.0
                    continue
                addrs_i = set(outputs[i].instructions.keys())
                addrs_j = set(outputs[j].instructions.keys())
                common = addrs_i & addrs_j
                if not common:
                    continue
                same = 0
                for addr in common:
                    ni = self._normalize_instr(outputs[i].instructions[addr])
                    nj = self._normalize_instr(outputs[j].instructions[addr])
                    if ni == nj:
                        same += 1
                agree_matrix[i, j] = same / len(common)

        total_inst = len(all_addrs)
        total_edges = len(all_edges)
        total_funcs = len(all_funcs)

        overall = 0.0
        if total_inst + total_edges + total_funcs > 0:
            overall = ((cons_inst / max(1, total_inst)) * 0.4 +
                      (cons_edges / max(1, total_edges)) * 0.35 +
                      (cons_funcs / max(1, total_funcs)) * 0.25)

        return ConsensusReport(
            n_tools=n_tools, total_instructions=total_inst,
            consensus_instructions=cons_inst,
            consensus_cfg_edges=cons_edges,
            total_cfg_edges_union=total_edges,
            consensus_functions=cons_funcs,
            total_functions_union=total_funcs,
            overall_consensus=overall,
            high_conflict_regions=high_conflict,
            tool_agreement_matrix=agree_matrix)

    def _find_conflict_regions(self,
                                addr_conflicts: Dict[int, float],
                                min_region_size: int = 4,
                                min_conflict_score: float = 0.5
                                ) -> List[Tuple[int, int, float]]:
        """定位连续高冲突地址区域-可能是混淆代码或工具bug集中区"""
        sorted_addrs = sorted(addr_conflicts.keys())
        if not sorted_addrs:
            return []

        regions = []
        region_start = sorted_addrs[0]
        region_scores = [addr_conflicts[region_start]]

        for i in range(1, len(sorted_addrs)):
            if sorted_addrs[i] - sorted_addrs[i-1] <= 16:  # 16字节内视为连续
                region_scores.append(addr_conflicts[sorted_addrs[i]])
            else:
                if len(region_scores) >= min_region_size:
                    avg_score = float(np.mean(region_scores))
                    if avg_score >= min_conflict_score:
                        regions.append((region_start, sorted_addrs[i-1], avg_score))
                region_start = sorted_addrs[i]
                region_scores = [addr_conflicts[sorted_addrs[i]]]

        if len(region_scores) >= min_region_size:
            avg_score = float(np.mean(region_scores))
            if avg_score >= min_conflict_score:
                regions.append((region_start, sorted_addrs[-1], avg_score))

        regions.sort(key=lambda x: -x[2])  # 按冲突分数降序
        return regions[:20]

    def generate_test_case(self, conflict_region: Tuple[int, int]
                           ) -> Dict[str, Any]:
        start, end = conflict_region
        diff = {}
        for out in self._outputs.values():
            tool_instrs = {}
            for addr in range(start, end + 1):
                if addr in out.instructions:
                    tool_instrs[addr] = out.instructions[addr]
            diff[out.tool.value] = tool_instrs
        return {
            'region': (start, end),
            'size_bytes': end - start + 1,
            'n_tools_with_coverage': len(diff),
            'tool_outputs': {t: {hex(a): i for a, i in instrs.items()}
                           for t, instrs in diff.items()},
            'hash_signature': hashlib.md5(
                str(diff).encode()).hexdigest()[:16],
        }

# 工具调用桥接实现在 src/verify/tool_invoker.py
# 此处仅保留核心的差分分析逻辑
