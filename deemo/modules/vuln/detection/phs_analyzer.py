# -*- coding: utf-8 -*-
# 创建: 2026-08-01  |  指针危险分析器
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
指针危险评分——二进制级别的轻量静态指针操作安全性评估。

技术问题:
  2024-2025年的研究表明, 纯静态、无需执行的二进制级
  内存安全违规预测仍然是一个未解决的问题。
  现有系统要么需要源码(BSan/POM), 要么需要动态插桩(AFD),
  要么仅做崩溃后的根因分类(CSSA/Lancet)。

  根本矛盾: 编译过程丢失了类型/边界/所有权等语义信息,
  而精确的静态指针分析依赖于这些信息。

  然而, 即使没有完整的语义信息, 仍可从二进制中提取
  指针操作的危险信号——接近似而非证明。

解决方案:
  指针危险评分(PHS)——不尝试证明违规(需要完全语义),
  而是基于从二进制可恢复的启发式对每个指针操作进行危险评分:
    1. 边界证据: 指针使用前是否存在比较(cmp/test)?
    2. 溯源清晰度: 指针能否追溯到分配点?
    3. 空指针检查: 解引用前是否存在NULL检查?
    4. 读写区分: 写操作比读操作更危险
    5. 循环上下文: 指针访问是否在循环内(重复使用→溢出可能性)
    6. 算术证据: 指针上是否存在算术操作(偏移计算)?

  输出: 每指针操作的PHS分数[0,1]+危险信号列表
  → 高分数操作→优先人工审查→可能发现未知内存安全漏洞

技术定位:
  与CSSA互补——CSSA分析崩溃后状态, PHS预测崩溃前危险
  与DABSS互补——DABSS合成模糊测试种子, PHS引导种子目标
  与CADE互补——CADE发现整体异常函数, PHS精确定位函数内危险操作
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

_log = logging.getLogger(__name__)


# ============================================================================
# 指针操作与危险评分
# ============================================================================


@dataclass
class PointerOperation:
    """单次指针操作——二进制中一次内存访问指令"""
    address: int                   # 指令地址
    instruction: str = ""          # 反汇编
    # 操作属性
    is_write: bool = False         # 写(store) vs 读(load)
    operand_register: str = ""     # 指针所在寄存器
    offset: int = 0                # 偏移量(立即数部分)
    # 危险信号
    has_bounds_check: bool = False       # 使用前有cmp/test?
    null_check_before: bool = False      # 有NULL检查?
    traceable_to_allocation: bool = False  # 可追溯到分配点?
    inside_loop: bool = False             # 在循环内?
    has_pointer_arithmetic: bool = False  # 指针上有算术操作?
    uses_user_input: bool = False         # 操作数来自外部输入?
    # 上下文
    containing_function: str = ""
    nearby_dangerous_calls: List[str] = field(default_factory=list)


@dataclass
class HazardScore:
    """单次指针操作的危险评分"""
    operation: PointerOperation
    # 分维度评分[0,1]
    bounds_score: float = 0.0       # 边界检查缺失→高分
    provenance_score: float = 0.0   # 溯源不清→高分
    null_check_score: float = 0.0   # NULL检查缺失→高分
    operation_score: float = 0.0    # 写操作→高分
    context_score: float = 0.0      # 循环内+用户输入→高分
    # 综合
    overall_hazard: float = 0.0     # 加权聚合[0,1]
    hazard_level: str = "LOW"       # CRITICAL|HIGH|MEDIUM|LOW


# ============================================================================
# 指针危险分析器
# ============================================================================


class PointerHazardAnalyzer:
    """二进制级指针操作危险评分——轻量静态启发式。

    设计原则:
      - 仅分析可从二进制直接恢复的证据(无类型推断/符号执行)
      - 宁可误报不可漏报(安全工具的基础偏向)
      - 输出可操作的危险评分+信号列表(非二元分类)

    与BSan(IEEE/ACM ICSE 2025)的差异:
      BSan: 静态分析+动态插桩混合→需执行
      PHS: 纯静态→无需执行→可集成至CI/CD的离线分析阶段
    """

    # 指针操作指令模式
    _PTR_ACCESS_PATTERNS = [
        r'mov\s+.*\[(\w+)',         # mov reg, [reg] 或 mov [reg], reg
        r'lea\s+\w+,\s*\[(\w+)',   # lea reg, [reg+offset]
        r'(?:add|sub)\s+\[(\w+)',   # add/sub [reg], val
        r'(?:push|pop)\s+',          # push/pop (栈指针操作)
    ]

    # 边界检查指令
    _BOUNDS_CHECK_PATTERNS = [
        r'cmp\s+\w+,\s*(?:0x\w+|\d+)',
        r'test\s+\w+,\s*\w+',
    ]

    def __init__(self):
        pass

    def analyze_function(self, instructions: List[str],
                           function_name: str = "",
                           base_addr: int = 0x400000
                           ) -> List[HazardScore]:
        """分析单个函数中的所有指针操作并评分。

        参数:
          instructions: 反汇编行列表
          function_name: 函数名
          base_addr: 基址

        返回HazardScore列表(仅含指针操作, 按危险降序)。
        """
        # 定位指针操作
        ptr_ops = self._find_pointer_ops(instructions, base_addr, function_name)

        # 对每个指针操作搜集危险信号
        scores = []
        for op in ptr_ops:
            # 边界检查——在指针操作前5条指令中搜索cmp/test
            op_idx = self._find_insn_index(instructions, op.address, base_addr)
            if op_idx >= 0:
                nearby = instructions[max(0, op_idx - 5):op_idx]
                op.has_bounds_check = any(
                    re.search(p, insn) for insn in nearby
                    for p in self._BOUNDS_CHECK_PATTERNS)
                op.null_check_before = any(
                    'test' in insn.lower() and op.operand_register.lower() in insn.lower()
                    for insn in nearby)
                op.inside_loop = self._is_inside_loop(instructions, op_idx)
                op.has_pointer_arithmetic = self._has_ptr_arith(
                    instructions, op_idx, op.operand_register)

            # 评分
            hazard = self._score(op)
            scores.append(hazard)

        scores.sort(key=lambda s: s.overall_hazard, reverse=True)
        return scores

    def _find_pointer_ops(self, instructions: List[str],
                            base_addr: int,
                            func_name: str) -> List[PointerOperation]:
        """在指令序列中定位指针操作"""
        ops = []
        for i, insn_str in enumerate(instructions):
            # 匹配内存访问: [reg] 或 [reg+offset]
            mem_match = re.search(r'\[(\w+)([+-]\w+)?\]', insn_str)
            if not mem_match:
                continue

            addr = self._extract_addr(insn_str, base_addr, i)
            reg = mem_match.group(1)
            is_write = any(kw in insn_str.split()[0].lower()
                           for kw in ('mov', 'add', 'sub', 'and', 'or', 'xor')) and \
                       insn_str.split(',')[0].strip().startswith('[')

            offset_str = mem_match.group(2) or ''
            try:
                offset = int(offset_str, 16) if '0x' in offset_str else (
                    int(offset_str) if offset_str else 0)
            except ValueError:
                offset = 0

            ops.append(PointerOperation(
                address=addr, instruction=insn_str.strip(),
                is_write=is_write, operand_register=reg,
                offset=offset, containing_function=func_name))

        return ops

    def _score(self, op: PointerOperation) -> HazardScore:
        """对单次指针操作进行多维度危险评分"""
        # 边界检查缺失→高分(最关键的信号)
        bounds = 0.8 if not op.has_bounds_check else 0.1
        # 溯源不清→高分(无法确定指针来源)
        provenance = 0.7 if not op.traceable_to_allocation else 0.2
        # NULL检查缺失→中高分(可能导致空指针解引用)
        null_ck = 0.6 if not op.null_check_before else 0.1
        # 写操作→危险(可能破坏内存)
        op_score = 0.5 if op.is_write else 0.2
        # 循环内+有算术→高风险(累积溢出)
        context = 0.0
        if op.inside_loop:
            context += 0.3
        if op.has_pointer_arithmetic:
            context += 0.25
        if op.uses_user_input:
            context += 0.25
        context = min(1.0, context)

        # 加权聚合(边界检查缺失权重最高)
        overall = (0.35 * bounds + 0.20 * provenance + 0.15 * null_ck +
                    0.15 * op_score + 0.15 * context)

        level = ("CRITICAL" if overall >= 0.7 else
                 "HIGH" if overall >= 0.5 else
                 "MEDIUM" if overall >= 0.3 else "LOW")

        return HazardScore(
            operation=op, bounds_score=bounds, provenance_score=provenance,
            null_check_score=null_ck, operation_score=op_score,
            context_score=context, overall_hazard=round(overall, 3),
            hazard_level=level)

    def _find_insn_index(self, insns: List[str], addr: int,
                           base: int) -> int:
        for i, insn in enumerate(insns):
            if self._extract_addr(insn, base, i) == addr:
                return i
        return -1

    def _extract_addr(self, insn: str, base: int, idx: int) -> int:
        m = re.match(r'\s*(?:0x)?([0-9a-fA-F]+)', insn.strip())
        if m:
            return int(m.group(1), 16)
        return base + idx * 4

    def _is_inside_loop(self, insns: List[str], idx: int) -> bool:
        """启发式循环检测——在指针操作前搜索向后跳转或循环模式"""
        for j in range(max(0, idx - 10), idx):
            insn = insns[j].lower()
            if any(kw in insn for kw in ('jmp', 'jne', 'je', 'loop',
                                           'dec', 'inc')):
                # 检查跳转目标是否在当前指令之前(向后跳转=循环)
                m = re.search(r'(?:0x)?([0-9a-fA-F]+)', insn)
                if m:
                    try:
                        target = int(m.group(1), 16)
                        if target < self._extract_addr(insns[idx], 0, idx):
                            return True
                    except ValueError:
                        pass
        return False

    def _has_ptr_arith(self, insns: List[str], idx: int,
                         reg: str) -> bool:
        """检查指针寄存器上是否有算术操作(add/sub/shl)"""
        for j in range(max(0, idx - 8), idx):
            insn = insns[j].lower()
            if reg.lower() in insn and any(
                    op in insn for op in ('add', 'sub', 'shl', 'sal', 'imul')):
                return True
        return False


__all__ = [
    "PointerOperation",
    "HazardScore",
    "PointerHazardAnalyzer",
]
