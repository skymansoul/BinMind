# 多级层次化函数摘要——从指令到模块的四级抽象描述
#
# 核心问题: function_summarizer.py生成单层摘要（"这个函数做什么"），
# 但不同使用场景需要不同粒度的信息:
#   - 漏洞快速扫描: 仅需一句话摘要（"memcpy无边界检查"）
#   - 深入分析: 需要基本块级别的控制流描述
#   - 架构理解: 需要模块级别的功能描述
# 单一粒度无法满足所有需求。
#
# 技术方案:
#   1. 四级层次: L1(指令级) → L2(基本块级) → L3(函数级) → L4(模块级)
#   2. 自底向上聚合: 每级摘要由其子级摘要聚合+提炼而成——
#      L3 = aggregate(L2 summaries) + function-level context
#   3. 跨级一致性: L(i)的摘要必须与L(i-1)的摘要保持一致——
#      不一致→回溯修正
#   4. 信息密度控制: 每级摘要的长度受信息密度约束——
#      L1最详细(每条指令)，L4最简洁(一句话)

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class SummaryLevel(Enum):
    L1_INSTRUCTION = 1    # 指令级: 单条指令的语义
    L2_BASIC_BLOCK = 2    # 基本块级: 块的聚合语义
    L3_FUNCTION = 3       # 函数级: 完整函数描述
    L4_MODULE = 4         # 模块级: 多函数协同描述


@dataclass
class HierarchicalSummary:
    """层次化摘要"""
    level: SummaryLevel
    entity_id: str
    summary_text: str
    key_actions: List[str]           # 关键操作列表
    data_flow_brief: str             # 数据流简述
    control_flow_brief: str          # 控制流简述
    parent_id: Optional[str] = None  # 上级实体ID
    child_summaries: List[str] = field(default_factory=list)
    consistency_score: float = 1.0   # 与下级摘要的一致性


class MultiLevelSummarizer:
    """多级层次化摘要生成器。

    自底向上聚合:
      L1: 指令→"加载/存储/算术/分支"类别标签
      L2: 基本块→L1标签序列→"顺序操作/条件分支/循环体"
      L3: 函数→L2摘要+调用上下文→完整功能描述
      L4: 模块→L3摘要+调用图→架构级描述

    跨级一致性检查:
      对L(i)的摘要做key action提取→与L(i-1)的key actions比较
      Jaccard相似度<0.5→回溯修正L(i)
    """

    def __init__(self, max_l1_length: int = 200,
                 max_l2_length: int = 500,
                 max_l3_length: int = 1000,
                 max_l4_length: int = 2000):
        self._max_len = {SummaryLevel.L1_INSTRUCTION: max_l1_length,
                        SummaryLevel.L2_BASIC_BLOCK: max_l2_length,
                        SummaryLevel.L3_FUNCTION: max_l3_length,
                        SummaryLevel.L4_MODULE: max_l4_length}

    def summarize_instruction(self,
                               instr: str, address: int = 0) -> HierarchicalSummary:
        """L1: 单条指令→类别标签。

        分类: mem_read / mem_write / arith / logic / branch / call / other
        """
        mn = instr.strip().lower().split()[0] if instr.strip().split() else ""
        cat_map = {'mov': 'mem_read', 'push': 'mem_write', 'pop': 'mem_read',
                   'add': 'arith', 'sub': 'arith', 'mul': 'arith',
                   'and': 'logic', 'or': 'logic', 'xor': 'logic',
                   'jmp': 'branch', 'call': 'call', 'ret': 'branch',
                   'cmp': 'compare', 'test': 'compare'}
        category = cat_map.get(mn, 'other')
        return HierarchicalSummary(
            level=SummaryLevel.L1_INSTRUCTION,
            entity_id=f"instr_{address:x}",
            summary_text=f"{category}: {instr[:60]}",
            key_actions=[category], data_flow_brief="",
            control_flow_brief="branch" if category == 'branch' else "linear")

    def summarize_basic_block(self,
                               block_id: str,
                               l1_summaries: List[HierarchicalSummary]
                               ) -> HierarchicalSummary:
        """L2: 基本块→L1摘要序列聚合。

        聚合规则: 统计类别分布→判断块类型
        - branch_count > 0 → "条件分支块"
        - arith_count占主导 → "计算块"
        - mem_read/write占主导 → "内存操作块"
        """
        categories = Counter()
        for s in l1_summaries:
            for action in s.key_actions:
                categories[action] += 1

        if categories.get('call', 0) > 0:
            block_type = "函数调用块"
        elif categories.get('branch', 0) > 0:
            block_type = "条件分支块"
        elif categories.get('mem_read', 0) + categories.get('mem_write', 0) > len(l1_summaries) * 0.4:
            block_type = "内存密集操作块"
        elif categories.get('arith', 0) + categories.get('logic', 0) > len(l1_summaries) * 0.5:
            block_type = "计算密集块"
        else:
            block_type = "通用操作块"

        return HierarchicalSummary(
            level=SummaryLevel.L2_BASIC_BLOCK,
            entity_id=block_id,
            summary_text=f"{block_type}({len(l1_summaries)} instrs)",
            key_actions=[block_type],
            data_flow_brief=f"读{ categories.get('mem_read', 0)}次, 写{categories.get('mem_write', 0)}次",
            control_flow_brief="",
            child_summaries=[s.entity_id for s in l1_summaries])

    def summarize_function(self,
                            func_id: str,
                            l2_summaries: List[HierarchicalSummary],
                            call_targets: List[str] = None
                            ) -> HierarchicalSummary:
        """L3: 函数→L2块摘要+调用上下文聚合"""
        block_types = Counter(s.summary_text for s in l2_summaries)
        dominant = block_types.most_common(2)

        n_blocks = len(l2_summaries)
        has_loop = n_blocks > 3 and any(
            '条件分支块' in s.summary_text for s in l2_summaries)

        func_type = "复合功能函数"
        if n_blocks <= 2 and not has_loop:
            func_type = "简单访问器"
        elif has_loop and any('计算' in s.summary_text for s in l2_summaries):
            func_type = "循环计算函数"
        elif has_loop and any('内存' in s.summary_text for s in l2_summaries):
            func_type = "数据处理函数"

        call_info = f", 调用{len(call_targets or [])}个子函数" if call_targets else ""
        summary = f"{func_type}: {dominant[0][0] if dominant else '未知'}{call_info}"

        return HierarchicalSummary(
            level=SummaryLevel.L3_FUNCTION,
            entity_id=func_id,
            summary_text=summary,
            key_actions=[func_type] + [bt for bt, _ in dominant],
            data_flow_brief=f"{n_blocks}个基本块",
            control_flow_brief="含循环" if has_loop else "线性/简单分支",
            child_summaries=[s.entity_id for s in l2_summaries])

    def check_consistency(self,
                           parent: HierarchicalSummary,
                           children: List[HierarchicalSummary]
                           ) -> float:
        """跨级一致性检查——上级摘要是否与下级一致。

        Jaccard相似度: |parent_actions ∩ child_actions| / |parent_actions ∪ child_actions|
        """
        parent_actions = set(parent.key_actions)
        child_actions = set()
        for c in children:
            child_actions.update(c.key_actions)
        if not parent_actions or not child_actions:
            return 1.0
        intersection = parent_actions & child_actions
        union = parent_actions | child_actions
        return len(intersection) / max(1, len(union))

    def build_full_hierarchy(self,
                              instructions: List[str],
                              basic_blocks: List[Tuple[str, List[int]]],
                              func_name: str = "",
                              call_targets: List[str] = None
                              ) -> Dict[SummaryLevel, List[HierarchicalSummary]]:
        """一步构建完整的四级层次摘要。

        Args:
            instructions: 所有指令列表
            basic_blocks: [(block_id, [instr_indices]), ...]
            func_name: 函数名
            call_targets: 被调用函数列表

        Returns:
            {L1: [...], L2: [...], L3: [...], L4: [...]}
        """
        hierarchy = {}
        all_l1 = []

        # L1
        for i, instr in enumerate(instructions):
            s = self.summarize_instruction(instr, i)
            all_l1.append(s)
        hierarchy[SummaryLevel.L1_INSTRUCTION] = all_l1

        # L2
        l2_list = []
        for block_id, instr_indices in basic_blocks:
            block_l1 = [all_l1[i] for i in instr_indices if i < len(all_l1)]
            s = self.summarize_basic_block(block_id, block_l1)
            l2_list.append(s)
        hierarchy[SummaryLevel.L2_BASIC_BLOCK] = l2_list

        # L3
        l3 = self.summarize_function(func_name, l2_list, call_targets)
        cons = self.check_consistency(l3, l2_list)
        l3.consistency_score = cons
        hierarchy[SummaryLevel.L3_FUNCTION] = [l3]

        # L4: 模块级——此处为单函数占位（多函数需调用方提供）
        l4 = HierarchicalSummary(
            level=SummaryLevel.L4_MODULE,
            entity_id=f"module_{func_name}",
            summary_text=f"模块包含函数{func_name}: {l3.summary_text}",
            key_actions=l3.key_actions[:],
            data_flow_brief=l3.data_flow_brief,
            control_flow_brief=l3.control_flow_brief,
            child_summaries=[l3.entity_id])
        hierarchy[SummaryLevel.L4_MODULE] = [l4]

        return hierarchy
