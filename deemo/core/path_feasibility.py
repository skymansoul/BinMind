"""
路径可行性检查 —— 验证alloc和store是否共存于同一可行执行路径。

静态检测的常见误报: malloc和后续store位于不同分支,
运行时只执行其中一条路径, 但静态分析将它们视为同一路径上的操作。

例: if(cond) p=malloc(64); else p=malloc(256);
    p[128]=0; // cond为false时不溢出, 为true时溢出
静态分析看到"malloc(64)"和"p[128]"→标记溢出。
但p[128]可能总是执行在malloc(256)的路径上→实际不溢出。

本模块做轻量路径可行性判定:
  1. 从alloc点正向DFS到store点, 收集路径条件
  2. 若路径条件包含对alloc_size的约束→评估是否排除溢出
  3. 若alloc和store之间有free→路径依然"可行"(UAF场景)

限制: 不做完整约束求解(太重), 只分析直接的cmp/jcc条件。
对加壳/混淆代码回退到保守判定(标记为"可能可行")。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class PathVerdict:
    """路径可行性判定"""
    alloc_addr: int
    store_addr: int
    feasible: bool            # True=alloc和store可能共存于同一路径
    condition_summary: str    # 路径条件摘要
    confidence: float         # 0.0-1.0
    evidence: str = ""


def check_path_feasibility(
    disasm_lines: List[str],
    alloc_line_idx: int,
    store_line_idx: int,
) -> PathVerdict:
    """检查alloc和store是否在可行路径上共存。

    简化: 若alloc和store之间存在条件分支,
    且分支条件约束了alloc_size→可能路径不共存→标记为不可行。
    否则保守地标记为可行(宁可保留也不误删)。
    """
    if alloc_line_idx < 0 or store_line_idx < 0:
        return PathVerdict(0, 0, True, "边界外(保守)", 0.1)
    if alloc_line_idx >= store_line_idx:
        return PathVerdict(0, 0, False, "store在alloc之前(不可能)", 0.95,
                          "store指令地址小于alloc指令地址——不可能先写后分配")

    # 提取alloc和store之间的条件分支
    branches = _extract_branches(disasm_lines, alloc_line_idx, store_line_idx)

    if not branches:
        return PathVerdict(alloc_line_idx, store_line_idx, True,
                          "无分支——单路径可达", 0.7,
                          "alloc到store之间无条件跳转阻止路径")

    # 分析分支条件是否约束了分配大小
    for br in branches:
        if br.get('constrains_size', False):
            return PathVerdict(alloc_line_idx, store_line_idx, False,
                              f"分支{br.get('condition','?')}约束分配大小",
                              0.6,
                              f"条件{br.get('condition','')}可能使alloc与store路径分离")

    # 无条件约束分配大小 → 标记为可行(保守)
    return PathVerdict(alloc_line_idx, store_line_idx, True,
                      f"{len(branches)}个分支但未约束分配大小", 0.5,
                      "分支存在但未明确约束alloc_size——保守判定可行")


def _extract_branches(
    disasm_lines: List[str], start: int, end: int
) -> List[Dict]:
    """提取start到end之间的条件分支指令。"""
    branches = []
    for i in range(start, min(end, len(disasm_lines))):
        line = disasm_lines[i].strip().lower()
        if not line or line.startswith(';'):
            continue
        # 条件跳转: jne/je/jl/jg/jb/ja/jle/jge/jbe/jae
        jcc_match = re.search(r'(jne|je|jz|jnz|jl|jle|jg|jge|jb|jbe|ja|jae)\s+', line)
        if jcc_match:
            # 向前搜索cmp/test条件
            condition = ""
            constrains_size = False
            for j in range(i - 1, max(start, i - 5), -1):
                prev_line = disasm_lines[j].strip().lower()
                if 'cmp' in prev_line:
                    condition = prev_line
                    # 检查cmp是否涉及"大小"相关寄存器
                    if any(r in prev_line for r in ('rdi', 'esi', 'edx', 'rax')):
                        constrains_size = True
                    break
            branches.append({
                'addr': i, 'jcc': jcc_match.group(1),
                'condition': condition,
                'constrains_size': constrains_size,
            })
    return branches


__all__ = ["PathVerdict", "check_path_feasibility"]
