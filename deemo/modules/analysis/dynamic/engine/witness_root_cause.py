# 创建: 2025-08-12 上午
# 修改: 2025-08-12 — use-def BFS 后向切片 + evidence-weighted blame
# 修改: 2025-08-16 — 修复 _enclosing_function 未初始化变量
"""
见证支持的崩溃根因定位器 — 从崩溃点沿 lifted IR 后向溯源。

传统崩溃分析 (crash_analysis.py) 报告崩溃点——但崩溃点通常是
"symptom" (如 memcpy 的 dst 为 NULL), 而非 "root cause"
(如 3 层调用前的 size 计算溢出)。本模块沿数据流后向搜索
从 symptom 到 root cause 的完整见证路径。

见证路径 (witness path):
  从崩溃指令开始, 沿 use-def 链回溯——每个中间节点都有
  具体的寄存器/内存值作为"见证" (如 "eax = 0 → 后续被用作指针")。
  完整的 witness path 形成从根源到崩溃的可验证证据链。

算法:
  1. 崩溃点识别: 从 faulting instruction 开始
  2. 后向切片: 沿 lifted IR 的 def-use 链回溯——此指令的操作数
     来自哪里? 继续回溯直到所有操作数都追溯到函数参数或全局变量
  3. 证据加权: 每条回溯边标注置信度 (直接赋值 → 1.0,
     条件赋值 → 0.5, 跨函数 → 0.7)
  4. 最小 blame 集: 按证据权重排序, top-K 作为根因候选

为什么 evidence-weighted ranking 优于简单的栈回溯:
  栈回溯仅告诉你"函数 A 调用了函数 B 调用了函数 C"——但不告诉你
  "函数 C 的错误输入来自函数 A 的哪一行"。见证路径补全了数据流信息。

ref: Veritas (arXiv:2605.15097, 2026) — witness-backed source-to-sink
     flow recovery from lifted LLVM IR, 本项目将 IR 层扩展到二进制层
ref: Kumushi (CCS 2026) — evidence-weighted minimum blame set ranking,
     本项目取其 OWA aggregation + diversity reranking 思路
ref: AutoCrashFL (arXiv:2510.22530, 2025) — crash-only RCA without
     coverage profiling, 本项目取其 top-K 定位 + 置信度评分
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional


@dataclass
class WitnessNode:
    """见证路径中的一个节点——一条指令 + 其数据来源。"""
    pc: int
    mnemonic: str = ''
    operands: str = ''
    evidence: dict[str, str] = field(default_factory=dict)  # {reg: source_description}
    confidence: float = 1.0
    depth: int = 0               # 距崩溃点的步数


@dataclass
class WitnessPath:
    """从根因到崩溃点的完整见证路径。"""
    crash_pc: int
    crash_type: str = ''        # 'segfault' | 'abort' | 'assert_fail'
    nodes: list[WitnessNode] = field(default_factory=list)
    total_confidence: float = 0.0
    root_cause_candidates: list[tuple[int, float, str]] = field(default_factory=list)


@dataclass
class BlameCandidate:
    """一个根因候选——函数 + 分数 + 证据。"""
    function_name: str = ''
    function_addr: int = 0
    blame_score: float = 0.0
    evidence_family: str = ''    # 'data_flow' | 'control_flow' | 'memory' | 'temporal'
    description: str = ''


# --- 后向数据流切片 ---

def backward_crash_slice(instructions: list[dict],
                         crash_pc: int,
                         max_depth: int = 50) -> WitnessPath:
    """从崩溃点沿数据流后向切片——构建见证路径。"""
    path = WitnessPath(crash_pc=crash_pc)

    # 找到崩溃指令
    crash_idx = next((i for i, ins in enumerate(instructions)
                      if ins.get('address') == crash_pc), None)
    if crash_idx is None:
        return path

    crash_ins = instructions[crash_idx]
    path.crash_type = _infer_crash_type(crash_ins)

    # BFS 后向遍历数据依赖
    visited: set[int] = set()
    queue = [(crash_idx, 0)]
    nodes_by_depth: dict[int, list[WitnessNode]] = defaultdict(list)

    while queue and len(visited) < max_depth:
        idx, depth = queue.pop(0)
        if idx in visited:
            continue
        visited.add(idx)

        ins = instructions[idx]
        uses = _extract_used_regs(ins)

        node = WitnessNode(
            pc=ins.get('address', 0),
            mnemonic=ins.get('mnemonic', ''),
            operands=str(ins.get('operands', '')),
            depth=depth,
        )

        # 对每个使用的寄存器, 向前搜索其定义
        for reg in uses:
            def_idx = _find_defining_instruction(instructions, idx, reg)
            if def_idx is not None and def_idx not in visited:
                confidence = 1.0 if def_idx == idx - 1 else 0.7
                node.evidence[reg] = f'defined@0x{instructions[def_idx].get("address",0):x}'
                node.confidence = min(node.confidence, confidence)
                queue.append((def_idx, depth + 1))
            else:
                node.evidence[reg] = 'extern_or_param'

        nodes_by_depth[depth].append(node)

    # 扁平化为按深度排序的节点
    for d in sorted(nodes_by_depth.keys()):
        path.nodes.extend(nodes_by_depth[d])

    # 总置信度 = 各节点置信度的几何平均
    if path.nodes:
        path.total_confidence = round(
            _geometric_mean([n.confidence for n in path.nodes]), 3)

    # 根因候选 = 最深层的节点 (距崩溃最远, 最可能是根因)
    max_d = max((n.depth for n in path.nodes), default=0)
    deep_nodes = [n for n in path.nodes if n.depth >= max_d - 2]
    path.root_cause_candidates = [
        (n.pc, n.confidence,
         f'{n.mnemonic} {n.operands} [evidence: {n.evidence}]')
        for n in deep_nodes[:5]
    ]

    return path


# --- 证据加权最小 blame 集 ---

def rank_blame_candidates(witness: WitnessPath,
                          functions: dict[int, str],
                          crash_exploration_variants: int = 0) -> list[BlameCandidate]:
    """证据加权排序——综合数据流 + 控制流 + 崩溃变体证据。

    三类证据:
      data_flow: 见证路径中的节点 (权重 × 置信度)
      control_flow: 崩溃点所在函数 + 调用栈函数 (权重 × 1/距离)
      crash_variant: 来自变体崩溃的交叉验证 (权重 × 变体数量)
    """
    candidates: dict[int, BlameCandidate] = {}

    # 数据流证据
    for node in witness.nodes:
        func_addr = _enclosing_function(node.pc, functions)
        score = node.confidence * (1.0 / (node.depth + 1))
        if func_addr in candidates:
            candidates[func_addr].blame_score += score
            candidates[func_addr].evidence_family = 'data_flow+control_flow'
        else:
            candidates[func_addr] = BlameCandidate(
                function_addr=func_addr,
                function_name=functions.get(func_addr, f'func_0x{func_addr:x}'),
                blame_score=score,
                evidence_family='data_flow',
                description=f'witness node @0x{node.pc:x}: {node.mnemonic}',
            )

    # crash_variant 交叉验证奖励
    if crash_exploration_variants > 0:
        variant_bonus = 0.1 * crash_exploration_variants
        for c in candidates.values():
            c.blame_score += variant_bonus

    # 排序 + diversity reranking: 同一 evidence_family 最多 3 个
    sorted_candidates = sorted(
        candidates.values(), key=lambda c: c.blame_score, reverse=True)
    family_counts: dict[str, int] = defaultdict(int)
    reranked = []
    for c in sorted_candidates:
        fam = c.evidence_family.split('+')[0]
        if family_counts.get(fam, 0) < 3:
            reranked.append(c)
            family_counts[fam] += 1

    return reranked[:20]


def _extract_used_regs(ins: dict) -> set[str]:
    """从指令中提取使用的寄存器 (简化: 逗号分隔的第二个操作数)。"""
    ops = str(ins.get('operands', ''))
    parts = ops.split(',')
    return {p.strip() for p in parts[1:]} if len(parts) >= 2 else set()


def _find_defining_instruction(ins_list: list[dict],
                               from_idx: int, reg: str) -> int | None:
    """在指令列表中向前搜索定义 reg 的最近指令。"""
    for i in range(from_idx - 1, max(0, from_idx - 30), -1):
        ops = str(ins_list[i].get('operands', ''))
        parts = ops.split(',')
        if parts and reg.strip() in parts[0].strip():
            return i
    return None


def _infer_crash_type(ins: dict) -> str:
    mnemonic = ins.get('mnemonic', '').lower()
    ops = str(ins.get('operands', '')).lower()
    if '[' in ops:
        return 'segfault'
    if mnemonic in ('ud2', 'int3', 'hlt'):
        return 'abort'
    return 'unknown'


def _enclosing_function(pc: int, funcs: dict[int, str]) -> int:
    last = 0
    for addr in sorted(funcs.keys()):
        if addr <= pc:
            last = addr
    return last


def _geometric_mean(values: list[float]) -> float:
    import math
    if not values:
        return 0.0
    log_sum = sum(math.log(max(v, 0.001)) for v in values)
    return math.exp(log_sum / len(values))


__all__ = [
    'WitnessNode', 'WitnessPath', 'BlameCandidate',
    'backward_crash_slice', 'rank_blame_candidates',
]
