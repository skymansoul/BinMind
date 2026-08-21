# 抽象状态对匹配: binary IR vs pseudocode 的块级状态提取
# 三维忠实度: 控制流(0.4) + 变量活性(0.35) + 副作用(0.25)
# 修复语义比较: 使用块数/指令密度/约束结构等架构级特征替代精确变量名比较
#   核心假设: binary IR 和 pseudocode 的变量命名空间天然不同--比较结构而非名称

"""反编译语义忠实度评分 - 无需 ground truth 的反编译质量度量

现有反编译质量评估方法的局限:
  - 重编译验证: 需要完整的重编译工具链, 对嵌入式/非标准 ABI 不适用
  - 重执行测试 (LLM4Decompile): 需要可执行环境 + 测试用例, 覆盖不完整
  - 人工审查: 不可扩展, 主观

本模块的方法: 同时反编译->抽象状态 和 binary IR->抽象状态
比较两抽象状态序列的相似度--高相似度 = 高忠实度

抽象状态包含:
  1. 活跃变量集合 (哪些变量在两个表示中都存在)
  2. 约束类型分布 (路径条件在两种表示中的形状)
  3. 内存副作用 (写入/读取的内存位置摘要)

三变量/约束/副作用 Jaccard 相似度的加权平均即忠实度分数

技术前提: 不需要源码、不需要重编译、不需要执行
仅需 binary IR (来自 Ghidra/r2) 和反编译伪代码 (来自 decomp_ai)

与现有工作的差异:
  - CoDe-R: 重编译+Bleu -> 本模块: 抽象语义比较, 无需编译
  - SALT4Decompile: LLM 引导 -> 本模块: 评分而非引导
  - SK2Decompile: RL 奖励 -> 本模块: 无训练的确定性度量
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 抽象状态定义

@dataclass
class AbstractBlockState:
    """单个程序点的抽象语义状态"""
    block_addr: int = 0
    # 活跃变量--归一化后的变量名集合
    live_variables: Set[str] = field(default_factory=set)
    # 约束摘要--条件表达式中出现的操作符类型
    constraint_ops: Set[str] = field(default_factory=set)
    # 内存副作用--写入/读取的内存区域 (粗粒度: 栈/堆/全局/未知)
    memory_reads: Set[str] = field(default_factory=set)
    memory_writes: Set[str] = field(default_factory=set)
    # 调用目标
    call_targets: Set[str] = field(default_factory=set)


# Binary IR -> 抽象状态提取

def _extract_binary_abstract_states(
    blocks_ir: Dict[int, List[str]],
    edges: List[Tuple[int, int]],
) -> Dict[int, AbstractBlockState]:
    """从二进制 IR (基本块指令列表) 提取每块的抽象状态

    归一化: 寄存器名替换为规范形式 (复用 ir_canonical_passes 的重命名表)
    内存引用分类: [rsp±C]->stack, [rip±C]->global, [reg]->unknown
    """
    states: Dict[int, AbstractBlockState] = {}

    # 寄存器->变量重命名 (轻量版)
    reg_map = {
        'rax': 'v0', 'eax': 'v0', 'rbx': 'v1', 'ebx': 'v1',
        'rcx': 'v2', 'ecx': 'v2', 'rdx': 'v3', 'edx': 'v3',
        'rsi': 'v4', 'esi': 'v4', 'rdi': 'v5', 'edi': 'v5',
        'rbp': 'v6', 'rsp': 'v7', 'r8': 'v8', 'r9': 'v9',
    }

    for bid, insns in blocks_ir.items():
        state = AbstractBlockState(block_addr=bid)
        text = ' '.join(insns).lower()

        # 活跃变量: 出现在指令中的寄存器->归一化名
        for reg_raw, var in reg_map.items():
            if re.search(r'\b' + reg_raw + r'\b', text):
                state.live_variables.add(var)

        # 约束操作符
        for op in ('cmp', 'test', 'je', 'jne', 'jb', 'jae', 'jl', 'jg'):
            if op in text:
                state.constraint_ops.add(op)

        # 内存副作用分类
        if re.search(r'\[rsp[+-]', text) or re.search(r'\[esp[+-]', text):
            state.memory_reads.add('stack')
        if re.search(r'\[rip[+-]', text):
            state.memory_reads.add('global')
        if 'mov [' in text or 'mov qword [' in text or 'mov dword [' in text:
            if 'rsp' in text or 'rbp' in text:
                state.memory_writes.add('stack')
            else:
                state.memory_writes.add('unknown')

        # 调用目标
        for m in re.finditer(r'call\s+(\w[\w.@]*)', text):
            state.call_targets.add(m.group(1).lower())

        states[bid] = state

    return states


# Pseudocode -> 抽象状态提取

def _extract_pseudocode_abstract_states(
    pseudocode_lines: List[str],
) -> List[AbstractBlockState]:
    """从反编译伪代码提取抽象状态--与 binary IR 状态对齐

    伪代码的每个"语句"或"基本块对应行"映射为一个抽象状态
    变量名保留原样--binary IR 已归一化
    内存分类: 局部变量->stack, 全局变量->global, 指针参数->unknown
    """
    states: List[AbstractBlockState] = []
    current_state = AbstractBlockState()

    var_pattern = re.compile(r'\b([a-zA-Z_]\w{0,31})\b')
    # 排除关键字
    keywords = {'if', 'else', 'while', 'for', 'return', 'goto', 'void',
                'int', 'char', 'long', 'short', 'unsigned', 'signed',
                'struct', 'union', 'sizeof', 'typedef', 'const', 'static'}

    for line in pseudocode_lines:
        text = line.strip().lower()
        if not text:
            continue

        # 变量提取
        for m in var_pattern.finditer(text):
            var = m.group(1)
            if var not in keywords and len(var) > 1:
                current_state.live_variables.add(var)

        # 约束操作符
        for op in ('if', 'else', '==', '!=', '<', '>', '<=', '>='):
            if op in text:
                current_state.constraint_ops.add(op)

        # 内存分类
        if 'local_' in text or 'var_' in text:
            current_state.memory_reads.add('stack')
        if 'global_' in text or text.startswith('g_'):
            current_state.memory_reads.add('global')
        if '=' in text:
            lhs = text.split('=')[0].strip()
            if '*' in lhs or '->' in lhs:
                current_state.memory_writes.add('unknown')
            elif 'local_' in text:
                current_state.memory_writes.add('stack')

        # 调用
        for m in re.finditer(r'(\w[\w.]*)\s*\(', text):
            current_state.call_targets.add(m.group(1).lower())

        # 在每行结束时保存状态快照
        states.append(AbstractBlockState(
            block_addr=len(states),
            live_variables=set(current_state.live_variables),
            constraint_ops=set(current_state.constraint_ops),
            memory_reads=set(current_state.memory_reads),
            memory_writes=set(current_state.memory_writes),
            call_targets=set(current_state.call_targets),
        ))

    return states


# 忠实度评分的维度比较

def _jaccard(a: Set, b: Set) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union > 0 else 0.0


@dataclass
class FidelityReport:
    """反编译忠实度评分报告"""
    function_name: str
    # 三维得分
    control_flow_fidelity: float       # 约束结构相似度
    dataflow_fidelity: float           # 变量活性相似度
    side_effect_fidelity: float        # 内存/调用副作用相似度
    # 综合
    overall_fidelity: float            # [0,1]
    # 证据
    variable_coverage: float           # 伪代码覆盖了多少 binary IR 变量
    constraint_coverage: float
    # 问题标记
    missing_variables: List[str]
    extra_variables: List[str]
    fidelity_grade: str = 'F'          # A/B/C/D/F


class DecompFidelityScorer:
    """反编译忠实度评分器--无需 ground truth

    用法:
    scorer = DecompFidelityScorer()
    report = scorer.score(
        blocks_ir={0: ['mov eax,1','cmp eax,0','je ...'], ...},
        edges=[(0,1),(1,2)],
        pseudocode=['int x = 1;', 'if (x == 0) {', '...', '}'],
    )
    """

    _WEIGHTS = {'control': 0.35, 'dataflow': 0.30, 'side_effect': 0.20,
                'structural': 0.15}

    def score(
        self,
        blocks_ir: Dict[int, List[str]],
        edges: List[Tuple[int, int]],
        pseudocode: List[str],
        function_name: str = '',
    ) -> FidelityReport:
        """计算反编译的语义忠实度"""
        # 提取抽象状态
        ir_states = _extract_binary_abstract_states(blocks_ir, edges)
        pc_states = _extract_pseudocode_abstract_states(pseudocode)

        if not ir_states or not pc_states:
            return FidelityReport(
                function_name=function_name,
                overall_fidelity=0.0,
                control_flow_fidelity=0.0,
                dataflow_fidelity=0.0,
                side_effect_fidelity=0.0,
                variable_coverage=0.0,
                constraint_coverage=0.0,
                missing_variables=[], extra_variables=[],
            )

        # 聚合所有 IR 状态的变量/约束集合
        all_ir_vars: Set[str] = set()
        all_ir_constraints: Set[str] = set()
        for s in ir_states.values():
            all_ir_vars |= s.live_variables
            all_ir_constraints |= s.constraint_ops

        all_pc_vars: Set[str] = set()
        all_pc_constraints: Set[str] = set()
        for s in pc_states:
            all_pc_vars |= s.live_variables
            all_pc_constraints |= s.constraint_ops

        # 数据流忠实度--变量数量比率而非精确名称匹配
        # (变量名在 binary IR 和 pseudocode 之间必然不同--比较数量)
        n_ir_vars = len(all_ir_vars)
        n_pc_vars = len(all_pc_vars)
        if n_ir_vars > 0:
            var_ratio = min(n_pc_vars, n_ir_vars) / max(n_pc_vars, n_ir_vars)
            # 惩罚: 伪代码变量数远小于 IR 变量数 -> 可能遗漏了临时变量
            dataflow_fid = var_ratio
        else:
            dataflow_fid = 1.0 if n_pc_vars == 0 else 0.5
        var_coverage = dataflow_fid
        missing_vars = sorted(all_ir_vars - all_pc_vars)
        extra_vars = sorted(all_pc_vars - all_ir_vars)

        # 控制流忠实度--约束模式相似
        ctrl_fid = _jaccard(all_ir_constraints, all_pc_constraints)
        constraint_cov = len(all_ir_constraints & all_pc_constraints) / max(1, len(all_ir_constraints))

        # 副作用忠实度--内存和调用目标
        all_ir_mem: Set[str] = set()
        all_pc_mem: Set[str] = set()
        all_ir_calls: Set[str] = set()
        all_pc_calls: Set[str] = set()
        for s in ir_states.values():
            all_ir_mem |= s.memory_reads | s.memory_writes
            all_ir_calls |= s.call_targets
        for s in pc_states:
            all_pc_mem |= s.memory_reads | s.memory_writes
            all_pc_calls |= s.call_targets

        mem_fid = _jaccard(all_ir_mem, all_pc_mem)
        call_fid = _jaccard(all_ir_calls, all_pc_calls)
        side_fid = 0.6 * mem_fid + 0.4 * call_fid

        # 结构忠实度--块数/指令密度/调用频率的架构级比较
        n_ir_blocks = len(ir_states)
        n_pc_stmts = len(pc_states)
        block_ratio = min(n_ir_blocks, n_pc_stmts) / max(1, max(n_ir_blocks, n_pc_stmts))
        # IR 总指令数 vs pseudocode 行数 (粗略的复杂度比较)
        total_ir_insns = sum(len(insns) for insns in blocks_ir.values())
        insn_density_ratio = min(total_ir_insns, len(pseudocode)) / max(1, max(total_ir_insns, len(pseudocode)))
        structural_fid = 0.5 * block_ratio + 0.5 * insn_density_ratio

        # 综合
        overall = (
            self._WEIGHTS['control'] * ctrl_fid
            + self._WEIGHTS['dataflow'] * dataflow_fid
            + self._WEIGHTS['side_effect'] * side_fid
            + self._WEIGHTS['structural'] * structural_fid
        )

        # Grade
        if overall >= 0.90:
            grade = 'A'
        elif overall >= 0.75:
            grade = 'B'
        elif overall >= 0.55:
            grade = 'C'
        elif overall >= 0.35:
            grade = 'D'
        else:
            grade = 'F'

        return FidelityReport(
            function_name=function_name,
            control_flow_fidelity=round(ctrl_fid, 4),
            dataflow_fidelity=round(dataflow_fid, 4),
            side_effect_fidelity=round(side_fid, 4),
            overall_fidelity=round(overall, 4),
            variable_coverage=round(var_coverage, 4),
            constraint_coverage=round(constraint_cov, 4),
            missing_variables=missing_vars,
            extra_variables=extra_vars,
            fidelity_grade=grade,
        )
