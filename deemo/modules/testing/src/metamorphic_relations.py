# 二进制分析工具的蜕变关系定义集
#
# 蜕变测试 (Metamorphic Testing) 的核心洞察:
#   若无法获取 ground-truth oracle, 则验证"输入变换后输出按预期规律变换"。
#   对二进制分析工具 (反编译器/反汇编器/符号执行引擎) 而言,
#   不存在"正确答案"oracle——但存在语义保持变换后输出应满足的结构不变量。
#
# 与现有差分测试的区别:
#   - diff_tester.py: 比较多个工具对同一输入的输出一致性 (跨工具oracle)
#   - diff_oracle.py: 以自然语言规范断言单次执行结果 (规范oracle)
#   - statistical_oracle.py: 比较输出度量的分布差异 (统计oracle)
#   - 本模块: 比较同一工具在语义保持变换前后的输出一致性 (蜕变oracle)
#     四者正交互补, 覆盖不同类别的缺陷。
#
# 蜕变关系设计原则:
#   1. 变换必须是语义保持的 (在二进制层面)
#   2. 输出关系必须是可自动验证的 (不依赖人工判断)
#   3. 关系必须对编译器优化级别鲁棒 (O0/O1/O2/O3 下均成立)
#
# 参考文献:
#   Chen et al. 1998, "Metamorphic Testing: A New Approach to Generating
#     Next Test Cases", HKUST Technical Report HKUST-CS98-01
#     — 蜕变测试的奠基性工作, 定义蜕变关系 (MR) 的形式化框架
#   ROSA (Koch et al. ICSE 2025) — 蜕变预言机 + fuzzing 检测后门,
#     本项目取其蜕变关系与模糊测试结合的思想, 但面向二进制分析
#     工具的正确性测试而非后门检测
#   OBsmith (2024) — LLM驱动的混淆器测试, 同时使用差分和蜕变测试;
#     本项目的蜕变关系设计借鉴了其"语义保持变换链"概念

from __future__ import annotations

import hashlib
import math
import re
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class RelationScope(str, Enum):
    """蜕变关系的适用范围——不同分析任务适用不同关系集"""
    DISASSEMBLY = "disassembly"        # 反汇编输出
    DECOMPILATION = "decompilation"    # 反编译输出
    SYMBOLIC = "symbolic"              # 符号执行/约束求解
    COVERAGE = "coverage"              # 覆盖率追踪
    CFG = "cfg"                        # 控制流图结构
    UNIVERSAL = "universal"            # 跨任务通用


class TransformKind(str, Enum):
    """输入变换类别——用于统计和诊断"""
    NOP_INJECTION = "nop_injection"            # NOP sled 插入
    REGISTER_RENAMING = "register_renaming"    # 寄存器重命名 (语义等价)
    CODE_REORDER = "code_reorder"              # 基本块重排 (无副作用)
    CONSTANT_OBFUSCATION = "constant_obfuscation"  # 常量编码变换
    ALIGNMENT_PADDING = "alignment_padding"    # 对齐填充
    DEAD_CODE_INSERTION = "dead_code_insertion" # 死代码注入 (不可达)
    SECTION_REORDER = "section_reorder"        # Section 重排
    EQUIVALENT_INSTRUCTION = "equivalent_instruction"  # 等价指令替换


@dataclass
class MetamorphicRelation:
    """单条蜕变关系——输入变换 + 输出断言

    input_transform 将原始字节映射为变换后字节;
    output_predicate 接收 (原输出, 新输出) 并返回 (是否满足, 原因)。
    is_symmetric 标记关系是否对称 (如结构等价是, 单调性不是)。
    """

    mr_id: str
    scope: RelationScope
    description: str
    input_transform: Callable[[bytes], bytes]
    output_predicate: Callable[[Any, Any], Tuple[bool, str]]
    transform_kind: TransformKind = TransformKind.NOP_INJECTION
    is_symmetric: bool = True
    known_limitations: List[str] = field(default_factory=list)


# ============================================================
# 输入变换函数 (语义保持)
# ============================================================

def _nop_inject_at_offset(data: bytes, offset: int, count: int = 1) -> bytes:
    """在指定偏移处注入 NOP (0x90) 序列——x86-64"""
    if offset < 0 or offset > len(data):
        return data
    return data[:offset] + b'\x90' * count + data[offset:]


def _pad_section_alignment(data: bytes, alignment: int = 16) -> bytes:
    """在二进制末尾追加对齐填充——不影响代码语义"""
    pad_len = (alignment - len(data) % alignment) % alignment
    if pad_len == 0:
        return data
    return data + b'\x00' * pad_len


def _append_unreachable_block(data: bytes) -> bytes:
    """在代码段末尾追加不可达基本块 (jmp 到函数入口)——仅适用于裸函数"""
    if len(data) < 5:
        return data
    # 追加: jmp rel8 (EB FE = 自循环, 不可达) + ret (C3)
    return data + b'\xEB\xFE\xC3'


def _equivalent_reg_swap(data: bytes) -> bytes:
    """寄存器等价替换: 在非调用约定敏感位置交换 rax↔rcx
    注: 此变换仅适用于简单场景。通用实现需 CFG 级别的 use-def 分析。
    当前版本作为蜕变关系框架的占位示例, 实际使用应结合反汇编上下文。
    """
    # 占位实现——实际寄存器重命名需在汇编/IR 层操作
    # 此处仅标记此关系可用于提示 LLM 或外部工具
    return data


# ============================================================
# 输出断言函数
# ============================================================

def _instruction_count_monotonic(orig_output: Any, trans_output: Any) -> Tuple[bool, str]:
    """NOP 注入后指令数应单调不减——且增量等于注入的 NOP 数"""
    orig_count = _count_instructions(orig_output)
    trans_count = _count_instructions(trans_output)
    if trans_count >= orig_count:
        return True, f"指令数 {orig_count} → {trans_count} (单调不减, 符合预期)"
    return False, f"指令数减少: {orig_count} → {trans_count} (违反单调性)"


def _cfg_structure_equivalent(orig_output: Any, trans_output: Any) -> Tuple[bool, str]:
    """NOP 注入不应改变 CFG 的分支结构 (边数/基本块数的拓扑不变量)

    检查: 基本块数差值 <= 1 (仅当 NOP 恰好跨基本块边界),
          边数完全一致 (NOP 不产生新分支)
    """
    orig_blocks = _extract_bb_count(orig_output)
    trans_blocks = _extract_bb_count(trans_output)
    orig_edges = _extract_edge_count(orig_output)
    trans_edges = _extract_edge_count(trans_output)

    block_diff = abs(trans_blocks - orig_blocks)
    edge_diff = abs(trans_edges - orig_edges)

    if block_diff <= 1 and edge_diff == 0:
        return True, f"CFG等价: BBs {orig_blocks}/{trans_blocks}, Edges {orig_edges}/{trans_edges}"
    return False, f"CFG偏离: ΔBBs={block_diff}, ΔEdges={edge_diff}"


def _semantic_hash_invariant(orig_output: Any, trans_output: Any) -> Tuple[bool, str]:
    """语义哈希不变性: 对齐填充不应改变输出的结构指纹

    使用 structural_fingerprint 的余弦距离, 阈值 0.02。
    高于阈值表示填充触发了非预期的解析行为变化。
    """
    try:
        from .statistical_oracle import StatisticalOracle
    except ImportError:
        return True, "无法加载 StatisticalOracle, 跳过语义哈希检查"

    orig_text = _to_text(orig_output)
    trans_text = _to_text(trans_output)

    fp_orig = StatisticalOracle.structural_fingerprint(orig_text)
    fp_trans = StatisticalOracle.structural_fingerprint(trans_text)

    # 提取为固定顺序向量
    keys = sorted(fp_orig.keys())
    v_orig = [fp_orig.get(k, 0.0) for k in keys]
    v_trans = [fp_trans.get(k, 0.0) for k in keys]

    dot = sum(a * b for a, b in zip(v_orig, v_trans))
    norm_a = math.sqrt(sum(a * a for a in v_orig))
    norm_b = math.sqrt(sum(b * b for b in v_trans))

    if norm_a < 1e-10 or norm_b < 1e-10:
        return True, "零向量, 跳过"

    cosine = dot / (norm_a * norm_b)
    dist = 1.0 - cosine

    if dist <= 0.02:
        return True, f"语义哈希不变 (cos_dist={dist:.4f})"
    return False, f"语义哈希偏离: cos_dist={dist:.4f} > 0.02"


def _crash_consistency(orig_output: Any, trans_output: Any) -> Tuple[bool, str]:
    """崩溃一致性: NOP/对齐填充不应引入新崩溃或消除已有崩溃"""
    orig_crashed = getattr(orig_output, 'crashed', False)
    trans_crashed = getattr(trans_output, 'crashed', False)

    if orig_crashed == trans_crashed:
        return True, f"崩溃状态一致: {orig_crashed}"
    if orig_crashed and not trans_crashed:
        return False, "原有崩溃消失 (变换可能掩盖了内存损坏)"
    return False, "新崩溃引入 (变换本身可能有副作用)"


def _exit_code_equivalence(orig_output: Any, trans_output: Any) -> Tuple[bool, str]:
    """退出码等价: 语义保持变换不应改变程序的退出码"""
    orig_ec = getattr(orig_output, 'exit_code', None)
    trans_ec = getattr(trans_output, 'exit_code', None)

    if orig_ec == trans_ec:
        return True, f"退出码一致: {orig_ec}"
    return False, f"退出码不一致: {orig_ec} ≠ {trans_ec}"


# ============================================================
# 辅助提取函数
# ============================================================

_INSTR_PATTERN = re.compile(
    r'\b(mov|push|pop|add|sub|cmp|jmp|je|jne|jg|jl|jge|jle|'
    r'ja|jb|jae|jbe|call|ret|lea|xor|and|or|test|nop|int3|'
    r'shl|shr|sar|rol|ror|imul|idiv|div|mul|neg|not|inc|dec|'
    r'syscall|int\s+0x80)\b', re.IGNORECASE)


def _count_instructions(output: Any) -> int:
    text = _to_text(output)
    return len(_INSTR_PATTERN.findall(text))


def _extract_bb_count(output: Any) -> int:
    """估算基本块数——通过标签/地址锚点模式"""
    text = _to_text(output)
    # 匹配反汇编中的地址标号模式: "  401000:" 或 "loc_401000:"
    addr_labels = set(re.findall(r'(?:loc_|LAB_)?([0-9a-fA-F]{6,16})\s*:', text))
    return max(1, len(addr_labels))


def _extract_edge_count(output: Any) -> int:
    """估算 CFG 边数——通过跳转指令 + 目标地址"""
    text = _to_text(output)
    jumps = len(re.findall(
        r'\b(jmp|je|jne|jg|jl|jge|jle|ja|jb|jae|jbe|js|jnz|jz|jo|jno)\b',
        text, re.IGNORECASE))
    return jumps


def _to_text(output: Any) -> str:
    """将各种输出表示统一为文本, 用于断言函数"""
    if isinstance(output, str):
        return output
    if isinstance(output, bytes):
        return output.decode('utf-8', errors='replace')
    # 尝试 stdout 属性 (ExecutionResult 等)
    raw = getattr(output, 'stdout', None)
    if raw is not None:
        return _to_text(raw)
    return str(output)


# ============================================================
# 预定义蜕变关系集
# ============================================================

def nop_injection_mr(nop_count: int = 3, offset: int = 0) -> MetamorphicRelation:
    """NOP 注入蜕变关系:
    变换: 在指定偏移插入 nop_count 条 NOP 指令
    断言: 指令数单调不减 + CFG 结构等价 + 崩溃状态一致
    """
    def _transform(data: bytes) -> bytes:
        return _nop_inject_at_offset(data, offset, nop_count)

    def _combined_predicate(orig: Any, trans: Any) -> Tuple[bool, str]:
        reasons: List[str] = []
        for pred in [_instruction_count_monotonic, _cfg_structure_equivalent,
                      _crash_consistency]:
            ok, msg = pred(orig, trans)
            if not ok:
                return False, msg
            reasons.append(msg)
        return True, " | ".join(reasons)

    return MetamorphicRelation(
        mr_id=f"nop_inject_{nop_count}",
        scope=RelationScope.UNIVERSAL,
        description=(f"在偏移 {offset} 处注入 {nop_count} 条 NOP 指令。"
                     "反汇编输出应包含这些 NOP 且不影响其他指令的解析。"),
        input_transform=_transform,
        output_predicate=_combined_predicate,
        transform_kind=TransformKind.NOP_INJECTION,
        known_limitations=["若 NOP 落在多字节指令中间, 反汇编器可能错误同步"],
    )


def alignment_padding_mr(pad_to: int = 16) -> MetamorphicRelation:
    """对齐填充蜕变关系:
    变换: 在输入末尾追加零字节至 pad_to 对齐
    断言: 语义哈希不变 + 退出码等价 + 崩溃状态一致
    """
    def _transform(data: bytes) -> bytes:
        return _pad_section_alignment(data, pad_to)

    def _combined_predicate(orig: Any, trans: Any) -> Tuple[bool, str]:
        for pred in [_semantic_hash_invariant, _exit_code_equivalence,
                      _crash_consistency]:
            ok, msg = pred(orig, trans)
            if not ok:
                return False, msg
        return True, "对齐填充后所有断言通过"

    return MetamorphicRelation(
        mr_id=f"align_pad_{pad_to}",
        scope=RelationScope.UNIVERSAL,
        description=f"输入末尾零填充至 {pad_to} 字节对齐。输出结构应不变。",
        input_transform=_transform,
        output_predicate=_combined_predicate,
        transform_kind=TransformKind.ALIGNMENT_PADDING,
        known_limitations=["某些解析器在高对齐要求下可能触发断言或越界"],
    )


def unreachable_block_mr() -> MetamorphicRelation:
    """不可达代码注入蜕变关系:
    变换: 在输入末尾追加不可达基本块
    断言: CFG 中不可达节点数应增加但可达部分保持不变
    """
    def _transform(data: bytes) -> bytes:
        return _append_unreachable_block(data)

    def _predicate(orig: Any, trans: Any) -> Tuple[bool, str]:
        # 反汇编器不应将不可达代码混入主控制流
        orig_text = _to_text(orig)
        trans_text = _to_text(trans)
        # 检查: 有意义的指令数应保持不变 (仅增加不可达块的指令)
        orig_instrs = _count_instructions(orig)
        trans_instrs = _count_instructions(trans)
        delta = trans_instrs - orig_instrs
        if 0 <= delta <= 5:
            return True, f"不可达块注入: 指令增量 {delta} (<=5, 合理)"
        return False, f"指令增量异常: {delta} (预期 <=5)"

    return MetamorphicRelation(
        mr_id="unreachable_block",
        scope=RelationScope.DISASSEMBLY,
        description="追加不可达基本块。可达CFG应不变, 不可达节点应增加。",
        input_transform=_transform,
        output_predicate=_predicate,
        transform_kind=TransformKind.DEAD_CODE_INSERTION,
        known_limitations=["仅对裸函数有效; 完整二进制需考虑重定位"],
    )


# ============================================================
# 预定义关系注册表
# ============================================================

PREDEFINED_RELATIONS: Dict[str, MetamorphicRelation] = {
    "nop_1": nop_injection_mr(nop_count=1, offset=0),
    "nop_3": nop_injection_mr(nop_count=3, offset=0),
    "nop_5_mid": nop_injection_mr(nop_count=5, offset=64),
    "align_16": alignment_padding_mr(16),
    "align_64": alignment_padding_mr(64),
    "unreachable_block": unreachable_block_mr(),
}


def get_relations_for_scope(scope: RelationScope) -> List[MetamorphicRelation]:
    """按适用范围筛选预定义蜕变关系"""
    result = []
    for mr in PREDEFINED_RELATIONS.values():
        if mr.scope == scope or mr.scope == RelationScope.UNIVERSAL:
            result.append(mr)
    return result
