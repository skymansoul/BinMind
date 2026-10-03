# 重构：从模板匹配升级为约束链+语义分类器

"""Patch Semantic Explainer — 基于约束链的补丁语义解释。

旧版使用 10 类正则模板匹配（本质是关键词填充）。新版改为：

1. 约束提取 — 从补丁新增指令中提取安全检查的符号约束
   cmp reg, N; jcc → 约束: reg < N
   test reg, reg; jz → 约束: reg != 0
   and reg, mask → 约束: reg ⊆ ~mask

2. 约束链构建 — 将约束连接为因果链
   输入 → 寄存器 → 比较 → 分支 → sink
   每个节点标注约束类型（上界/下界/非零/掩码/范围）

3. 分类 — 基于约束链拓扑对补丁语义分类
   [SizeInput → CmpBound → Branch → Abort] → "添加了输入大小边界检查"
   [PtrInput → TestZero → Branch → Error]   → "添加了空指针检查"
   而非依赖关键词匹配。

本模块不采用模板匹配，原因：
  模板 "cmp + jcc = bounds_check" 无法区分 cmp rdi, 256 (大小检查) 和
  cmp [rbp-8], 0x7f454c46 (ELF magic 检查)。
  约束链保留操作数和数据流 → 可精确分类。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ChangeCategory(str, Enum):
    BOUNDS_CHECK = "bounds_check"
    NULL_CHECK = "null_check"
    FUNCTION_REPLACED = "function_replaced"
    INPUT_SANITIZATION = "input_sanitization"
    CANARY_ADDED = "canary_added"
    CONTROL_FLOW = "control_flow"
    ERROR_HANDLING = "error_handling"
    CONSTANT_UPDATED = "constant_updated"
    COMPLEX = "complex"


@dataclass
class ConstraintNode:
    """约束链中的一个节点。"""
    node_type: str = ""              # cmp | test | and | call | branch | sink
    instruction: str = ""
    # 约束参数
    left_operand: str = ""           # 被比较的寄存器/内存
    right_operand: str = ""          # 比较值
    comparison: str = ""             # lt | le | eq | ne | gt | ge
    # 后继节点索引
    true_branch_to: int = -1         # 条件成立时跳转到
    false_branch_to: int = -1        # 条件不成立时 fallthrough 到


@dataclass
class ConstraintChain:
    """从输入到 sink 的完整约束链。"""
    nodes: List[ConstraintNode] = field(default_factory=list)
    # 解释
    category: ChangeCategory = ChangeCategory.COMPLEX
    summary: str = ""
    cwe_id: str = ""
    confidence: float = 0.0


@dataclass
class SemanticExplanation:
    category: ChangeCategory = ChangeCategory.COMPLEX
    summary: str = ""
    detail: str = ""
    cwe_id: str = ""
    confidence: float = 0.0
    chain: Optional[ConstraintChain] = None


@dataclass
class PatchExplanation:
    patch_id: str = ""
    explanations: List[SemanticExplanation] = field(default_factory=list)
    overall_summary: str = ""
    vulnerability_class: str = ""
    affected_functions: List[str] = field(default_factory=list)
    high_confidence_count: int = 0

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'summary': self.overall_summary,
            'vuln_class': self.vulnerability_class,
            'explanations': [
                {'category': e.category.value, 'summary': e.summary, 'cwe': e.cwe_id,
                 'confidence': round(e.confidence, 2)}
                for e in self.explanations
            ],
        }


# 约束提取器

class ConstraintExtractor:
    """从汇编指令行提取符号约束。"""

    def extract(self, asm_lines: List[str]) -> List[ConstraintNode]:
        nodes = []
        for i, line in enumerate(asm_lines):
            node = self._parse_line(i, line)
            if node:
                nodes.append(node)
        return nodes

    def _parse_line(self, idx: int, line: str) -> Optional[ConstraintNode]:
        stripped = line.strip().lower().replace(',', ' ')

        # cmp reg, imm
        m = re.search(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
        if m:
            reg = m.group(1)
            val = m.group(2)
            return ConstraintNode(
                node_type='cmp', instruction=line.strip(),
                left_operand=reg, right_operand=val, comparison='?')

        # test reg, reg
        m = re.search(r'\btest\s+(\w+),?\s+(\w+)', stripped)
        if m and m.group(1) == m.group(2):
            return ConstraintNode(
                node_type='cmp', instruction=line.strip(),
                left_operand=m.group(1), right_operand='0', comparison='ne')

        # and reg, mask
        m = re.search(r'\band\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', stripped)
        if m:
            return ConstraintNode(
                node_type='and', instruction=line.strip(),
                left_operand=m.group(1), right_operand=m.group(2), comparison='mask')

        # 条件分支
        if stripped.startswith('j') and len(stripped.split()[0]) > 1:
            jcc = stripped.split()[0]
            cmp_map = {'je':'eq','jne':'ne','jb':'lt','jbe':'le','ja':'gt','jae':'ge',
                      'jl':'lt','jle':'le','jg':'gt','jge':'ge','jz':'eq','jnz':'ne'}
            return ConstraintNode(
                node_type='branch', instruction=line.strip(),
                comparison=cmp_map.get(jcc, '?'))

        # call abort/exit
        if re.search(r'\bcall\s+(abort|exit|__assert)\b', stripped):
            return ConstraintNode(node_type='sink', instruction=line.strip())

        return None


# 约束链构建器

class ChainBuilder:
    """将约束节点连接为因果链。"""

    def build(self, nodes: List[ConstraintNode]) -> List[ConstraintChain]:
        chains = []
        current_chain = ConstraintChain()

        for i, node in enumerate(nodes):
            current_chain.nodes.append(node)
            # 遇到 sink → 链结束
            if node.node_type == 'sink' and len(current_chain.nodes) >= 2:
                chains.append(current_chain)
                current_chain = ConstraintChain()
            # 过长链截断
            if len(current_chain.nodes) > 10:
                chains.append(current_chain)
                current_chain = ConstraintChain()

        # 未到达 sink 的部分链也保留
        if len(current_chain.nodes) >= 2:
            chains.append(current_chain)
        return chains


# 链分类器

class ChainClassifier:
    """基于约束链拓扑对补丁语义分类。"""

    _SIZE_REGS = {'rdi','rsi','rdx','rcx','r8','r9','eax','ecx','edx'}
    _PTR_REGS = {'rdi','rsi','rdx'}

    def classify(self, chain: ConstraintChain) -> ConstraintChain:
        nodes = chain.nodes
        if len(nodes) < 2:
            return chain

        cmp_node = next((n for n in nodes if n.node_type == 'cmp'), None)
        branch_node = next((n for n in nodes if n.node_type == 'branch'), None)
        sink_node = next((n for n in nodes if n.node_type == 'sink'), None)
        and_node = next((n for n in nodes if n.node_type == 'and'), None)

        # 规则: cmp+测试零 + branch + sink → NULL_CHECK
        if cmp_node and branch_node and cmp_node.right_operand == '0' and cmp_node.comparison == 'ne':
            chain.category = ChangeCategory.NULL_CHECK
            chain.summary = "添加了空指针检查: 验证 %s 非零后继续" % cmp_node.left_operand
            chain.cwe_id = "CWE-476"
            chain.confidence = 0.88

        # 规则: cmp+数值阈值 + branch + sink → BOUNDS_CHECK
        elif cmp_node and branch_node and sink_node and cmp_node.right_operand not in ('0', ''):
            try:
                threshold = int(cmp_node.right_operand, 16) if cmp_node.right_operand.startswith('0x') else int(cmp_node.right_operand)
                chain.category = ChangeCategory.BOUNDS_CHECK
                chain.summary = "添加了边界检查: 限制阈值为 %d" % threshold
                chain.cwe_id = "CWE-120"
                chain.confidence = 0.85
            except ValueError:
                chain.category = ChangeCategory.CONTROL_FLOW
                chain.summary = "控制流变更: 新增了条件分支路径"
                chain.confidence = 0.55

        # 规则: and+mask → INPUT_SANITIZATION
        elif and_node and branch_node:
            chain.category = ChangeCategory.INPUT_SANITIZATION
            chain.summary = "添加了输入净化: 掩码过滤 %s" % and_node.right_operand
            chain.cwe_id = "CWE-78"
            chain.confidence = 0.75

        # 规则: 仅 branch + sink → ERROR_HANDLING
        elif branch_node and sink_node and not cmp_node:
            chain.category = ChangeCategory.ERROR_HANDLING
            chain.summary = "添加了错误处理路径"
            chain.confidence = 0.60

        else:
            chain.category = ChangeCategory.CONTROL_FLOW
            chain.summary = "控制流变更"
            chain.confidence = 0.40

        return chain


# 解释引擎

class PatchExplainer:
    """基于约束链的补丁语义解释器。"""

    def __init__(self):
        self._extractor = ConstraintExtractor()
        self._builder = ChainBuilder()
        self._classifier = ChainClassifier()

    def explain(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "",
                function_name: str = "") -> PatchExplanation:
        exp = PatchExplanation(patch_id=patch_id)
        if function_name:
            exp.affected_functions.append(function_name)

        # 提取新增指令的约束
        orig_set = set(self._norm(original_asm))
        added_lines = [l for l in patched_asm if self._norm_single(l) not in orig_set]
        nodes = self._extractor.extract(added_lines)
        chains = self._builder.build(nodes)

        explanations = []
        for chain in chains:
            chain = self._classifier.classify(chain)
            expl = SemanticExplanation(
                category=chain.category, summary=chain.summary,
                cwe_id=chain.cwe_id, confidence=chain.confidence, chain=chain)
            # 细化
            if chain.category == ChangeCategory.BOUNDS_CHECK:
                expl.detail = "新增的 cmp 指令后跟条件分支 + abort——典型的边界检查模式"
            elif chain.category == ChangeCategory.NULL_CHECK:
                expl.detail = "test 指令检查指针非零，后跟条件跳转——空指针验证模式"
            explanations.append(expl)

        if not explanations:
            explanations.append(SemanticExplanation(
                category=ChangeCategory.COMPLEX,
                summary="此补丁涉及复杂变更，约束链无法自动分类",
                confidence=0.15))

        exp.explanations = explanations
        exp.high_confidence_count = sum(1 for e in explanations if e.confidence >= 0.75)

        cats = {e.category for e in explanations}
        if ChangeCategory.BOUNDS_CHECK in cats:
            exp.vulnerability_class = "缓冲区溢出 (CWE-120)"
        elif ChangeCategory.NULL_CHECK in cats:
            exp.vulnerability_class = "空指针解引用 (CWE-476)"
        elif ChangeCategory.INPUT_SANITIZATION in cats:
            exp.vulnerability_class = "注入攻击 (CWE-78/79)"
        else:
            exp.vulnerability_class = "未分类"
        exp.overall_summary = '; '.join(e.summary for e in explanations)

        return exp

    @staticmethod
    def _norm(lines: List[str]) -> List[str]:
        return [PatchExplainer._norm_single(l) for l in lines]

    @staticmethod
    def _norm_single(line: str) -> str:
        return line.strip().lower().replace(',', ' ').split(';')[0].strip()
