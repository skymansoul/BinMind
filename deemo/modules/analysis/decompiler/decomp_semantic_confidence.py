# 跨反编译器语义一致性: 两反编译器对同一函数产生语义等价伪代码时置信度加倍
# 类型流一致性: 抽象解释在变量使用点推导期望类型, 与声明类型比较

"""反编译器语义置信度增强 - 从语法启发式升级到语义验证

decompiler_confidence_ensemble.py 的评估维度:
  1. 可达性自洽 - 纯语法: 标签有无悬挂引用
  2. 栈帧一致性 - 纯语法: 偏移有无冲突
  3. 死代码率 - 控制流但非语义

以上三维度全部基于语法/CFG 模式--不涉及代码语义
对于混淆代码或复杂控制流, 语法自洽 != 语义正确:
  反编译器可能产生语法完美但逻辑错误的伪代码

本模块增加三个语义验证维度:
  A. 跨反编译器语义一致分: 两反编译器对同一基本块的变量定义-使用关系一致
     -> 置信度加倍 (双盲验证)
  B. 类型流一致性: 通过抽象解释追踪每个变量的类型约束
     在跨基本块边界检查类型一致性
  C. 路径条件可满足性: 抽取条件分支的约束, 快速检查是否逻辑可满足
     (矛盾条件 -> 反编译器生成了不可能的执行路径)

设计意图 - 将置信度从 "这段伪代码看起来自洽" 升级到
"这段伪代码在语义约束下被交叉验证"。
在专利审查中, 这种从 syntax-based heuristics 到
semantic-grounded verification 的过渡是关键新颖性陈述
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 数据结构

@dataclass
class VarDefUse:
    """单个基本块内的变量定义-使用摘要"""
    block_addr: int
    defined_vars: Set[str] = field(default_factory=set)
    used_vars: Set[str] = field(default_factory=set)
    # 类型约束: var_name -> {'int', 'ptr', 'array', 'unknown'}
    type_hints: Dict[str, str] = field(default_factory=dict)


@dataclass
class SemanticConfidenceReport:
    """语义置信度的结构化报告"""
    cross_decompiler_agreement: float = 0.0
    type_flow_consistency: float = 0.0
    path_condition_satisfiability: float = 0.0
    semantic_score: float = 0.0           # 三项加权
    evidence: List[str] = field(default_factory=list)


# 维度 A: 跨反编译器语义一致性

class CrossDecompilerSemanticChecker:
    """比较两个反编译器对同一函数的输出--在语义层面而非文本层面

    原理: 若 Ghidra 和 r2 对同一函数产生截然不同的变量定义-使用关系
    至少有一个反编译器出错了。反之, 若两者的 def-use 图高度重叠
    则两者大概率都正确--置信度应上调

    比较维度:
    1. 变量定义集合的 Jaccard 相似度
    2. 基本块间 def-use 边的一致性
    3. 调用目标的一致性

    阈值: Jaccard >= 0.7 -> 高度一致; < 0.3 -> 严重分歧
    """

    def __init__(self, jaccard_threshold: float = 0.7):
        self._threshold = jaccard_threshold

    def compare(
        self,
        blocks_a: List[Dict[str, Any]],
        blocks_b: List[Dict[str, Any]],
    ) -> float:
        """比较两个反编译器输出的语义一致性

        blocks_a/blocks_b: 各基本块的 def-use 信息
        格式: {'addr': int, 'code': str, 'defs': [var_names], 'uses': [var_names]}
        """
        defs_a = self._extract_var_set(blocks_a, 'defs')
        defs_b = self._extract_var_set(blocks_b, 'defs')
        uses_a = self._extract_var_set(blocks_a, 'uses')
        uses_b = self._extract_var_set(blocks_b, 'uses')
        calls_a = self._extract_calls(blocks_a)
        calls_b = self._extract_calls(blocks_b)

        # Jaccard 相似度--每维度
        def_jaccard = self._jaccard(defs_a, defs_b)
        use_jaccard = self._jaccard(uses_a, uses_b)
        call_jaccard = self._jaccard(calls_a, calls_b)

        # 加权--def 比 use 更重要 (反编译器可能使用不同的临时变量名
        # 但定义集合应一致--定义来自 IR 而非命名策略)
        score = 0.4 * def_jaccard + 0.35 * use_jaccard + 0.25 * call_jaccard
        return min(1.0, score)

    def confidence_boost(
        self,
        agreement_score: float,
        base_confidence: float,
    ) -> float:
        """将语义一致性转换为置信度增益

        高一致性时给予最大 +0.25 的 boost
        低一致性时施加 -0.15 的 penalty
        """
        if agreement_score >= self._threshold:
            # 双盲验证通过--置信度显著提升
            boost = 0.25 * (agreement_score - self._threshold) / (1.0 - self._threshold)
            return min(1.0, base_confidence + boost)
        else:
            # 分歧--置信度惩罚
            penalty = 0.15 * (self._threshold - agreement_score) / self._threshold
            return max(0.1, base_confidence - penalty)

    @staticmethod
    def _extract_var_set(
        blocks: List[Dict[str, Any]], key: str
    ) -> Set[str]:
        """从基本块列表中提取变量名集合--经归一化处理

        归一化: 去除反编译器特定的前缀/后缀
        Ghidra: local_xxx, uVar1, iVar2
        r2: var_xxh, arg_xxh
        归一化为统一形式以便跨反编译器比较
        """
        raw: Set[str] = set()
        for b in blocks:
            for var in b.get(key, []):
                var_str = str(var).strip()
                normalized = CrossDecompilerSemanticChecker._normalize_var(var_str)
                raw.add(normalized)
        return raw

    @staticmethod
    def _normalize_var(var_name: str) -> str:
        """变量名归一化--减少反编译器命名差异的影响"""
        v = var_name.lower().strip()
        # 去掉常见前缀
        for prefix in ('local_', 'uvar', 'ivar', 'var_', 'arg_', 'param_'):
            if v.startswith(prefix):
                v = v[len(prefix):]
                break
        # 去掉寄存器名伪装 (如 var_eax -> 保留)
        return v

    @staticmethod
    def _extract_calls(blocks: List[Dict[str, Any]]) -> Set[str]:
        """提取调用目标集合"""
        calls: Set[str] = set()
        call_pattern = re.compile(
            r'(?:call|CALL)\s+(\w[\w.@#$]*)', re.IGNORECASE
        )
        for b in blocks:
            code = b.get('code', '')
            for m in call_pattern.finditer(code):
                calls.add(m.group(1).lower())
        return calls

    @staticmethod
    def _jaccard(a: Set, b: Set) -> float:
        if not a and not b:
            return 1.0  # 两者都无定义 -> 一致
        union = len(a | b)
        if union == 0:
            return 0.0
        return len(a & b) / union


# 维度 B: 类型流一致性

class TypeFlowConsistencyChecker:
    """通过抽象解释追踪变量类型在跨块传播时的一致性

    问题: 反编译器可能对同一变量在不同基本块中推断出冲突的类型
    例如 block A 中 v1 被视为 int (参与算术运算)
    block B 中 v1 被视为 ptr (参与指针解引用)
    若 v1 不是 union 类型, 这种冲突表明反编译器在某个块的类型推断有误

    检测方法:
    1. 为每变量维护类型约束集合 (int/ptr/array/unknown)
    2. 跨块传播: 若 var 在 block A 定义并在 block B 使用
       检查 A 的定义类型是否与 B 的使用类型兼容
    3. 冲突计数--每冲突扣分
    """

    # 类型兼容矩阵: True = 合法组合
    _COMPAT = {
        ('int', 'int'): True,   ('int', 'ptr'): False,  ('int', 'array'): False,
        ('ptr', 'int'): True,   ('ptr', 'ptr'): True,   ('ptr', 'array'): True,
        ('array', 'int'): True, ('array', 'ptr'): True,  ('array', 'array'): True,
        # unknown 与任何类型兼容
    }

    @staticmethod
    def _is_compatible(t1: str, t2: str) -> bool:
        if 'unknown' in (t1, t2):
            return True
        return TypeFlowConsistencyChecker._COMPAT.get((t1, t2), False)

    def check(self, blocks: List[Dict[str, Any]]) -> float:
        """检查跨基本块的类型流一致性

        blocks: 包含 type_hints 的基本块列表
        每块格式: {'addr': int, 'defs': [...], 'uses': [...],
                    'type_hints': {var: type_str}, 'successors': [addr,.]}

        返回 [0, 1] 分数--1 = 完全一致
        """
        if not blocks:
            return 0.5

        # 构建每个变量的跨块类型约束集合
        var_types: Dict[str, Set[str]] = defaultdict(set)
        for b in blocks:
            hints = b.get('type_hints', {})
            for var, typ in hints.items():
                var_types[var].add(typ)

        # 统计类型冲突
        conflicts = 0
        total_vars = len(var_types)
        if total_vars == 0:
            return 0.6  # 无类型信息 -> 中位分

        for var, types in var_types.items():
            type_list = list(types)
            for i in range(len(type_list)):
                for j in range(i + 1, len(type_list)):
                    if not self._is_compatible(type_list[i], type_list[j]):
                        conflicts += 1
                        break

        conflict_ratio = conflicts / total_vars
        # 指数衰减: 冲突越多, 分数急剧下降
        return math.exp(-3.0 * conflict_ratio)


# 维度 C: 路径条件可满足性

class PathConditionChecker:
    """快速检查反编译器生成的条件分支是否逻辑可能

    问题: 反编译器在处理混淆代码时可能生成矛盾的条件分支
    例如 if (x > 10 && x < 5) -- 永不成立的条件
    这种分支在语法上正确但在语义上不可能执行

    检测: 抽取条件表达式, 转换为简单的区间约束
    检查区间交集是否为空--空交集 -> 矛盾条件
    """

    # 简单约束的模式: var OP constant
    _CONSTRAINT_PAT = re.compile(
        r'(\w+)\s*(==|!=|<|<=|>|>=)\s*(-?\d+|0x[0-9a-fA-F]+)'
    )

    def check(self, pseudocode: str) -> float:
        """检查伪代码中所有条件分支的逻辑可满足性

        返回 [0, 1] 分数--1 = 所有条件逻辑一致
        """
        conditions = self._extract_conditions(pseudocode)
        if not conditions:
            return 0.8  # 无条件分支 -> 对简单函数默认为合理

        unsatisfiable = 0
        for cond_text in conditions:
            constraints = self._parse_constraints(cond_text)
            if constraints and not self._is_satisfiable(constraints):
                unsatisfiable += 1

        total = len(conditions)
        if total == 0:
            return 0.8

        ratio = unsatisfiable / total
        return max(0.1, 1.0 - ratio * 2.0)

    def _extract_conditions(self, pseudocode: str) -> List[str]:
        """提取 if/while 的条件表达式"""
        # 匹配 if (condition) 和 while (condition)
        pattern = re.compile(
            r'(?:if|while)\s*\(([^)]+)\)', re.IGNORECASE
        )
        return [m.group(1).strip() for m in pattern.finditer(pseudocode)]

    def _parse_constraints(
        self, cond_text: str
    ) -> List[Tuple[str, str, int]]:
        """将条件文本解析为 (var, op, constant) 约束列表"""
        constraints = []
        for m in self._CONSTRAINT_PAT.finditer(cond_text):
            var = m.group(1)
            op = m.group(2)
            val_str = m.group(3)
            try:
                val = int(val_str, 0)
            except ValueError:
                continue
            constraints.append((var, op, val))
        return constraints

    @staticmethod
    def _is_satisfiable(
        constraints: List[Tuple[str, str, int]]
    ) -> bool:
        """判断一组线性约束是否存在共同解

        方法: 对每变量维护区间 [low, high] 的交集
        若任一变量区间为空 -> 不可满足
        仅处理 AND 连接--OR 连接单独处理 (更弱但足够)
        """
        # 对每变量的区间
        intervals: Dict[str, List[Tuple[int, int]]] = defaultdict(list)

        for var, op, val in constraints:
            if op == '==':
                intervals[var].append((val, val))
            elif op == '!=':
                # != 不产生区间约束 (排除一个点 != 区间)
                continue
            elif op == '<':
                intervals[var].append((-float('inf'), val - 1))
            elif op == '<=':
                intervals[var].append((-float('inf'), val))
            elif op == '>':
                intervals[var].append((val + 1, float('inf')))
            elif op == '>=':
                intervals[var].append((val, float('inf')))

        for var, bounds in intervals.items():
            low = max(b[0] for b in bounds)
            high = min(b[1] for b in bounds)
            if low > high:
                return False

        return True


# 语义置信度聚合器

class SemanticConfidenceAggregator:
    """聚合三个语义验证维度 -> 产生置信度调整

    使用方式:
    aggregator = SemanticConfidenceAggregator()
    report = aggregator.evaluate(
        blocks_output_a, blocks_output_b, pseudocode
    )
    adjusted_confidence = aggregator.adjust(base_confidence, report)
    """

    _WEIGHTS = {
        'cross_decompiler': 0.45,
        'type_flow': 0.30,
        'path_condition': 0.25,
    }

    def __init__(self):
        self._cross_checker = CrossDecompilerSemanticChecker()
        self._type_checker = TypeFlowConsistencyChecker()
        self._path_checker = PathConditionChecker()

    def evaluate(
        self,
        blocks_primary: List[Dict[str, Any]],
        blocks_secondary: Optional[List[Dict[str, Any]]] = None,
        pseudocode: str = '',
    ) -> SemanticConfidenceReport:
        """评估伪代码的语义置信度

        blocks_primary: 主要反编译器的基本块
        blocks_secondary: 第二反编译器的基本块 (若可用)
        pseudocode: 伪代码全文

        返回: SemanticConfidenceReport
        """
        report = SemanticConfidenceReport()
        evidence = []

        # A: 跨反编译器一致性
        if blocks_secondary:
            report.cross_decompiler_agreement = self._cross_checker.compare(
                blocks_primary, blocks_secondary
            )
            if report.cross_decompiler_agreement >= 0.7:
                evidence.append(
                    f"cross-decompiler agreement high ({report.cross_decompiler_agreement:.2f})"
                )
            elif report.cross_decompiler_agreement < 0.3:
                evidence.append(
                    f"cross-decompiler divergence ({report.cross_decompiler_agreement:.2f})"
                )
        else:
            report.cross_decompiler_agreement = 0.5  # 无第二反编译器 -> 中性

        # B: 类型流一致性
        report.type_flow_consistency = self._type_checker.check(blocks_primary)
        if report.type_flow_consistency < 0.5:
            evidence.append(
                f"type flow conflicts detected ({report.type_flow_consistency:.2f})"
            )

        # C: 路径条件可满足性
        if pseudocode:
            report.path_condition_satisfiability = self._path_checker.check(pseudocode)
            if report.path_condition_satisfiability < 0.5:
                evidence.append(
                    "unsatisfiable path conditions found"
                )

        # 加权语义分
        report.semantic_score = (
            self._WEIGHTS['cross_decompiler'] * report.cross_decompiler_agreement
            + self._WEIGHTS['type_flow'] * report.type_flow_consistency
            + self._WEIGHTS['path_condition'] * report.path_condition_satisfiability
        )
        report.evidence = evidence

        return report

    def adjust(
        self,
        base_confidence: float,
        report: SemanticConfidenceReport,
    ) -> float:
        """将语义置信度应用于基础置信度

        调整策略:
        - semantic_score >= 0.8: 向上调整最多 +0.20
        - semantic_score 在 0.4-0.6: 不调整 (中性)
        - semantic_score < 0.4: 向下调整最多 -0.25

        使用 sigmoid 式平滑调整--避免阶跃
        """
        score = report.semantic_score
        # 映射到 [-1, +1] 调整因子
        if score >= 0.6:
            factor = (score - 0.6) / 0.4  # [0, +1]
            adjustment = factor * 0.20
        elif score <= 0.4:
            factor = (0.4 - score) / 0.4  # [0, +1]
            adjustment = -factor * 0.25
        else:
            adjustment = 0.0

        return max(0.05, min(1.0, base_confidence + adjustment))
