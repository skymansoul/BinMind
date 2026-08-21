# 三模态交叉验证: 伪代码声明类型 vs 动态 trace 使用模式 vs 汇编指令约束
# 分支条件一致性: 反编译的 if 条件 vs 动态 trace 的实际分支方向

"""跨模态反编译器幻觉检测 - 动态执行迹与静态反编译输出的交叉验证

AI 反编译器 (decomp_ai.py) 基于 LLM 从汇编生成伪代码
LLM 在以下场景倾向产生幻觉:
  1. 类型幻觉: LLM 猜测变量类型 (int vs ptr) 但猜测错误
  2. 分支幻觉: LLM 重构条件表达式但与实际汇编逻辑不等价
  3. 变量幻觉: LLM 创造不存在于汇编中的"解释性"变量
  4. 死代码错觉: LLM 恢复的代码路径在实际执行中从不被触发

本模块的交叉验证来自三个独立信息源:
  A. 反编译伪代码 (来自 decomp_ai) - 声明类型、表达式结构、变量名
  B. 动态执行迹 (来自 dynamic/engine) - 寄存器值、内存访问、分支方向
  C. 原始汇编指令 (来自 objdump/r2) - 指令的操作数宽度、访存模式

三个源之间的不一致 -> 幻觉标记

与现有方法的关系:
- CoDe-R: 通过重编译 + BLEU 验证 -> 需要完整重编译, 对嵌入式/非标准 ABI 不可用
- Celebi: 通过 LLM 注意力头验证 -> 仅适用于白盒 LLM, 对 API 调用的 LLM 不可用
- 本模块: 通过动态执行迹验证 -> 不需要重编译, 不需要白盒访问 LLM
  仅需目标二进制可执行 (对于大多数分析场景成立)

技术前提: 需要至少一次成功的目标函数执行 (可通过 fuzzing harness 或手动输入)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 数据结构

class HallucinationType(Enum):
    TYPE_MISMATCH = auto()         # 声明的类型与运行时使用模式冲突
    BRANCH_INCONSISTENCY = auto()  # 反编译的条件与实际分支方向不一致
    SPURIOUS_VARIABLE = auto()     # 反编译声明了不存在于汇编中的变量
    DEAD_PATH = auto()             # 反编译恢复了从不执行的代码路径
    WIDTH_MISMATCH = auto()        # 变量宽度声明与汇编操作数宽度不符


@dataclass
class HallucinationMarker:
    """单个幻觉检测标记"""
    hallucination_type: HallucinationType
    confidence: float                 # [0,1] - 0=不确定, 1=确认幻觉
    # 位置信息
    pseudocode_line: int = 0
    pseudocode_text: str = ''
    assembly_address: int = 0
    # 冲突证据
    declared_fact: str = ''           # 反编译器声称的
    observed_fact: str = ''           # 动态迹观察到的
    # 建议修正
    suggested_correction: str = ''


@dataclass
class HallucinationReport:
    """幻觉检测的完整报告"""
    function_name: str
    total_markers: int
    markers: List[HallucinationMarker]
    # 汇总评分
    overall_hallucination_score: float  # [0,1] - 0=完全可靠, 1=严重幻觉
    type_consistency: float             # 类型一致性 [0,1]
    branch_consistency: float           # 分支一致性 [0,1]
    variable_consistency: float         # 变量一致性 [0,1]


# 动态迹中的类型使用模式提取

def _extract_runtime_type_usage(
    trace_memory_accesses: List[Dict[str, Any]],
    variable_name: str,
) -> Dict[str, Any]:
    """从动态迹中提取变量的运行时使用模式

    返回: {'dereferenced': bool, 'arithmetic_used': bool,
            'compared_to_null': bool, 'value_range': (min, max),
            'access_sizes': set of {1,2,4,8}}
    """
    result = {
        'dereferenced': False,
        'arithmetic_used': False,
        'compared_to_null': False,
        'value_range': (0, 0),
        'access_sizes': set(),
    }
    for access in trace_memory_accesses:
        if access.get('variable') != variable_name:
            continue
        if access.get('is_deref'):
            result['dereferenced'] = True
        if access.get('is_arithmetic'):
            result['arithmetic_used'] = True
        if access.get('compared_to_zero'):
            result['compared_to_null'] = True
        sz = access.get('access_size', 0)
        if sz > 0:
            result['access_sizes'].add(sz)

    return result


# 类型一致性检查器

class TypeConsistencyChecker:
    """检查反编译的类型声明与动态迹中的使用模式是否一致

    规则:
    - 反编译器说 int -> 迹中不应出现解引用 -> 否则标记 TYPE_MISMATCH
    - 反编译器说 ptr -> 迹中不应出现算术运算 -> 否则标记 TYPE_MISMATCH
    - 反编译器说 int8 -> 迹中访问宽度应 <= 1 字节 -> 否则标记 WIDTH_MISMATCH
    """

    # 声明类型 -> (是否允许解引用, 是否允许算术, 预期访问宽度)
    _TYPE_RULES = {
        'int':   (False, True,  {1, 2, 4, 8}),
        'int8':  (False, True,  {1}),
        'int16': (False, True,  {1, 2}),
        'int32': (False, True,  {1, 2, 4}),
        'int64': (False, True,  {1, 2, 4, 8}),
        'uint':  (False, True,  {1, 2, 4, 8}),
        'ptr':   (True,  False, {4, 8}),
        'char*': (True,  False, {1}),
        'void*': (True,  False, {4, 8}),
        'float': (False, False, {4, 8}),
    }

    def check(
        self,
        declared_type: str,
        runtime_usage: Dict[str, Any],
        variable_name: str = '',
        line_number: int = 0,
    ) -> List[HallucinationMarker]:
        """检查单个变量的类型一致性"""
        markers = []
        rules = self._TYPE_RULES.get(declared_type)
        if rules is None:
            return markers  # 未知类型--无法检查

        allow_deref, allow_arith, expected_widths = rules

        # 检查解引用
        if runtime_usage.get('dereferenced') and not allow_deref:
            markers.append(HallucinationMarker(
                hallucination_type=HallucinationType.TYPE_MISMATCH,
                confidence=0.85,
                pseudocode_line=line_number,
                declared_fact=f'{variable_name}: {declared_type}',
                observed_fact=f'{variable_name} dereferenced at runtime',
                suggested_correction=f'{variable_name}: ptr or uintptr_t',
            ))

        # 检查算术使用
        if runtime_usage.get('arithmetic_used') and not allow_arith:
            markers.append(HallucinationMarker(
                hallucination_type=HallucinationType.TYPE_MISMATCH,
                confidence=0.80,
                pseudocode_line=line_number,
                declared_fact=f'{variable_name}: {declared_type}',
                observed_fact=f'{variable_name} used in arithmetic',
                suggested_correction=f'{variable_name}: int or uintptr_t',
            ))

        # 检查访问宽度
        actual_widths = runtime_usage.get('access_sizes', set())
        if actual_widths and expected_widths:
            if not actual_widths.issubset(expected_widths):
                markers.append(HallucinationMarker(
                    hallucination_type=HallucinationType.WIDTH_MISMATCH,
                    confidence=0.70,
                    pseudocode_line=line_number,
                    declared_fact=f'{variable_name}: {declared_type} (expected widths {expected_widths})',
                    observed_fact=f'actual access widths {actual_widths}',
                    suggested_correction='widen variable type or check union',
                ))

        return markers


# 分支一致性检查器

class BranchConsistencyChecker:
    """检查反编译的条件语句与动态迹中的实际分支方向是否一致

    原理: 若反编译器生成 if (x > 10) 而动态迹显示当 x=5 时
    走了 then 分支 -> 反编译的条件表达式必定是错的

    从动态迹提取的信息:
    - 每分支点的条件变量值 (通过寄存器快照)
    - 实际采取的分支方向 (通过下一条 PC 地址)
    """

    @staticmethod
    def _parse_decompiled_condition(cond_text: str) -> Optional[Dict[str, Any]]:
        """解析反编译的条件表达式--提取变量和比较操作符"""
        # 模式: var OP const
        m = re.match(
            r'\s*(\w+)\s*(==|!=|<|<=|>|>=)\s*(-?\d+|0x[0-9a-fA-F]+)',
            cond_text.strip()
        )
        if not m:
            return None
        return {
            'variable': m.group(1),
            'operator': m.group(2),
            'constant': int(m.group(3), 0),
        }

    @staticmethod
    def _evaluate_condition(cond: Dict[str, Any], var_value: int) -> bool:
        """在具体变量值上评估条件"""
        op = cond['operator']
        const = cond['constant']
        if op == '==':
            return var_value == const
        if op == '!=':
            return var_value != const
        if op == '<':
            return var_value < const
        if op == '<=':
            return var_value <= const
        if op == '>':
            return var_value > const
        if op == '>=':
            return var_value >= const
        return False

    def check(
        self,
        decompiled_conditions: List[Dict[str, Any]],
        branch_trace: List[Dict[str, Any]],
    ) -> List[HallucinationMarker]:
        """检查分支一致性

        decompiled_conditions: [{'addr': 0x401000, 'condition': 'x > 10',
                                  'then_target': 0x401100, 'else_target': 0x401050}]
        branch_trace: [{'addr': 0x401000, 'reg_snapshot': {'rax': 5},
                         'taken_target': 0x401050}, ...]

        返回不一致的分支标记
        """
        markers = []
        # 构建 trace 索引--按地址
        trace_by_addr: Dict[int, List[Dict]] = defaultdict(list)
        for bt in branch_trace:
            trace_by_addr[bt.get('addr', 0)].append(bt)

        for dc in decompiled_conditions:
            addr = dc.get('addr', 0)
            cond_text = dc.get('condition', '')
            parsed = self._parse_decompiled_condition(cond_text)
            if parsed is None:
                continue

            traces = trace_by_addr.get(addr, [])
            for bt in traces:
                reg_snap = bt.get('reg_snapshot', {})
                var_name = parsed['variable']
                if var_name not in reg_snap:
                    continue

                var_value = reg_snap[var_name]
                expected = self._evaluate_condition(parsed, var_value)
                actual_taken = bt.get('taken_target', 0)
                then_target = dc.get('then_target', 0)

                # 若条件期望走 then 但实际走了 else -> 不一致
                actual_is_then = (actual_taken == then_target)
                if expected != actual_is_then:
                    markers.append(HallucinationMarker(
                        hallucination_type=HallucinationType.BRANCH_INCONSISTENCY,
                        confidence=0.90,
                        assembly_address=addr,
                        declared_fact=f'condition "{cond_text}" -> '
                                     f'expected {"then" if expected else "else"}',
                        observed_fact=f'var {var_name}={var_value}, '
                                     f'actual branch: {"then" if actual_is_then else "else"}',
                        suggested_correction=f'review condition at 0x{addr:x}',
                    ))

        return markers


# 变量活性检查器

class VariableLivenessChecker:
    """检查反编译声明的变量是否在汇编/动态迹中实际存在

    反编译器可能创造 "合成变量"--在汇编中无对应寄存器/内存位置
    但在伪代码中为解释性目的出现。常见于 LLM 反编译器
    """

    def check(
        self,
        decompiled_variables: Set[str],
        assembly_registers: Set[str],
        assembly_memory_refs: Set[str],
    ) -> List[HallucinationMarker]:
        """检查每个反编译变量的活性

        变量名可能与汇编标识符不完全匹配--使用模糊匹配
        """
        markers = []
        # 汇编中出现的所有标识符
        all_asm_ids = assembly_registers | assembly_memory_refs

        for var in decompiled_variables:
            # 跳过寄存器名 (eax, rbx, ...) --这些天然存在
            if self._is_register_name(var):
                continue

            # 模糊匹配: 变量名作为子串出现在任何汇编标识符中
            var_lower = var.lower().lstrip('*&')
            found = any(var_lower in aid.lower() for aid in all_asm_ids)

            if not found:
                markers.append(HallucinationMarker(
                    hallucination_type=HallucinationType.SPURIOUS_VARIABLE,
                    confidence=0.65,
                    declared_fact=f'variable "{var}" declared in pseudocode',
                    observed_fact='no matching identifier in assembly',
                    suggested_correction=f'remove or rename "{var}"',
                ))

        return markers

    @staticmethod
    def _is_register_name(name: str) -> bool:
        regs_64 = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                   'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'}
        regs_32 = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
                   'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'}
        return name.lower() in regs_64 or name.lower() in regs_32


# 主检测器

class DecompilerHallucinationDetector:
    """跨模态反编译器幻觉检测器--三源交叉验证

    用法:
    detector = DecompilerHallucinationDetector()
    report = detector.detect(
        pseudocode=pseudocode_text,
        type_declarations={'x': 'int', 'p': 'ptr'},
        decompiled_conditions=[...],
        trace_memory_accesses=[...],
        branch_trace=[...],
        assembly_registers={'rax', 'rbx', ...},
        assembly_memory_refs={'[rbp-0x10]', '[rsi]', ...},
    )
    """

    def __init__(self):
        self._type_checker = TypeConsistencyChecker()
        self._branch_checker = BranchConsistencyChecker()
        self._liveness_checker = VariableLivenessChecker()

    def detect(
        self,
        pseudocode: str = '',
        type_declarations: Optional[Dict[str, str]] = None,
        decompiled_conditions: Optional[List[Dict[str, Any]]] = None,
        trace_memory_accesses: Optional[List[Dict[str, Any]]] = None,
        branch_trace: Optional[List[Dict[str, Any]]] = None,
        assembly_registers: Optional[Set[str]] = None,
        assembly_memory_refs: Optional[Set[str]] = None,
        function_name: str = '',
    ) -> HallucinationReport:
        """执行全面的跨模态幻觉检测"""

        type_declarations = type_declarations or {}
        decompiled_conditions = decompiled_conditions or []
        trace_memory_accesses = trace_memory_accesses or []
        branch_trace = branch_trace or []
        assembly_registers = assembly_registers or set()
        assembly_memory_refs = assembly_memory_refs or set()

        all_markers: List[HallucinationMarker] = []

        # 维度 A: 类型一致性
        for var_name, declared_type in type_declarations.items():
            runtime_usage = _extract_runtime_type_usage(
                trace_memory_accesses, var_name
            )
            markers = self._type_checker.check(
                declared_type, runtime_usage, var_name
            )
            all_markers.extend(markers)

        # 维度 B: 分支一致性
        if decompiled_conditions and branch_trace:
            markers = self._branch_checker.check(
                decompiled_conditions, branch_trace
            )
            all_markers.extend(markers)

        # 维度 C: 变量活性
        decompiled_vars = set(type_declarations.keys())
        markers = self._liveness_checker.check(
            decompiled_vars, assembly_registers, assembly_memory_refs,
        )
        all_markers.extend(markers)

        # 汇总统计
        type_ok = sum(
            1 for m in all_markers
            if m.hallucination_type == HallucinationType.TYPE_MISMATCH
        )
        branch_ok = sum(
            1 for m in all_markers
            if m.hallucination_type == HallucinationType.BRANCH_INCONSISTENCY
        )
        var_ok = sum(
            1 for m in all_markers
            if m.hallucination_type == HallucinationType.SPURIOUS_VARIABLE
        )

        n_decls = max(1, len(type_declarations))
        n_conds = max(1, len(decompiled_conditions))
        n_vars = max(1, len(decompiled_vars))

        # 综合幻觉评分--越高越严重
        type_score = min(1.0, type_ok / n_decls * 2.0)
        branch_score = min(1.0, branch_ok / n_conds * 2.0)
        var_score = min(1.0, var_ok / n_vars * 2.0)

        overall = 0.4 * type_score + 0.35 * branch_score + 0.25 * var_score

        return HallucinationReport(
            function_name=function_name,
            total_markers=len(all_markers),
            markers=sorted(all_markers, key=lambda m: -m.confidence),
            overall_hallucination_score=round(overall, 4),
            type_consistency=round(1.0 - type_score, 4),
            branch_consistency=round(1.0 - branch_score, 4),
            variable_consistency=round(1.0 - var_score, 4),
        )
