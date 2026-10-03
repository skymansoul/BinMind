"""
轻量污点引擎 - def-use 链重建 + 简化VSA, 为格式化字符串/堆溢出/UAF
检测器提供共享数据流分析基础设施。无重依赖(angr/z3), 直接在反编译
IR文本上运行。设计: 精度换速度, 最多10跳回溯, 每结果带confidence。
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DefUseNode:
    """def-use 图节点 - 一条赋值语句。"""
    pc: int                          # 指令地址
    var_name: str                    # 被赋值的变量名
    rhs: str                         # 右值表达式 (原始文本)
    uses: list[str] = field(default_factory=list)    # 此赋值引用的变量名列表
    defined_by: list[int] = field(default_factory=list)  # 定义 uses 中变量的节点 pc 列表
    source_type: str = ''            # 'user_input' | 'const' | 'heap' | 'stack' | 'unknown'
    source_confidence: float = 0.0


@dataclass
class ValueSet:
    """简化值集 - 分类来源类型而非具体值。"""
    types: set[str]   # 此变量可能属于的类别集合
    confidences: dict[str, float]

    def is_user_controlled(self, threshold: float = 0.5) -> bool:
        return self.confidences.get('user_input', 0.0) >= threshold

    def is_constant(self) -> bool:
        return 'const' in self.types and len(self.types) == 1

    @staticmethod
    def unknown() -> 'ValueSet':
        return ValueSet(types={'unknown'}, confidences={'unknown': 0.0})

    @staticmethod
    def from_source(source: str, confidence: float = 1.0) -> 'ValueSet':
        return ValueSet(types={source}, confidences={source: confidence})

    def merge(self, other: 'ValueSet') -> 'ValueSet':
        """合并两个值集 (phi node 或条件分支汇合点)。"""
        all_types = self.types | other.types
        merged_conf = {}
        for t in all_types:
            c1 = self.confidences.get(t, 0.0)
            c2 = other.confidences.get(t, 0.0)
            merged_conf[t] = max(c1, c2)
        return ValueSet(types=all_types, confidences=merged_conf)


class LightweightTaintEngine:
    """轻量污点传播引擎。

    输入: 反编译后的指令列表 (每行一条 IR 指令)。
    输出: 每个变量的 ValueSet, 分类来源为用户输入/堆/常量。
    """

    # 用户输入源函数的识别名
    _USER_INPUT_SOURCES = {
        'read', 'fread', 'fgets', 'gets', 'scanf', 'fscanf', 'recv', 'recvfrom',
        'getline', '__isoc99_scanf', '__isoc99_fscanf',
        'argv', 'argc', 'environ',
    }
    # 堆分配函数的识别名
    _HEAP_SOURCES = {
        'malloc', 'calloc', 'realloc', 'memalign', 'posix_memalign',
        'operator_new', 'new', 'g_malloc', 'g_malloc0',
    }
    # 栈分配模式
    _STACK_PATTERNS = {'alloca', '__builtin_alloca'}

    def __init__(self, max_backtrack_hops: int = 5):
        self._max_hops = max_backtrack_hops
        self._nodes: dict[int, DefUseNode] = {}

    def build_defuse_graph(self, ir_lines: list[str]) -> dict[int, DefUseNode]:
        """从反编译 IR 文本构建 def-use 图。

        识别形如 `var = expr` 或 `%1 = load i32, ptr %2` 的 SSA 赋值。
        返回 {pc: DefUseNode} 映射。"""
        self._nodes = {}

        # 匹配赋值语句: var = expr 或 %id = op args
        assign_pat = re.compile(
            r'(?:%\w+|\w+)\s*=\s*(.+)'
        )
        var_pat = re.compile(r'%(\w+)|(\b[a-z_]\w{1,31}\b)')

        for i, line in enumerate(ir_lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(('#', '//', ';')):
                continue

            m = assign_pat.match(stripped)
            if not m:
                continue

            rhs = m.group(1)
            # 提取被赋值变量: 等号左侧
            lhs_match = re.match(r'(%\w+|\w+)', stripped)
            if not lhs_match:
                continue
            var_name = lhs_match.group(1)

            # 提取 rhs 中引用的变量
            used_vars = []
            for vm in var_pat.finditer(rhs):
                v = vm.group(1) or vm.group(2)
                if v and v != var_name and not v.isdigit():
                    used_vars.append(v)

            node = DefUseNode(pc=i, var_name=var_name, rhs=rhs, uses=used_vars)
            self._nodes[i] = node

        # 建立 defined_by 链接: 对每个 use, 找最近的定义
        for pc, node in self._nodes.items():
            for u in node.uses:
                def_pc = self._find_nearest_def(u, pc)
                if def_pc is not None:
                    node.defined_by.append(def_pc)

        return self._nodes

    def _find_nearest_def(self, var_name: str, before_pc: int) -> Optional[int]:
        """在 before_pc 之前查找 var_name 的最近定义。"""
        best_pc = None
        for pc, node in self._nodes.items():
            if pc < before_pc and node.var_name == var_name:
                if best_pc is None or pc > best_pc:
                    best_pc = pc
        return best_pc

    def trace_source(self, var_name: str, start_pc: int) -> ValueSet:
        """从 start_pc 处回溯变量 var_name 的来源。

        沿 defined_by 链递归回溯, 最多 _max_hops 跳。
        若链的末端是用户输入函数/堆分配/常量, 返回对应的 ValueSet。"""
        visited = set()
        return self._trace_impl(var_name, start_pc, 0, visited)

    def _trace_impl(self, var_name: str, pc: int, depth: int,
                    visited: set[tuple]) -> ValueSet:
        if depth > self._max_hops:
            return ValueSet.unknown()

        key = (var_name, pc)
        if key in visited:
            return ValueSet.unknown()
        visited.add(key)

        node = self._nodes.get(pc)
        if node is None:
            # pc 处无赋值; 检查 var_name 是否为参数/全局变量
            return ValueSet.from_source(
                'user_input', 0.4) if self._looks_like_param(var_name) else ValueSet.unknown()

        # 检查 rhs 是否直接调用了源函数
        src, conf = self._match_source_call(node.rhs)
        if src:
            return ValueSet.from_source(src, conf)

        # 沿 defined_by 链递归
        if not node.defined_by:
            # 链终止: 检查 rhs 是否为字面量常量
            if self._is_literal_constant(node.rhs):
                return ValueSet.from_source('const', 0.95)
            return ValueSet.unknown()

        # 多来源定义 (如 phi 节点): 合并所有路径
        merged = ValueSet(types=set(), confidences={})
        for def_pc in node.defined_by:
            def_node = self._nodes.get(def_pc)
            if def_node:
                result = self._trace_impl(def_node.var_name, def_pc, depth + 1, visited)
                merged = merged.merge(result)
        return merged if merged.types else ValueSet.unknown()

    def _match_source_call(self, rhs: str) -> tuple[str, float]:
        """检查 rhs 是否调用了已知源函数。返回 (source_type, confidence)。"""
        rhs_lower = rhs.lower()
        for src in self._USER_INPUT_SOURCES:
            if src in rhs_lower:
                return ('user_input', 0.85)
        for src in self._HEAP_SOURCES:
            if src in rhs_lower:
                return ('heap', 0.90)
        for pat in self._STACK_PATTERNS:
            if pat in rhs_lower:
                return ('stack', 0.90)
        return ('', 0.0)

    def _is_literal_constant(self, rhs: str) -> bool:
        r = rhs.strip()
        if r.startswith('"') and r.endswith('"'):
            return True
        try:
            int(r, 0)
            return True
        except (ValueError, TypeError):
            return False

    def _looks_like_param(self, var_name: str) -> bool:
        """启发式: 变量名是否像函数参数 (a1, arg0, param1 等)。"""
        return any(p in var_name.lower() for p in ('arg', 'param', 'a0', 'a1', 'a2', 'a3'))

    def compute_variable_sources(self, var_names: list[str], at_pc: int) -> dict[str, ValueSet]:
        """批量计算多个变量在指定 pc 处的来源。"""
        return {v: self.trace_source(v, at_pc) for v in var_names}

    def stats(self) -> dict:
        return {
            'nodes': len(self._nodes),
            'max_hops': self._max_hops,
        }
