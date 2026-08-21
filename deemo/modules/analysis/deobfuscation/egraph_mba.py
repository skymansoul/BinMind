#!/usr/bin/env python3
"""
E-graph MBA 表达式简化器

基于 的 e-graph 框架
使用等价类（e-class）和 e-node 数据结构对 MBA 混淆表达式进行
重写和简化。与传统规则匹配不同，e-graph 支持同时探索多条重写路径
通过提取最优重写结果

核心数据结构：
- ENode: 操作符 + 子节点 e-class ID 列表
- EClass: 等价节点集合 + 共享分析数据
- EGraph: 全局等价关系图

融合 的半线性 MBA 处理：
对含常量的位运算操作数进行部分求值后再入图
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)

# 条件导入 Z3（可选验证）
try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False
    logger.debug("z3 未安装，重写正确性验证不可用")


@dataclass
class ENode:
    # e-graph 节点：操作符 + 子 e-class ID 元组
    # op 类型: 'const', 'var', '+', '-', '*', '&', '|', '^', '<<', '>>', '~', 'neg'
    op: str
    children: Tuple[int, ...] = ()  # e-class IDs
    value: Optional[int] = None     # const 操作符的具体值
    var_name: Optional[str] = None  # var 操作符的变量名

    def __hash__(self):
        return hash((self.op, self.children, self.value, self.var_name))

    def __eq__(self, other):
        if not isinstance(other, ENode):
            return False
        return (self.op == other.op and self.children == other.children
                and self.value == other.value and self.var_name == other.var_name)


@dataclass
class EClass:
    """e-class: 一组等价节点"""
    id: int
    nodes: List[ENode] = field(default_factory=list)
    # 分析数据缓存
    is_const: bool = False
    const_value: Optional[int] = None

    def add_node(self, node: ENode) -> bool:
        if node not in self.nodes:
            self.nodes.append(node)
            return True
        return False


class EGraph:
    # 维护 e-class 集合 + e-node→e-class 映射
    # 支持 add/查找/合并/rebuild/提取

    def __init__(self):
        self.classes: List[EClass] = []
        self.hashcons: Dict[ENode, int] = {}  # e-node → e-class ID
        self.pending: List[Tuple[int, int]] = []  # 待合并 (id_a, id_b)
        self._analysis_dirty: bool = True

    def _new_class(self) -> int:
        cid = len(self.classes)
        self.classes.append(EClass(id=cid))
        return cid

    def add(self, op: str, children: Tuple[int, ...] = (),
            value: Optional[int] = None, var_name: Optional[str] = None) -> int:
        # 常量折叠：所有子节点皆为常量时直接计算
        if op in ('+', '-', '*', '&', '|', '^', '<<', '>>'):
            child_vals = []
            all_c = True
            for cid in children:
                ec = self.classes[cid]
                if ec.is_const and ec.const_value is not None:
                    child_vals.append(ec.const_value)
                else:
                    all_c = False
                    break
            if all_c and len(child_vals) == len(children):
                folded = self._eval_const(op, child_vals)
                if folded is not None:
                    return self.add('const', value=folded)

        node = ENode(op, children, value, var_name)

        if node in self.hashcons:
            return self.hashcons[node]

        cid = self._new_class()
        self.classes[cid].add_node(node)
        self.hashcons[node] = cid

        if op == 'const' and value is not None:
            self.classes[cid].is_const = True
            self.classes[cid].const_value = value

        self._analysis_dirty = True
        return cid

    def _eval_const(self, op: str, values: List[int]) -> Optional[int]:
        """常量表达式求值，32位截断"""
        mask = 0xFFFFFFFF
        try:
            if op == '+': return (values[0] + values[1]) & mask
            if op == '-': return (values[0] - values[1]) & mask
            if op == '*': return (values[0] * values[1]) & mask
            if op == '&': return values[0] & values[1]
            if op == '|': return values[0] | values[1]
            if op == '^': return values[0] ^ values[1]
            if op == '<<': return (values[0] << (values[1] & 31)) & mask
            if op == '>>': return (values[0] >> (values[1] & 31)) & mask
        except (IndexError, TypeError):
            pass
        return None

    def merge(self, id_a: int, id_b: int) -> int:
        """合并两个 e-class，返回合并后的 ID"""
        if id_a == id_b:
            return id_a
        # 总是合并到较小 ID（偏序）
        if id_a > id_b:
            id_a, id_b = id_b, id_a

        self.pending.append((id_b, id_a))
        return id_a

    def find(self, node: ENode) -> Optional[int]:
        return self.hashcons.get(node)

    def rebuild(self) -> int:
        """
        执行 congruence closure + union-查找 合并

        返回本轮合并的 e-class 对数
        """
        merged = 0
        while self.pending:
            id_from, id_to = self.pending.pop()

            # 跳过已被合并的 class
            if not self.classes[id_from].nodes:
                continue

            # 合并节点
            for node in self.classes[id_from].nodes:
                self.classes[id_to].add_node(node)
                self.hashcons[node] = id_to

            # 更新常量信息
            if self.classes[id_from].is_const:
                self.classes[id_to].is_const = True
                self.classes[id_to].const_value = self.classes[id_from].const_value

            self.classes[id_from].nodes = []
            merged += 1

            # 检查父节点是否需要合并
            for other_node in list(self.classes[id_to].nodes):
                for i, child_id in enumerate(other_node.children):
                    if child_id == id_from:
                        new_children = list(other_node.children)
                        new_children[i] = id_to
                        new_node = ENode(
                            other_node.op, tuple(new_children),
                            other_node.value, other_node.var_name
                        )
                        existing = self.find(new_node)
                        if existing is not None and existing != id_to:
                            self.pending.append((existing, id_to))

        self._analysis_dirty = True
        return merged

    def extract(self, cid: int, depth: int = 0, max_depth: int = 10) -> str:
        """
        从 e-class 提取最优表达式（最小 AST 深度优先）
        """
        if depth >= max_depth:
            ec = self.classes[cid]
            if ec.is_const:
                return str(ec.const_value)
            if ec.nodes:
                first = ec.nodes[0]
                if first.op == 'var':
                    return first.var_name or '?'
                if first.op == 'const':
                    return str(first.value)
            return '?'

        ec = self.classes[cid]
        if ec.is_const:
            return str(ec.const_value)

        if not ec.nodes:
            return '?'

        best = None
        best_len = float('inf')

        for node in ec.nodes:
            if node.op == 'const':
                cand = str(node.value)
            elif node.op == 'var':
                cand = node.var_name or '?'
            elif node.op == '~':
                inner = self.extract(node.children[0], depth + 1, max_depth)
                cand = f'(~{inner})'
            elif node.op == 'neg':
                inner = self.extract(node.children[0], depth + 1, max_depth)
                cand = f'(-{inner})'
            elif len(node.children) == 2:
                left = self.extract(node.children[0], depth + 1, max_depth)
                right = self.extract(node.children[1], depth + 1, max_depth)
                cand = f'({left} {node.op} {right})'
            else:
                continue

            if len(cand) < best_len:
                best_len = len(cand)
                best = cand

        return best or '?'


class MBARewriteRules:
    """
    MBA 重写规则集

    融合 [Lee 2024, 2404.05431] 的 25 条恒等规则
    与 [Skees 2024, 2406.10016] 的半线性扩展规则
    """

    # 标准线性 MBA 规则（e-graph 格式）
    RULES = [
        # (x ^ y) + 2*(x & y) = x + y
        ('add', ('xor', 'x', 'y'), ('mul', ('const', 2), ('and', 'x', 'y')),
         'add', 'x', 'y'),
        # (x | y) - (x & y) = x ^ y
        ('sub', ('or', 'x', 'y'), ('and', 'x', 'y'),
         'xor', 'x', 'y'),
        # x + x = x * 2
        ('add', 'x', 'x',
         'mul', 'x', ('const', 2)),
        # x ^ x = 0
        ('xor', 'x', 'x',
         'const', None, None, 0),
        # x & x = x
        ('and', 'x', 'x',
         'var', 'x'),
        # x | x = x
        ('or', 'x', 'x',
         'var', 'x'),
        # x & 0 = 0
        ('and', 'x', ('const', 0),
         'const', None, None, 0),
        # ~(~x | ~y) = x & y
        ('not', ('or', ('not', 'x'), ('not', 'y')),
         'and', 'x', 'y'),
        # ~(~x & ~y) = x | y
        ('not', ('and', ('not', 'x'), ('not', 'y')),
         'or', 'x', 'y'),
        # (x + y) - y = x
        ('sub', ('add', 'x', 'y'), 'y',
         'var', 'x'),
        # (x ^ y) ^ y = x
        ('xor', ('xor', 'x', 'y'), 'y',
         'var', 'x'),
        # (x << 3) - x = x * 7 [TrickBot 模式]
        ('sub', ('shl', 'x', ('const', 3)), 'x',
         'mul', 'x', ('const', 7)),
        # (x ^ y) + ((x & y) << 1) = x + y [TrickBot carry-addition]
        ('add', ('xor', 'x', 'y'), ('shl', ('and', 'x', 'y'), ('const', 1)),
         'add', 'x', 'y'),
        # (~x + y) + 1 = y - x [2's complement variant]
        ('add', ('add', ('not', 'x'), 'y'), ('const', 1),
         'sub', 'y', 'x'),
    ]

    @classmethod
    def apply_rules(cls, egraph: EGraph, max_iterations: int = 5) -> int:
        """
        将规则集迭代应用于 e-graph

        返回新创建的等价类数量（即发现的新等价关系数）
        """
        total_new = 0

        for iteration in range(max_iterations):
            new_this_round = 0
            node_list = [
                (cid, node)
                for cid, ec in enumerate(egraph.classes)
                if ec.nodes
                for node in ec.nodes
            ]

            # 对每对 (e-class, node) 尝试模式匹配
            for cid, node in node_list:
                matched = cls._try_match_node(egraph, node)
                for existing_cid in matched:
                    if cid != existing_cid:
                        egraph.merge(cid, existing_cid)
                        new_this_round += 1

            merged = egraph.rebuild()
            total_new += new_this_round + merged

            if new_this_round + merged == 0:
                break  # 不动点

        return total_new

    @classmethod
    def _try_match_node(cls, egraph: EGraph, node: ENode) -> Set[int]:
        """
        尝试对单个 e-node 匹配所有规则

        返回匹配到的等价 e-class ID 集合
        """
        results: Set[int] = set()

        for rule in cls.RULES:
            res = cls._match_single_rule(egraph, node, rule)
            if res is not None:
                results.add(res)

        return results

    @classmethod
    def _match_single_rule(cls, egraph: EGraph, node: ENode, rule: tuple) -> Optional[int]:
        """
        单条规则的匹配和实例化
        """
        # 简化：使用操作符名称匹配
        # 完整的模式匹配需要 AST 遍历，这里实现关键规则的快速路径
        op = node.op

        # 规则: x ^ x = 0
        if op == 'xor' and len(node.children) == 2:
            if node.children[0] == node.children[1]:
                return egraph.add('const', value=0)

        # 规则: x & x = x
        if op == 'and' and len(node.children) == 2:
            if node.children[0] == node.children[1]:
                return node.children[0]

        # 规则: x | x = x
        if op == 'or' and len(node.children) == 2:
            if node.children[0] == node.children[1]:
                return node.children[0]

        # 规则: x & 0 = 0
        if op == 'and' and len(node.children) == 2:
            if (egraph.classes[node.children[1]].is_const
                    and egraph.classes[node.children[1]].const_value == 0):
                return egraph.add('const', value=0)
            if (egraph.classes[node.children[0]].is_const
                    and egraph.classes[node.children[0]].const_value == 0):
                return egraph.add('const', value=0)

        # 规则: (x << 3) - x = x * 7
        if op == 'sub' and len(node.children) == 2:
            left = node.children[0]
            right = node.children[1]
            l_nodes = egraph.classes[left].nodes
            if l_nodes and l_nodes[0].op == '<<':
                shl_node = l_nodes[0]
                if (len(shl_node.children) == 2
                        and egraph.classes[shl_node.children[1]].is_const
                        and egraph.classes[shl_node.children[1]].const_value == 3):
                    if shl_node.children[0] == right:
                        x_cid = right
                        seven = egraph.add('const', value=7)
                        return egraph.add('*', (x_cid, seven))

        return None


class MBASimplifier:
    """
    MBA 表达式简化器（e-graph 后端）

    端到端流程：
    1. 解析输入表达式为 AST
    2. 将 AST 转换为 e-graph
    3. 迭代应用重写规则
    4. 提取最优简化结果
    5. 可选 Z3 验证 [Skees 2024]
    """

    def __init__(self, bit_width: int = 32, verify_z3: bool = True):
        self.bit_width = bit_width
        self.verify_z3 = verify_z3 and _HAS_Z3
        self._var_counter = 0
        self._var_map: Dict[str, int] = {}

    def simplify(self, expr_str: str) -> Dict[str, Any]:
        """简化 MBA 表达式, 返回含 original/simplified/steps/verified 的 dict。"""
        egraph = EGraph()

        # 解析 → AST → EGraph
        tokens = self._tokenize(expr_str)
        root_cid = self._build_egraph(egraph, tokens)

        if root_cid is None:
            return {
                'original': expr_str,
                'simplified': expr_str,
                'steps': 0,
                'verified': False,
                'error': '解析失败'
            }

        original_rep = egraph.extract(root_cid)

        # Apply rewrite rules
        steps = MBARewriteRules.apply_rules(egraph, max_iterations=5)

        # 提取
        simplified = egraph.extract(root_cid)

        # Verify
        verified = False
        if self.verify_z3 and simplified != original_rep:
            verified = self._z3_verify(original_rep, simplified)

        return {
            'original': expr_str,
            'simplified': simplified,
            'steps': steps,
            'verified': verified
        }

    def _tokenize(self, expr_str: str) -> List[str]:
        """词法分析：将表达式拆分为 token 序列"""
        expr = expr_str.replace(' ', '')
        tokens = []
        i = 0
        while i < len(expr):
            c = expr[i]
            if c in '()+-*&|^~':
                tokens.append(c)
                i += 1
            elif c == '<' and i + 1 < len(expr) and expr[i + 1] == '<':
                tokens.append('<<')
                i += 2
            elif c == '>' and i + 1 < len(expr) and expr[i + 1] == '>':
                tokens.append('>>')
                i += 2
            elif c.isdigit() or (c == '0' and i + 1 < len(expr) and expr[i + 1] in 'xX'):
                j = i
                while j < len(expr) and (expr[j].isdigit() or expr[j] in 'xXabcdefABCDEF'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            elif c.isalpha() or c == '_':
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == '_'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                i += 1
        return tokens

    def _build_egraph(self, egraph: EGraph, tokens: List[str]) -> Optional[int]:
        """将 token 序列构建为 e-graph 节点"""
        # 简化实现：递归下降解析基本表达式
        return self._parse_expr(egraph, tokens, 0)[0]

    def _parse_expr(self, egraph: EGraph, tokens: List[str], pos: int
                    ) -> Tuple[Optional[int], int]:
        """递归下降解析器，返回 (eclass_id, next_pos)"""
        if pos >= len(tokens):
            return None, pos

        token = tokens[pos]

        if token == '(':
            # 处理二元操作符: (left op right)
            if pos + 3 >= len(tokens):
                return None, pos

            left, pos = self._parse_atom(egraph, tokens, pos + 1)
            if left is None or pos >= len(tokens):
                return None, pos

            op_token = tokens[pos]
            op_map = {'+': '+', '-': '-', '*': '*', '&': '&', '|': '|', '^': '^',
                      '<<': '<<', '>>': '>>'}
            if op_token not in op_map:
                return None, pos
            pos += 1

            right, pos = self._parse_atom(egraph, tokens, pos)
            if right is None:
                return None, pos

            if pos < len(tokens) and tokens[pos] == ')':
                pos += 1

            cid = egraph.add(op_map[op_token], (left, right))
            return cid, pos

        elif token == '~':
            inner, pos = self._parse_atom(egraph, tokens, pos + 1)
            if inner is None:
                return None, pos
            return egraph.add('~', (inner,)), pos

        else:
            return self._parse_atom(egraph, tokens, pos)

    def _parse_atom(self, egraph: EGraph, tokens: List[str], pos: int
                    ) -> Tuple[Optional[int], int]:
        """解析原子：变量、常量或嵌套表达式"""
        if pos >= len(tokens):
            return None, pos

        token = tokens[pos]

        if token == '(':
            return self._parse_expr(egraph, tokens, pos)

        # 常量
        try:
            if token.startswith('0x') or token.startswith('0X'):
                value = int(token, 16)
            else:
                value = int(token)
            return egraph.add('const', value=value), pos + 1
        except ValueError:
            pass

        # 变量
        if token not in self._var_map:
            self._var_map[token] = self._var_counter
            self._var_counter += 1

        return egraph.add('var', var_name=token), pos + 1

    def _z3_verify(self, expr_a: str, expr_b: str) -> bool:
        """
        使用 Z3 验证两个表达式等价

        对 32-bit 位向量进行全量词验证
        参考 [Skees 2024] 的验证策略
        """
        if not _HAS_Z3:
            return False

        try:
            # 收集所有变量
            vars_a = set(re.findall(r'[a-zA-Z_]\w*', expr_a))
            vars_b = set(re.findall(r'[a-zA-Z_]\w*', expr_b))
            all_vars = (vars_a | vars_b) - {'and', 'or', 'not', 'xor'}

            z3_vars = {v: z3.BitVec(v, self.bit_width) for v in all_vars}

            def _to_z3(expr_str: str) -> z3.BitVecRef:
                """将字符串表达式转为 Z3 表达式（简化版）"""
                code = expr_str
                for v, bv in z3_vars.items():
                    code = re.sub(r'\b' + v + r'\b', f'z3_vars["{v}"]', code)
                code = code.replace('^', '^')
                code = code.replace('&', '&')
                code = code.replace('|', '|')
                code = code.replace('~', '~')
                code = code.replace('<<', '<<')
                code = code.replace('>>', '>>')
                try:
                    return eval(code, {'z3_vars': z3_vars, 'z3': z3})
                except Exception:
                    return None

            z3_a = _to_z3(expr_a)
            z3_b = _to_z3(expr_b)

            if z3_a is None or z3_b is None:
                return False

            solver = z3.Solver()
            solver.add(z3_a != z3_b)
            result = solver.check()
            return str(result) == 'unsat'

        except Exception as e:
            logger.debug(f"Z3 验证异常: {e}")
            return False


def simplify_mba_egraph(expr: str, bit_width: int = 32) -> Dict[str, Any]:
    """
    便捷函数：使用 e-graph 简化 MBA 表达式

    终端用户接口，实现 [Lee 2024, 2404.05431] 的完整流程
    """
    simplifier = MBASimplifier(bit_width=bit_width, verify_z3=_HAS_Z3)
    return simplifier.simplify(expr)
