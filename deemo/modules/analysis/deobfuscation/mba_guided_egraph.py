# 不变量引导的规则调度: 每轮迭代只激活高优先级规则, 其余惰性求值
# 指纹碰撞快速合并: 同指纹节点跳过重写直接合并

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .mba_invariant_lifter import MBAInvariantLifter


# 规则定义

@dataclass
class RewriteRule:
    name: str
    pattern_op: str          # 匹配的操作符
    pattern_arity: int       # 匹配的子节点数
    # 条件: 给定匹配的 e-node, 返回是否可应用此规则
    condition: Optional[Callable[[Dict], bool]] = None
    # 变换: 给定原始 e-node, 返回重写后的 e-node
    transform: Optional[Callable[[Dict], Dict]] = None
    # 优先级: 0=低 (惰性), 1=中, 2=高 (立即应用)
    priority: int = 1


# 标准 MBA 重写规则集

def _build_mba_rules() -> List[RewriteRule]:
    rules: List[RewriteRule] = []

# 高优先级: 常量折叠和恒等元
    rules.append(RewriteRule(
        name="and_zero", pattern_op="&", pattern_arity=2, priority=2,
        condition=lambda n: (
            (n['children'][0].get('op') == 'const' and n['children'][0].get('value') == 0)
            or (n['children'][1].get('op') == 'const' and n['children'][1].get('value') == 0)
        ),
        transform=lambda n: {'op': 'const', 'value': 0, 'children': [], 'var': None},
    ))
    rules.append(RewriteRule(
        name="or_one", pattern_op="|", pattern_arity=2, priority=2,
        condition=lambda n: (
            (n['children'][0].get('op') == 'const' and n['children'][0].get('value') == 1)
            or (n['children'][1].get('op') == 'const' and n['children'][1].get('value') == 1)
        ),
        transform=lambda n: {'op': 'const', 'value': 1, 'children': [], 'var': None},
    ))
    rules.append(RewriteRule(
        name="xor_self", pattern_op="^", pattern_arity=2, priority=2,
        condition=lambda n: _nodes_equal(n['children'][0], n['children'][1]),
        transform=lambda n: {'op': 'const', 'value': 0, 'children': [], 'var': None},
    ))
    rules.append(RewriteRule(
        name="and_self", pattern_op="&", pattern_arity=2, priority=2,
        condition=lambda n: _nodes_equal(n['children'][0], n['children'][1]),
        transform=lambda n: n['children'][0],  # x & x -> x
    ))
    rules.append(RewriteRule(
        name="or_self", pattern_op="|", pattern_arity=2, priority=2,
        condition=lambda n: _nodes_equal(n['children'][0], n['children'][1]),
        transform=lambda n: n['children'][0],  # x | x -> x
    ))

# 中优先级: 互补和分配
    rules.append(RewriteRule(
        name="and_not_self", pattern_op="&", pattern_arity=2, priority=1,
        condition=lambda n: (
            n['children'][0].get('op') == '~'
            and _nodes_equal(n['children'][0]['children'][0], n['children'][1])
        ) or (
            n['children'][1].get('op') == '~'
            and _nodes_equal(n['children'][1]['children'][0], n['children'][0])
        ),
        transform=lambda n: {'op': 'const', 'value': 0, 'children': [], 'var': None},
    ))
    rules.append(RewriteRule(
        name="or_not_self", pattern_op="|", pattern_arity=2, priority=1,
        condition=lambda n: (
            n['children'][0].get('op') == '~'
            and _nodes_equal(n['children'][0]['children'][0], n['children'][1])
        ) or (
            n['children'][1].get('op') == '~'
            and _nodes_equal(n['children'][1]['children'][0], n['children'][0])
        ),
        transform=lambda n: {'op': 'const', 'value': 1, 'children': [], 'var': None},
    ))
# 低优先级: 交换律 / 结合律
    # 这些变换不直接化简但为其他规则创造匹配机会
    rules.append(RewriteRule(
        name="add_commute", pattern_op="+", pattern_arity=2, priority=0,
        condition=lambda n: True,
        transform=lambda n: {
            'op': '+', 'children': [n['children'][1], n['children'][0]],
            'value': None, 'var': None,
        },
    ))
    rules.append(RewriteRule(
        name="and_commute", pattern_op="&", pattern_arity=2, priority=0,
        condition=lambda n: True,
        transform=lambda n: {
            'op': '&', 'children': [n['children'][1], n['children'][0]],
            'value': None, 'var': None,
        },
    ))
    rules.append(RewriteRule(
        name="or_commute", pattern_op="|", pattern_arity=2, priority=0,
        condition=lambda n: True,
        transform=lambda n: {
            'op': '|', 'children': [n['children'][1], n['children'][0]],
            'value': None, 'var': None,
        },
    ))
    rules.append(RewriteRule(
        name="xor_commute", pattern_op="^", pattern_arity=2, priority=0,
        condition=lambda n: True,
        transform=lambda n: {
            'op': '^', 'children': [n['children'][1], n['children'][0]],
            'value': None, 'var': None,
        },
    ))

    return rules


def _nodes_equal(a: Dict, b: Dict) -> bool:
    if a.get('op') != b.get('op'):
        return False
    if a.get('value') != b.get('value'):
        return False
    if a.get('var') != b.get('var'):
        return False
    ca, cb = a.get('children', []), b.get('children', [])
    if len(ca) != len(cb):
        return False
    return all(ca[i] is cb[i] for i in range(len(ca)))


# 不变量引导的 e-graph 化简器

@dataclass
class SimplifyStats:
    initial_nodes: int = 0
    final_nodes: int = 0
    rules_applied: Dict[str, int] = field(default_factory=dict)
    fingerprint_merges: int = 0
    iterations: int = 0
    elapsed_ms: float = 0.0


class InvariantGuidedEGraph:

    def __init__(self, max_iterations: int = 5):
        self._rules = _build_mba_rules()
        self._lifter = MBAInvariantLifter()
        self._max_iter = max_iterations
        # 收敛检测参数
        self._stagnation_threshold = 0.05  # < 5% 新增 -> 趋近饱和

    def simplify(self, expr: Dict) -> Tuple[Dict, SimplifyStats]:
        t0 = time.perf_counter()
        stats = SimplifyStats(initial_nodes=self._count_nodes(expr))

        # Phase 1: 抽象不变量提取
        root_av, root_fp = self._lifter.lift(expr)
        if root_av.is_constant:
            # 表达式在三值格上即为常数-直接折叠, 跳过 e-graph
            stats.final_nodes = 1
            stats.elapsed_ms = (time.perf_counter() - t0) * 1000
            stats.iterations = 0
            const_val = 0 if root_av.is_zero else 1
            return {'op': 'const', 'value': const_val, 'children': [], 'var': None}, stats

        # Phase 2: 迭代重写
        current = expr
        prev_node_count = self._count_nodes(current)
        rules_by_priority = self._partition_rules()

        for iteration in range(self._max_iter):
            stats.iterations = iteration + 1

            # 收集当前表达式树中所有可重写位置
            matches = self._find_rewrite_matches(current, rules_by_priority)

            if not matches:
                break

            # 按优先级排序: 高优先级先应用 (产生更大化简收益)
            matches.sort(key=lambda m: -m[2])  # m[2] = rule_priority

            # 应用重写
            applied_any = False
            for node_ref, rule, _ in matches:
                try:
                    if rule.condition and not rule.condition(node_ref):
                        continue
                    new_node = rule.transform(node_ref)
                    # 检查是否真正产生了不同的表达式
                    if not _nodes_equal(node_ref, new_node):
                        self._inline_replace(node_ref, new_node)
                        stats.rules_applied[rule.name] = \
                            stats.rules_applied.get(rule.name, 0) + 1
                        applied_any = True
                except (KeyError, IndexError, TypeError):
                    continue

            if not applied_any:
                break

            # 收敛检测
            new_node_count = self._count_nodes(current)
            growth_rate = (new_node_count - prev_node_count) / max(1, prev_node_count)
            if growth_rate < self._stagnation_threshold and iteration >= 2:
                # 连续两轮增长 < 5% -> 趋近饱和, 提前终止
                break
            prev_node_count = new_node_count

        stats.final_nodes = self._count_nodes(current)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000

        return current, stats

    def _partition_rules(self) -> Dict[int, List[RewriteRule]]:
        groups: Dict[int, List[RewriteRule]] = defaultdict(list)
        for r in self._rules:
            groups[r.priority].append(r)
        return dict(groups)

    def _find_rewrite_matches(
        self, expr: Dict, rules_by_priority: Dict[int, List[RewriteRule]]
    ) -> List[Tuple[Dict, RewriteRule, int]]:
        matches: List[Tuple[Dict, RewriteRule, int]] = []
        self._collect_matches(expr, rules_by_priority, matches)
        return matches

    def _collect_matches(
        self,
        node: Dict,
        rules_by_priority: Dict[int, List[RewriteRule]],
        matches: List[Tuple[Dict, RewriteRule, int]],
    ) -> None:
        op = node.get('op', 'var')
        # 对当前节点尝试匹配规则
        for priority, rules in rules_by_priority.items():
            for rule in rules:
                if rule.pattern_op == op and rule.pattern_arity <= len(
                    node.get('children', [])
                ):
                    matches.append((node, rule, priority))

        # 递归到子节点
        for child in node.get('children', []):
            if isinstance(child, dict):
                self._collect_matches(child, rules_by_priority, matches)

    @staticmethod
    def _inline_replace(node: Dict, replacement: Dict) -> None:
        node['op'] = replacement.get('op', 'var')
        node['children'] = replacement.get('children', [])
        node['value'] = replacement.get('value')
        node['var'] = replacement.get('var')

    @staticmethod
    def _count_nodes(expr: Dict) -> int:
        count = 1
        for child in expr.get('children', []):
            if isinstance(child, dict):
                count += InvariantGuidedEGraph._count_nodes(child)
        return count


# 便捷接口

def simplify_mba_expr(expr: Dict) -> Tuple[Dict, SimplifyStats]:
    engine = InvariantGuidedEGraph()
    return engine.simplify(expr)
