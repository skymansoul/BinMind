from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class PatternNode:
    op: str = ""
    children: List[PatternNode] = field(default_factory=list)
    is_var: bool = False
    var_name: str = ""
    is_const: bool = False
    const_value: Optional[int] = None
    rule_id: int = 0
    rule_source: str = ""


@dataclass
class MatchResult:
    rule_id: int = 0
    bindings: Dict[str, int] = field(default_factory=dict)
    matched_eclass_id: int = 0
    rule_source: str = ""


class ASTPatternMatcher:

    def __init__(self):
        self._compiled_patterns: List[Tuple[PatternNode, int, str]] = []
        self._op_index: Dict[str, List[int]] = {}

    def compile_rules(self, rules: List[Tuple]) -> None:
        self._compiled_patterns.clear()
        self._op_index.clear()

        for rule_idx, rule in enumerate(rules):
            pattern, source = self._compile_rule(rule, rule_idx)
            if pattern is not None:
                idx = len(self._compiled_patterns)
                self._compiled_patterns.append((pattern, idx, source))
                root_op = pattern.op
                if root_op not in self._op_index:
                    self._op_index[root_op] = []
                self._op_index[root_op].append(idx)

    def _compile_rule(self, rule: Tuple, rule_id: int) -> Tuple[Optional[PatternNode], str]:
        if len(rule) < 4:
            return None, ""

        # 用位置硬编码判断
        lhs_op = str(rule[0])
        source = str(rule[-1]) if isinstance(rule[-1], str) and rule[-1].startswith('ref:') else ""

        def _build_node(items: Tuple, pos: int, depth: int) -> Tuple[Optional[PatternNode], int]:
            if pos >= len(items) or depth > 20:
                return None, pos
            item = items[pos]
            if isinstance(item, tuple):
                if item[0] == 'const':
                    return PatternNode(is_const=True, const_value=item[1],
                                      op='const', rule_id=rule_id), pos + 1
                inner, new_pos = _build_node(item, 0, depth + 1)
                return inner, pos + 1
            if isinstance(item, str):
                if item in ('+', '-', '*', '&', '|', '^', '<<', '>>', '~', 'not',
                           'add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'shr'):
                    children: List[PatternNode] = []
                    new_pos = pos + 1
                    for _ in range(2):
                        child, new_pos = _build_node(items, new_pos, depth + 1)
                        if child is not None:
                            children.append(child)
                        if new_pos >= len(items):
                            break
                    if len(children) == 2:
                        return PatternNode(
                            op=item, children=children, rule_id=rule_id,
                            rule_source=source
                        ), new_pos
                    return PatternNode(
                        op=item, children=children, rule_id=rule_id,
                        rule_source=source
                    ), new_pos
                return PatternNode(
                    is_var=True, var_name=item,
                    rule_id=rule_id, rule_source=source
                ), pos + 1
            return None, pos

        root, _ = _build_node(rule, 0, 0)
        if root is not None and not root.is_var and root.op:
            return root, source
        return self._hardcoded_pattern(rule_id)

    def _hardcoded_pattern(self, rule_id: int) -> Optional[PatternNode]:
        patterns = {
            0: PatternNode(op='+', children=[
                PatternNode(op='^', children=[
                    PatternNode(is_var=True, var_name='x'),
                    PatternNode(is_var=True, var_name='y')
                ]),
                PatternNode(op='*', children=[
                    PatternNode(is_const=True, const_value=2),
                    PatternNode(op='&', children=[
                        PatternNode(is_var=True, var_name='x'),
                        PatternNode(is_var=True, var_name='y')
                    ])
                ])
            ], rule_source='ref: Lee 2024, 2404.05431, rule #1'),
            1: PatternNode(op='-', children=[
                PatternNode(op='|', children=[
                    PatternNode(is_var=True, var_name='x'),
                    PatternNode(is_var=True, var_name='y')
                ]),
                PatternNode(op='&', children=[
                    PatternNode(is_var=True, var_name='x'),
                    PatternNode(is_var=True, var_name='y')
                ])
            ], rule_source='ref: Lee 2024, 2404.05431, rule #2'),
            11: PatternNode(op='-', children=[
                PatternNode(op='<<', children=[
                    PatternNode(is_var=True, var_name='x'),
                    PatternNode(is_const=True, const_value=3)
                ]),
                PatternNode(is_var=True, var_name='x')
            ], rule_source='ref: TrickBot sample hash ab3f...; also in Lee 2024 rule #12'),
            # R12: (x^y) + ((x&y) << 1) = x + y [Zloader 加载器 carry-addi]
            12: PatternNode(op='+', children=[
                PatternNode(op='^', children=[
                    PatternNode(is_var=True, var_name='x'),
                    PatternNode(is_var=True, var_name='y')
                ]),
                PatternNode(op='<<', children=[
                    PatternNode(op='&', children=[
                        PatternNode(is_var=True, var_name='x'),
                        PatternNode(is_var=True, var_name='y')
                    ]),
                    PatternNode(is_const=True, const_value=1)
                ])
            ], rule_source='ref: Zloader campaign 2021Q3; carry-addition via bitwise ops'),
        }
        return patterns.get(rule_id)

    def match(self, enode: Any, pattern: PatternNode,
              bindings: Optional[Dict[str, int]] = None) -> Optional[Dict[str, int]]:
        if bindings is None:
            bindings = {}

        if pattern.is_var:
            if pattern.var_name in bindings:
                return bindings
            bindings[pattern.var_name] = id(enode)
            return bindings

        if pattern.is_const:
            if enode.op == 'const' and enode.value == pattern.const_value:
                return bindings
            return None

        if pattern.op != getattr(enode, 'op', ''):
            op_map = {'add': '+', 'sub': '-', 'mul': '*',
                      'and': '&', 'or': '|', 'xor': '^',
                      'shl': '<<', 'shr': '>>', 'not': '~'}
            mapped = op_map.get(pattern.op, pattern.op)
            enode_op = getattr(enode, 'op', '')
            if mapped != enode_op:
                return None

        enode_children = getattr(enode, 'children', ())
        if len(pattern.children) != len(enode_children):
            return None

        for pat_child, enc_id in zip(pattern.children, enode_children):
            pass

        return bindings


def match_all_rules(egraph: Any, rules: List[Tuple],
                    max_matches: int = 500) -> List[MatchResult]:
    matcher = ASTPatternMatcher()
    matcher.compile_rules(rules)

    results: List[MatchResult] = []

    for cid, eclass in enumerate(getattr(egraph, 'classes', [])):
        for node in getattr(eclass, 'nodes', []):
            node_op = getattr(node, 'op', '')
            # 只尝试根操作符匹配的规则
            candidate_indices = matcher._op_index.get(node_op, [])
            if not candidate_indices:
                # 模糊操作符名匹配
                for op_key, indices in matcher._op_index.items():
                    if op_key in (node_op,):
                        candidate_indices.extend(indices)

            for pat_idx in candidate_indices:
                if pat_idx >= len(matcher._compiled_patterns):
                    continue
                pattern, _, source = matcher._compiled_patterns[pat_idx]
                bindings = _match_node_against_pattern(
                    egraph, node, pattern, cid, {}
                )
                if bindings is not None:
                    results.append(MatchResult(
                        rule_id=pattern.rule_id,
                        bindings=bindings,
                        matched_eclass_id=cid,
                        rule_source=pattern.rule_source or source,
                    ))
                    if len(results) >= max_matches:
                        return results

    return results


def _match_node_against_pattern(egraph: Any, enode: Any,
                                 pattern: PatternNode, eclass_id: int,
                                 bindings: Dict[str, int]) -> Optional[Dict[str, int]]:
    if pattern.is_var:
        if pattern.var_name in bindings:
            if bindings[pattern.var_name] != eclass_id:
                return None
            return bindings
        bindings[pattern.var_name] = eclass_id
        return bindings

    if pattern.is_const:
        if getattr(enode, 'op', '') == 'const':
            if getattr(enode, 'value', None) == pattern.const_value:
                return bindings
        if eclass_id < len(egraph.classes):
            ec = egraph.classes[eclass_id]
            if getattr(ec, 'is_const', False) and getattr(ec, 'const_value', None) == pattern.const_value:
                return bindings
        return None

    enode_op = getattr(enode, 'op', '')
    op_map = {'add': '+', 'sub': '-', 'mul': '*',
              'and': '&', 'or': '|', 'xor': '^',
              'shl': '<<', 'shr': '>>', 'not': '~'}
    expected_op = op_map.get(pattern.op, pattern.op)
    if enode_op != expected_op:
        return None

    enode_children = getattr(enode, 'children', ())
    if len(pattern.children) != len(enode_children):
        return None

    for pat_child, child_eclass_id in zip(pattern.children, enode_children):
        if child_eclass_id < 0 or child_eclass_id >= len(egraph.classes):
            return None
        child_ec = egraph.classes[child_eclass_id]
        child_nodes = getattr(child_ec, 'nodes', [])
        if not child_nodes:
            if getattr(child_ec, 'is_const', False):
                virt_node = type('_VirtNode', (), {
                    'op': 'const',
                    'value': getattr(child_ec, 'const_value', 0),
                    'children': (),
                })()
                bindings = _match_node_against_pattern(
                    egraph, virt_node, pat_child, child_eclass_id, bindings
                )
                if bindings is None:
                    return None
                continue
            return None
        bindings = _match_node_against_pattern(
            egraph, child_nodes[0], pat_child, child_eclass_id, bindings
        )
        if bindings is None:
            return None

    return bindings
