from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum


class Op(Enum):
    ADD = 'add'
    SUB = 'sub'
    MUL = 'mul'
    AND = 'and'
    OR = 'or'
    XOR = 'xor'
    NOT = 'not'
    NEG = 'neg'
    SHL = 'shl'
    CONST = 'const'
    VAR = 'var'


@dataclass
class ENode:
    op: Op
    children: tuple[int, ...]
    value: int = 0
    var_name: str = ''


@dataclass
class EClass:
    id: int
    nodes: list[ENode] = field(default_factory=list)
    _best_cost: float = float('inf')
    _best_node_idx: int = -1

    def add_node(self, node: ENode) -> bool:
        for existing in self.nodes:
            if (existing.op == node.op
                    and existing.children == node.children
                    and existing.value == node.value):
                return False
        self.nodes.append(node)
        self._best_cost = float('inf')
        return True


# Union-Find (e-class 合并)

class EGraph:

    __slots__ = ('_classes', '_parent', '_hashcons', '_var_ids')

    def __init__(self):
        self._classes: dict[int, EClass] = {}
        self._parent: dict[int, int] = {}
        self._hashcons: dict[tuple, int] = {}
        self._var_ids: dict[str, int] = {}

    def _find(self, cid: int) -> int:
        root = cid
        while root in self._parent and self._parent[root] != root:
            root = self._parent[root]
        cur = cid
        while cur != root and cur in self._parent:
            nxt = self._parent[cur]
            self._parent[cur] = root
            cur = nxt
        return root

    def _union(self, a: int, b: int) -> bool:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return False
        if ra > rb:
            ra, rb = rb, ra
        self._parent[rb] = ra
        canon_ec = self._classes.get(ra)
        merged_ec = self._classes.get(rb)
        if canon_ec is not None and merged_ec is not None:
            for node in merged_ec.nodes:
                canon_ec.add_node(node)
            merged_ec.nodes.clear()
            canon_ec._best_cost = float('inf')
        return True

    def add_node(self, node: ENode) -> int:
        canon_children = tuple(self._find(c) for c in node.children)
        canon_node = ENode(op=node.op, children=canon_children,
                           value=node.value, var_name=node.var_name)
        key = (canon_node.op.value, canon_node.children, canon_node.value)
        existing = self._hashcons.get(key)
        if existing is not None:
            return self._find(existing)

        cid = len(self._classes)
        self._classes[cid] = EClass(id=cid)
        self._classes[cid].add_node(canon_node)
        self._hashcons[key] = cid
        return cid

    def new_var(self, name: str) -> int:
        if name in self._var_ids:
            return self._var_ids[name]
        n = ENode(op=Op.VAR, children=(), var_name=name)
        cid = self.add_node(n)
        self._var_ids[name] = cid
        return cid

    def new_const(self, value: int) -> int:
        n = ENode(op=Op.CONST, children=(), value=value)
        return self.add_node(n)

    def canonicalize(self, node: ENode) -> ENode:
        canon_children = tuple(self._find(c) for c in node.children)
        return ENode(op=node.op, children=canon_children,
                     value=node.value, var_name=node.var_name)

    def rebuild(self) -> int:
        unions = 0
        new_hashcons: dict[tuple, list[int]] = {}
        for cid, eclass in self._classes.items():
            can_cid = self._find(cid)
            for node in eclass.nodes:
                canon = self.canonicalize(node)
                key = (canon.op.value, canon.children, canon.value)
                new_hashcons.setdefault(key, []).append(can_cid)
        self._hashcons.clear()
        for key, cids in new_hashcons.items():
            canonical = min(self._find(c) for c in cids)
            self._hashcons[key] = canonical
            for c in cids:
                if self._union(c, canonical):
                    unions += 1
        return unions

    def _match_pattern(self, pattern: ENode, eclass_id: int) -> list[dict[str, int]]:
        eclass = self._classes.get(self._find(eclass_id))
        if eclass is None:
            return []
        results = []
        for node in eclass.nodes:
            bindings = self._match_node(pattern, node)
            if bindings is not None:
                results.extend(bindings)
        return results

    def _match_node(self, pat: ENode, node: ENode) -> list[dict[str, int]] | None:
        if pat.op == Op.VAR and pat.var_name:
            return [{pat.var_name: self._find(node.children[0])
                    if node.children else -1}]
        if pat.op == Op.CONST:
            if node.op == Op.CONST and node.value == pat.value:
                return [{}]
            return None
        if pat.op != node.op:
            return None
        if len(pat.children) != len(node.children):
            return None
        child_bindings = [{}]
        for pat_child, node_child in zip(pat.children, node.children):
            pc = self._classes.get(self._find(pat_child))
            nc = self._classes.get(self._find(node_child))
            if pc is None or nc is None:
                return None
            new_bindings = []
            for bind in child_bindings:
                for n_node in nc.nodes:
                    for p_node in pc.nodes:
                        sub = self._match_node(p_node, n_node)
                        if sub is not None:
                            for sb in sub:
                                merged = dict(bind)
                                merged.update(sb)
                                new_bindings.append(merged)
            child_bindings = new_bindings
            if not child_bindings:
                return None
        return child_bindings

    def apply_rule(self, lhs: ENode, rhs_builder, cost: float = 1.0) -> int:
        unions = 0
        for cid in list(self._classes.keys()):
            can_cid = self._find(cid)
            matches = self._match_pattern(lhs, can_cid)
            for bind in matches:
                rhs = rhs_builder(self, bind)
                if rhs is not None:
                    if self._union(can_cid, rhs):
                        unions += 1
        return unions

    def extract(self, eclass_id: int, cost_fn=None) -> str:
        return self._extract_impl(eclass_id, cost_fn, set())

    def _extract_impl(self, eclass_id: int, cost_fn, visiting: set[int]) -> str:
        if cost_fn is None:
            cost_fn = _default_cost
        cid = self._find(eclass_id)
        eclass = self._classes.get(cid)
        if eclass is None:
            return '?'
        if eclass._best_cost < float('inf'):
            return self._rebuild_expr(eclass._best_node_idx, eclass)

        if cid in visiting:
            for node in eclass.nodes:
                if all(self._find(c) not in visiting for c in node.children):
                    eclass._best_cost = 1e9
                    eclass._best_node_idx = eclass.nodes.index(node)
                    return self._rebuild_expr(eclass._best_node_idx, eclass)
            return '?'

        visiting.add(cid)
        best_cost = float('inf')
        best_node = None
        for i, node in enumerate(eclass.nodes):
            child_costs = 0.0
            for cc in node.children:
                cc_cid = self._find(cc)
                cc_eclass = self._classes.get(cc_cid)
                if cc_eclass:
                    self._extract_impl(cc_cid, cost_fn, visiting)
                    child_costs += cc_eclass._best_cost
            total = cost_fn(node) + child_costs
            if total < best_cost:
                best_cost = total
                best_node = i
        if best_node is not None:
            eclass._best_cost = best_cost
            eclass._best_node_idx = best_node
        visiting.discard(cid)
        return self._rebuild_expr(best_node, eclass) if best_node is not None else '?'

    def _rebuild_expr(self, node_idx: int, eclass: EClass) -> str:
        if node_idx < 0 or node_idx >= len(eclass.nodes):
            return '?'
        node = eclass.nodes[node_idx]
        if node.op == Op.CONST:
            return f'0x{node.value:x}' if node.value > 9 else str(node.value)
        if node.op == Op.VAR:
            return node.var_name or f'v{node.value}'
        if node.op == Op.NEG:
            c = self.extract(node.children[0]) if node.children else '?'
            return f'(-{c})'
        if node.op == Op.NOT:
            c = self.extract(node.children[0]) if node.children else '?'
            return f'(~{c})'
        children = [self.extract(c) for c in node.children]
        op_map = {Op.ADD: '+', Op.SUB: '-', Op.MUL: '*',
                  Op.AND: '&', Op.OR: '|', Op.XOR: '^', Op.SHL: '<<'}
        op_str = op_map.get(node.op, '?')
        return f'({children[0]} {op_str} {children[1]})' if len(children) >= 2 else children[0]

    def stats(self) -> dict:
        canon = set(self._find(c) for c in self._classes)
        total_nodes = sum(len(ec.nodes) for ec in self._classes.values())
        return {'eclasses': len(canon), 'enodes': total_nodes}


def _default_cost(node: ENode) -> float:
    if node.op in (Op.CONST, Op.VAR):
        return 1.0
    if node.op in (Op.NOT, Op.NEG):
        return 1.5
    if node.op == Op.MUL:
        return 3.0
    return 2.0


def _build_mba_rules() -> list[tuple[str, str]]:
    return [
        ('identity_xor_zero', '_apply_id_xor_zero'),
        ('identity_and_self', '_apply_id_and_self'),
        ('identity_or_self', '_apply_id_or_self'),
        ('identity_xor_self', '_apply_id_xor_self'),
        ('identity_add_zero', '_apply_id_add_zero'),
        ('identity_mul_one', '_apply_id_mul_one'),
        ('identity_mul_zero', '_apply_id_mul_zero'),
        ('identity_sub_self', '_apply_id_sub_self'),
        ('distributive_and_xor', '_apply_distributive_and_xor'),
        ('mba_add_xor_and', '_apply_mba_add_rule'),
        ('mba_sub_xor_and', '_apply_mba_sub_rule'),
        ('mba_xor_to_or_and', '_apply_mba_xor_to_add_sub'),
    ]


class EGraphMBASimplifier:

    __slots__ = ('_max_iter', '_max_nodes', '_rules')

    def __init__(self, max_iterations: int = 10, max_nodes: int = 5000):
        self._max_iter = max_iterations
        self._max_nodes = max_nodes
        self._rules = _build_mba_rules()

    def simplify(self, expr_ast: dict) -> str:
        eg = EGraph()
        root_id = self._ast_to_egraph(eg, expr_ast)

        for iteration in range(self._max_iter):
            unions = 0
            for rule_name, method_name in self._rules:
                method = getattr(self, method_name, None)
                if method is not None:
                    unions += method(eg)
            unions += eg.rebuild()
            if unions == 0:
                break
            total = sum(len(ec.nodes) for ec in eg._classes.values())
            if total > self._max_nodes:
                break

        result = eg.extract(root_id)
        return result

    def _ast_to_egraph(self, eg: EGraph, ast: dict) -> int:
        op_map = {'add': Op.ADD, 'sub': Op.SUB, 'mul': Op.MUL,
                  'and': Op.AND, 'or': Op.OR, 'xor': Op.XOR,
                  'not': Op.NOT, 'neg': Op.NEG, 'shl': Op.SHL}
        op = ast.get('op', '').lower()
        if op == 'const':
            return eg.new_const(int(ast.get('value', 0)))
        if op == 'var':
            return eg.new_var(ast.get('name', 'x'))
        if op in op_map:
            lhs_id = self._ast_to_egraph(eg, ast.get('lhs', {}))
            rhs_id = self._ast_to_egraph(eg, ast.get('rhs', {})) if 'rhs' in ast else lhs_id
            if op in ('not', 'neg'):
                n = ENode(op=op_map[op], children=(lhs_id,))
            else:
                n = ENode(op=op_map[op], children=(lhs_id, rhs_id))
            return eg.add_node(n)
        return eg.new_const(0)

    def _apply_id_xor_zero(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.XOR or len(node.children) != 2:
                    continue
                for i, child_cid in enumerate(node.children):
                    child = eg._classes.get(eg._find(child_cid))
                    if child and any(n.op == Op.CONST and n.value == 0 for n in child.nodes):
                        other = node.children[1 - i]
                        if eg._union(cid, other):
                            u += 1
                        break
        return u

    def _apply_id_and_self(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.AND or len(node.children) != 2:
                    continue
                if eg._find(node.children[0]) == eg._find(node.children[1]):
                    if eg._union(cid, node.children[0]):
                        u += 1
        return u

    def _apply_id_or_self(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.OR or len(node.children) != 2:
                    continue
                if eg._find(node.children[0]) == eg._find(node.children[1]):
                    if eg._union(cid, node.children[0]):
                        u += 1
        return u

    def _apply_id_xor_self(self, eg: EGraph) -> int:
        u = 0
        zero_cid = eg.new_const(0)
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.XOR or len(node.children) != 2:
                    continue
                if eg._find(node.children[0]) == eg._find(node.children[1]):
                    if eg._union(cid, zero_cid):
                        u += 1
        return u

    def _apply_id_add_zero(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.ADD or len(node.children) != 2:
                    continue
                for i, child_cid in enumerate(node.children):
                    child = eg._classes.get(eg._find(child_cid))
                    if child and any(n.op == Op.CONST and n.value == 0 for n in child.nodes):
                        other = node.children[1 - i]
                        if eg._union(cid, other):
                            u += 1
                        break
        return u

    def _apply_id_mul_one(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.MUL or len(node.children) != 2:
                    continue
                for i, child_cid in enumerate(node.children):
                    child = eg._classes.get(eg._find(child_cid))
                    if child and any(n.op == Op.CONST and n.value == 1 for n in child.nodes):
                        other = node.children[1 - i]
                        if eg._union(cid, other):
                            u += 1
                        break
        return u

    def _apply_id_mul_zero(self, eg: EGraph) -> int:
        u = 0
        zero_cid = eg.new_const(0)
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.MUL or len(node.children) != 2:
                    continue
                for child_cid in node.children:
                    child = eg._classes.get(eg._find(child_cid))
                    if child and any(n.op == Op.CONST and n.value == 0 for n in child.nodes):
                        if eg._union(cid, zero_cid):
                            u += 1
                        break
        return u

    def _apply_id_sub_self(self, eg: EGraph) -> int:
        u = 0
        zero_cid = eg.new_const(0)
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.SUB or len(node.children) != 2:
                    continue
                if eg._find(node.children[0]) == eg._find(node.children[1]):
                    if eg._union(cid, zero_cid):
                        u += 1
        return u

    def _apply_distributive_and_xor(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.AND or len(node.children) != 2:
                    continue
                c0, c1 = node.children
                c1_ec = eg._classes.get(eg._find(c1))
                if c1_ec is None:
                    continue
                for inner in list(c1_ec.nodes):
                    if inner.op != Op.XOR or len(inner.children) != 2:
                        continue
                    y_cid, z_cid = inner.children
                    and_xy = eg.add_node(ENode(Op.AND, (c0, y_cid)))
                    and_xz = eg.add_node(ENode(Op.AND, (c0, z_cid)))
                    xor_result = eg.add_node(ENode(Op.XOR, (and_xy, and_xz)))
                    if eg._union(cid, xor_result):
                        u += 1
        return u

    def _apply_mba_xor_to_add_sub(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.XOR or len(node.children) != 2:
                    continue
                c0, c1 = node.children
                or_node = eg.add_node(ENode(Op.OR, (c0, c1)))
                and_node = eg.add_node(ENode(Op.AND, (c0, c1)))
                sub_node = eg.add_node(ENode(Op.SUB, (or_node, and_node)))
                if eg._union(cid, sub_node):
                    u += 1
        return u

    def _apply_mba_sub_rule(self, eg: EGraph) -> int:
        u = 0
        for cid, ec in list(eg._classes.items()):
            for node in list(ec.nodes):
                if node.op != Op.SUB or len(node.children) != 2:
                    continue
                left_cid, right_cid = node.children
                left = eg._classes.get(eg._find(left_cid))
                right = eg._classes.get(eg._find(right_cid))
                if left is None or right is None:
                    continue
                for ln in left.nodes:
                    if ln.op != Op.OR or len(ln.children) != 2:
                        continue
                    o0, o1 = ln.children
                    for rn in right.nodes:
                        if rn.op != Op.AND or len(rn.children) != 2:
                            continue
                        a0, a1 = rn.children
                        if {eg._find(o0), eg._find(o1)} == {eg._find(a0), eg._find(a1)}:
                            xor_node = eg.add_node(ENode(Op.XOR, (o0, o1)))
                            if eg._union(cid, xor_node):
                                u += 1
                            break
        return u

    def _apply_mba_add_rule(self, eg: EGraph) -> int:
        unions = 0
        for cid, eclass in list(eg._classes.items()):
            for node in list(eclass.nodes):
                if node.op != Op.ADD:
                    continue
                if len(node.children) != 2:
                    continue
                left_cid, right_cid = node.children
                left = eg._classes.get(eg._find(left_cid))
                right = eg._classes.get(eg._find(right_cid))
                if left is None or right is None:
                    continue
                for ln in left.nodes:
                    if ln.op != Op.XOR or len(ln.children) != 2:
                        continue
                    x_cid, y_cid = ln.children
                    for rn in right.nodes:
                        if rn.op != Op.MUL or len(rn.children) != 2:
                            continue
                        rc0 = eg._classes.get(eg._find(rn.children[0]))
                        rc1 = eg._classes.get(eg._find(rn.children[1]))
                        if rc0 is None or rc1 is None:
                            continue
                        const2 = any(n2.op == Op.CONST and n2.value == 2 for n2 in rc0.nodes)
                        and_side = rc1 if const2 else rc0
                        const_side = rc0 if const2 else rc1
                        if not const2:
                            if not any(n2.op == Op.CONST and n2.value == 2 for n2 in rc1.nodes):
                                continue
                            const2 = True
                        if not const2:
                            continue
                        for an in and_side.nodes:
                            if an.op != Op.AND or len(an.children) != 2:
                                continue
                            ax_cid, ay_cid = an.children
                            ax_canon = eg._find(ax_cid)
                            ay_canon = eg._find(ay_cid)
                            x_canon = eg._find(x_cid)
                            y_canon = eg._find(y_cid)
                            if {ax_canon, ay_canon} == {x_canon, y_canon}:
                                simplified = ENode(Op.ADD, (x_cid, y_cid))
                                simp_cid = eg.add_node(simplified)
                                if eg._union(cid, simp_cid):
                                    unions += 1
                                break
        return unions

    def stats(self) -> dict:
        return {'rules': len(self._rules), 'max_iter': self._max_iter}


__all__ = ['EGraphMBASimplifier', 'EGraph', 'ENode', 'Op']
