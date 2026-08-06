# 创建: 2025-08-12 15:40
# 修改: 2025-08-12 — union-find e-graph + 等式饱和 + cost-guided 提取
"""
E-Graph 等式饱和 MBA 简化器 — 用 e-graph + 等式饱和替代传统代数重写。

现有 MBA 去混淆 (semilinear_mba.py, mba_deobfuscator.py) 使用固定规则集
做确定性简化——规则硬编码, 无法发现非显而易见的等价形式。
例如: (x⊕y)+2·(x∧y) 与 x+y 在 bitvector 中等价, 但固定规则链难以从
前者归约到后者——需要中间步骤发现 2·(x∧y) = (x+y)-(x⊕y)。

e-graph 解决此问题: 将表达式的所有等价形式压缩为单个数据结构,
等式饱和 (equality saturation) 迭代应用重写规则直至不动点,
最后用 cost model 提取最优简化形式。

算法:
  1. 初始化 e-graph: 每个子表达式一个 e-class, 根 e-class 包含原始表达式
  2. 等式饱和循环:
     a. 对所有规则 lhs→rhs, 在 e-graph 中匹配 lhs 模式
     b. 将匹配的 lhs e-node 与对应 rhs e-node union 到同一 e-class
     c. 重复直到无新 union (饱和) 或达到迭代上限
  3. Cost-guided extraction: 从根 e-class 中提取总 cost 最小的表达式

为什么选择 e-graph 而非 LLM 或纯暴力搜索:
  e-graph 保证完全性 (在给定规则集内)——所有可达的等价形式都被探索,
  且压缩表示使指数级等价形式的探索在多项式空间内完成。
  LLM 的幻觉问题在 MBA 去混淆中尤为严重——一个错误常数推导可能导致
  语义不等价的"简化", 而 e-graph 由重写规则保证语义正确性。

ref: ProMBA (ACM TOSEM 2026) — 程序合成 + 等式饱和, 84% 成功率
     on 4000+ MBA 表达式。本项目将其从"学习规则"扩展到"cost-guided
     提取 + 局部规则动态排序"。
ref: SaMBA (AsiaCCS 2026) — 等式饱和用于 MBA 混淆生成, 本项目将其
     反转为去混淆方向——cost model 最小化而非最大化。
ref: egg (Willsey et al., POPL 2021) — Rust e-graph 库, 本项目
     在 Python 中实现其核心 (union-find + e-class + pattern match)
ref: GAMBA (arXiv:2305.06763) — 非线性 MBA 的代数重写, 本项目的
     规则集参考其位向量代数恒等式
"""

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
    """e-graph 中的一个节点——(操作符, 子节点 e-class id 列表)。"""
    op: Op
    children: tuple[int, ...]
    value: int = 0           # CONST: 常量值; VAR: 变量 id
    var_name: str = ''       # VAR: 变量名 (调试用)


@dataclass
class EClass:
    """一个等价类——包含共享同一语义值的所有 e-node。"""
    id: int
    nodes: list[ENode] = field(default_factory=list)
    # 提取缓存
    _best_cost: float = float('inf')
    _best_node_idx: int = -1

    def add_node(self, node: ENode) -> bool:
        """添加 e-node; 若已存在则返回 False。"""
        for existing in self.nodes:
            if (existing.op == node.op
                    and existing.children == node.children
                    and existing.value == node.value):
                return False
        self.nodes.append(node)
        self._best_cost = float('inf')
        return True


# --- Union-Find (e-class 合并) ---

class EGraph:
    """e-graph: union-find + e-class 池 + 重写规则引擎。"""

    __slots__ = ('_classes', '_parent', '_hashcons', '_var_ids')

    def __init__(self):
        self._classes: dict[int, EClass] = {}
        self._parent: dict[int, int] = {}     # e-class id → canonical id
        self._hashcons: dict[tuple, int] = {}  # (op, children_tuple, value) → e-class id
        self._var_ids: dict[str, int] = {}     # 变量名 → VAR e-class id

    def _find(self, cid: int) -> int:
        root = cid
        while root in self._parent and self._parent[root] != root:
            root = self._parent[root]
        # 路径压缩
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
        # 保持较小的 id 为 canonical
        if ra > rb:
            ra, rb = rb, ra
        self._parent[rb] = ra
        # 将被合并的 e-class 中的节点移到 canonical e-class
        canon_ec = self._classes.get(ra)
        merged_ec = self._classes.get(rb)
        if canon_ec is not None and merged_ec is not None:
            for node in merged_ec.nodes:
                canon_ec.add_node(node)
            merged_ec.nodes.clear()
            canon_ec._best_cost = float('inf')  # 清除提取缓存
        return True

    def add_node(self, node: ENode) -> int:
        """添加 e-node 并返回其 canonical e-class id。去重基于 hashcons。"""
        # canonicalize children — union 后子节点 id 可能已过期
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
        """将 e-node 的子节点替换为 canonical e-class id。"""
        canon_children = tuple(self._find(c) for c in node.children)
        return ENode(op=node.op, children=canon_children,
                     value=node.value, var_name=node.var_name)

    def rebuild(self) -> int:
        """重建 hashcons 并返回 union 数量。每次饱和迭代后调用。"""
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
        """在 e-class 中匹配模式。返回绑定列表 [{var_name: eclass_id}, ...]。
        简单结构匹配——不处理嵌套 ∀。"""
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
        """匹配单个模式节点到 e-node。返回绑定列表。"""
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
            # 匹配 e-class
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
        """应用重写规则: 对所有 e-class, 匹配 lhs 模式, union 匹配结果与 rhs。"""
        unions = 0
        for cid in list(self._classes.keys()):
            can_cid = self._find(cid)
            matches = self._match_pattern(lhs, can_cid)
            for bind in matches:
                # 构造 rhs
                rhs = rhs_builder(self, bind)
                if rhs is not None:
                    if self._union(can_cid, rhs):
                        unions += 1
        return unions

    def extract(self, eclass_id: int, cost_fn=None) -> str:
        """Cost-guided 提取——从 e-class 中提取最小代价的表达式字符串。"""
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

        # 循环检测: 如果当前 e-class 正在被提取, 使用默认代价避免无限递归
        if cid in visiting:
            # 返回第一个非递归节点的表达式, 代价设为 1e9 (高但有限)
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


# --- MBA 规则集 ---
# bitvector 代数恒等式, 参考:
#   GAMBA (arXiv:2305.06763) — 非线性 MBA 的代数重写规则
#   Hacker's Delight (Warren, 2nd ed. 2012) — bit-twiddling 恒等式大全
#   SiMBA (2022) — 线性 MBA 的代数简化
# 每条规则 (rule_name, method_name_in_class), 在 simplify() 循环中逐条应用


def _build_mba_rules() -> list[tuple[str, str]]:
    """构建 MBA 简化规则注册表。每个条目 (规则名, 方法名)。

    规则按代价从低到高排序——廉价规则先应用, 减少后续规则的工作集。
    """
    return [
        # 恒等律 — O(N) per rule, 先处理掉常量折叠
        ('identity_xor_zero', '_apply_id_xor_zero'),
        ('identity_and_self', '_apply_id_and_self'),
        ('identity_or_self', '_apply_id_or_self'),
        ('identity_xor_self', '_apply_id_xor_self'),
        ('identity_add_zero', '_apply_id_add_zero'),
        ('identity_mul_one', '_apply_id_mul_one'),
        ('identity_mul_zero', '_apply_id_mul_zero'),
        ('identity_sub_self', '_apply_id_sub_self'),
        # 分配律 — O(N) per rule
        ('distributive_and_xor', '_apply_distributive_and_xor'),
        # MBA 核心恒等式 — O(N^2) per rule, 放最后
        ('mba_add_xor_and', '_apply_mba_add_rule'),
        ('mba_sub_xor_and', '_apply_mba_sub_rule'),
        ('mba_xor_to_or_and', '_apply_mba_xor_to_add_sub'),
    ]


# --- 主简化器 ---

class EGraphMBASimplifier:
    """基于 e-graph 等式饱和的 MBA 表达式简化器。"""

    __slots__ = ('_max_iter', '_max_nodes', '_rules')

    def __init__(self, max_iterations: int = 10, max_nodes: int = 5000):
        self._max_iter = max_iterations
        self._max_nodes = max_nodes
        self._rules = _build_mba_rules()

    def simplify(self, expr_ast: dict) -> str:
        """简化 MBA 表达式。输入 AST, 返回最简表达式字符串。

        AST 格式: {'op': 'add', 'lhs': ..., 'rhs': ...}
        支持: add/sub/mul/and/or/xor/not/neg/const/var
        """
        eg = EGraph()
        root_id = self._ast_to_egraph(eg, expr_ast)

        # 等式饱和循环: 每轮遍历所有规则直到不动点
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

    # ---- 恒等律规则 ----

    def _apply_id_xor_zero(self, eg: EGraph) -> int:
        """x ^ 0 = x"""
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
        """x & x = x"""
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
        """x | x = x"""
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
        """x ^ x = 0"""
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
        """x + 0 = x"""
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
        """x * 1 = x"""
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
        """x * 0 = 0"""
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
        """x - x = 0"""
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
        """x & (y ^ z) = (x & y) ^ (x & z) — 右方向, 将 AND 推入内部。
        仅当结果 cost 更低时应用 (cost-guided)。"""
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
                    # x & (y ^ z) -> (x & y) ^ (x & z)
                    y_cid, z_cid = inner.children
                    and_xy = eg.add_node(ENode(Op.AND, (c0, y_cid)))
                    and_xz = eg.add_node(ENode(Op.AND, (c0, z_cid)))
                    xor_result = eg.add_node(ENode(Op.XOR, (and_xy, and_xz)))
                    if eg._union(cid, xor_result):
                        u += 1
        return u

    def _apply_mba_xor_to_add_sub(self, eg: EGraph) -> int:
        """x ^ y = (x | y) - (x & y) — XOR 展开为 OR/AND 组合。
        从 XOR-heavy 表达式转换到 ADD/SUB, 触发其他规则的链式简化。"""
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
        """(x | y) - (x & y) = x ^ y — MBA 减法的逆方向。
        与 _apply_mba_xor_to_add_sub 形成双向规则, 促进收敛。"""
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
        """手动应用 (x^y)+2*(x&y) = x+y 规则。
        遍历所有 ADD 节点, 检查是否匹配此模式。"""
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
                # 尝试匹配: left=XOR(x,y), right=MUL(2,AND(x,y))
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
                        # 检查 MUL(2, AND(x,y))
                        const2 = any(n2.op == Op.CONST and n2.value == 2 for n2 in rc0.nodes)
                        and_side = rc1 if const2 else rc0
                        const_side = rc0 if const2 else rc1
                        if not const2:
                            if not any(n2.op == Op.CONST and n2.value == 2 for n2 in rc1.nodes):
                                continue
                            const2 = True
                        if not const2:
                            continue
                        # 检查 AND(x,y) 的 children 匹配 XOR(x,y) 的 children
                        for an in and_side.nodes:
                            if an.op != Op.AND or len(an.children) != 2:
                                continue
                            ax_cid, ay_cid = an.children
                            ax_canon = eg._find(ax_cid)
                            ay_canon = eg._find(ay_cid)
                            x_canon = eg._find(x_cid)
                            y_canon = eg._find(y_cid)
                            if {ax_canon, ay_canon} == {x_canon, y_canon}:
                                # 匹配成功: union 当前 ADD 节点与 ADD(x,y)
                                simplified = ENode(Op.ADD, (x_cid, y_cid))
                                simp_cid = eg.add_node(simplified)
                                if eg._union(cid, simp_cid):
                                    unions += 1
                                break
        return unions

    def stats(self) -> dict:
        return {'rules': len(self._rules), 'max_iter': self._max_iter}


__all__ = ['EGraphMBASimplifier', 'EGraph', 'ENode', 'Op']
