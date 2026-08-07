"""
LACRA 仿射约束域 — 差分约束图传递闭包, 证明 write_size ≤ alloc_size.

参考: Cousot & Halbwachs, Mine.
"""


import re
from typing import Dict, List, Optional, Set, Tuple


class ConstraintSet:
    """差分约束图 — 传递闭包实现变量间关系推理.

    adj[x][y] = c 表示 x - y ≤ c.
    传递闭包: Floyd-Warshall → 可在常数时间内查询任意变量对的关系.
    容量: 16变量上限, 保证 < 1ms 闭包计算.
    """
    _MAX_VARS = 16
    _MAX_EDGES = 256
    _INF = 1 << 60

    def __init__(self):
        self._adj: Dict[str, Dict[str, int]] = {}
        self._edge_count = 0

    def add_var_bound(self, var: str, lo: Optional[int], hi: Optional[int]):
        if hi is not None:
            self._ensure("_0", var)
            self._adj["_0"][var] = min(self._adj["_0"].get(var, self._INF), hi)
        if lo is not None:
            self._ensure(var, "_0")
            self._adj[var]["_0"] = min(self._adj[var].get("_0", self._INF), -lo)

    def add_diff(self, a: str, b: str, bound: int):
        """a - b ≤ bound."""
        if len(self._adj) >= self._MAX_VARS or self._edge_count >= self._MAX_EDGES:
            return
        self._ensure(a, b)
        if bound < self._adj[a].get(b, self._INF):
            self._adj[a][b] = bound
            self._edge_count += 1

    def add_equality(self, a: str, b: str, delta: int = 0):
        """a = b + delta."""
        self.add_diff(a, b, delta)
        self.add_diff(b, a, -delta)

    def add_guard(self, var: str, op: str, value: int):
        if op == '<':
            self.add_diff(var, "_0", value - 1)
        elif op == '<=':
            self.add_diff(var, "_0", value)
        elif op == '>':
            self.add_diff("_0", var, -value - 1)
        elif op == '>=':
            self.add_diff("_0", var, -value)

    def close(self):
        """Floyd-Warshall 传递闭包 — V≤16保证 <1ms."""
        nodes = list(self._adj.keys())
        for k in nodes:
            if k not in self._adj:
                continue
            for i in nodes:
                if i not in self._adj or k not in self._adj[i]:
                    continue
                ik = self._adj[i][k]
                for j in nodes:
                    if j not in self._adj[k]:
                        continue
                    new = ik + self._adj[k][j]
                    if new < self._adj[i].get(j, self._INF):
                        self._adj[i][j] = new

    def get_bound(self, a: str, b: str) -> Optional[int]:
        """获取 a - b ≤ c 中的最小c, 无路径返回None."""
        self.close()
        if a in self._adj and b in self._adj[a]:
            v = self._adj[a][b]
            return v if v < (self._INF // 2) else None
        return None

    def can_prove_leq(self, x: str, y: str, slack: int = 0) -> Optional[bool]:
        """求证 x ≤ y + slack, 即 x - y ≤ slack."""
        bound = self.get_bound(x, y)
        if bound is not None:
            return bound <= slack
        # 检查反方向: 是否必然违反
        rev = self.get_bound(y, x)
        if rev is not None and rev < -slack:
            return False
        return None

    def _ensure(self, a: str, b: str):
        if a not in self._adj:
            self._adj[a] = {}
        if b not in self._adj:
            self._adj[b] = {}
        if b not in self._adj[a]:
            self._adj[a][b] = self._INF


def extract_affine_from_stmt(stmt: str,
                              vars_of_interest: Set[str] = None,
                              const_map: Dict[str, int] = None) -> List[Tuple[str, str, int]]:
    """提取仿射赋值关系: 返回 [(target, source, delta), ...].

    支持: x=c | x=-c | x=y | x=y+c | x=y-c | x=y+z | x=y-z | x=y+z+c.
    两变量模式通过const_map解析其中一个变量为常量.
    """
    s = stmt.strip()
    cm = const_map or {}

    # 单变量+常量模式优先 (避免被两变量\w+误匹配)
    # x = y + c
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*;?\s*$', s)
    if m:
        return [(m.group(1), m.group(2), int(m.group(3)))]
    # x = y - c
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*\-\s*(\d+)\s*;?\s*$', s)
    if m:
        return [(m.group(1), m.group(2), -int(m.group(3)))]
    # x = c (包括负数)
    m = re.match(r'\s*(\w+)\s*=\s*(-?\d+)\s*;?\s*$', s)
    if m:
        return [(m.group(1), "_0", int(m.group(2)))]
    # x = y
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*;?\s*$', s)
    if m:
        return [(m.group(1), m.group(2), 0)]

    # 多操作数折叠: x = 1 + 2 + var + 16 → x = var + 19
    m = re.match(r'\s*(\w+)\s*=\s*(.+?)\s*;?\s*$', s)
    if m and ('+' in m.group(2) or '-' in m.group(2)):
        target, rhs = m.group(1), m.group(2)
        tokens = re.findall(r'([a-zA-Z_]\w*|\d+|[+\-])', rhs)
        var_name, const_sum, op, multi = "", 0, 1, False
        for tok in tokens:
            if tok == '+': op = 1
            elif tok == '-': op = -1
            elif tok.isdigit() or (tok.startswith('-') and tok[1:].isdigit()):
                const_sum += op * int(tok)
            elif not var_name:
                var_name = tok
            else:
                multi = True; break  # 多变量, 放弃折叠
        if not multi:
            if var_name:
                return [(target, var_name, const_sum)]
            return [(target, "_0", const_sum)]

    # 两变量模式 (cm解析后仍无法折叠时回退)
    # x = y + z + c
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*\+\s*(\d+)\s*;?\s*$', s)
    if m:
        t, a, b, c_val = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if a in cm: return [(t, b, cm[a] + c_val)]
        if b in cm: return [(t, a, cm[b] + c_val)]
        return []
    # x = y + z
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;?\s*$', s)
    if m:
        t, a, b = m.group(1), m.group(2), m.group(3)
        if a in cm: return [(t, b, cm[a])]
        if b in cm: return [(t, a, cm[b])]
        return []
    # x = y - z
    m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*\-\s*(\w+)\s*;?\s*$', s)
    if m:
        t, a, b = m.group(1), m.group(2), m.group(3)
        if b in cm: return [(t, a, -cm[b])]
        return []
    return []




class AffineSafetyProver:
    """仿射安全性证明器 — LACRA核心判定引擎.

    核心思想: 将 alloc 和 write 的 size 表达式都映射到差分约束图中,
    通过传递闭包证明 write_size ≤ alloc_size + slack.

    例: alloc_expr="ie_len+4", write_expr="ie_len"
      → _alloc = ie_len + 4, _write = ie_len + 0
      → _write - _alloc = (ie_len) - (ie_len+4) = -4
      → -4 ≤ slack (任何slack≥0) → True → SAFE → 过滤
    """

    def try_prove_safe(self, alloc_var: str, alloc_expr: str,
                       write_var: str, write_expr: str,
                       stmt_assignments: List[Tuple[str, str, int]],
                       stmt_guards: List[Tuple[str, str, int]],
                       chunk_slack: int = 16,
                       diff_constraints: List[Tuple[str, str, int]] = None) -> Optional[bool]:
        """尝试证明 alloc-write 对安全.

        Args:
          alloc_var: 分配目标变量名 (如 ie_buf)
          alloc_expr: 分配大小表达式 (如 "ie_len + 4")
          write_var: 写入目标变量名 (如 ie_buf)
          write_expr: 写入大小表达式 (如 "ie_len" 或 "copy")
          stmt_assignments: 函数内的赋值关系 [(target, source, delta), ...]
          stmt_guards: 函数内的守卫条件 [(var, op, val), ...]
          chunk_slack: allocator chunk slack

        Returns: True=可证明安全(应过滤), False=可证明溢出, None=不确定.
        """
        if alloc_var != write_var:
            return None  # 不同缓冲区 — 不是堆溢出FP场景

        # 写入大小为0 → 永远安全
        if self._is_zero_size(write_expr):
            return True

        cs = ConstraintSet()

        # 添加所有赋值关系
        for x, y, delta in stmt_assignments:
            cs.add_equality(x, y, delta)

        # 添加守卫条件
        for var, op, val in stmt_guards:
            cs.add_guard(var, op, val)

        # 添加差分约束 (来自三元min等不等式推导)
        if diff_constraints:
            for a, b, bound in diff_constraints:
                cs.add_diff(a, b, bound)

        # 解析 alloc 表达式: _A = base_var + delta
        alloc_rels = self._parse_expr_relations(alloc_expr, "_A")
        for target, source, delta in alloc_rels:
            cs.add_equality(target, source, delta)

        # 解析 write 表达式: _W = base_var + delta
        write_rels = self._parse_expr_relations(write_expr, "_W")
        for target, source, delta in write_rels:
            cs.add_equality(target, source, delta)

        cs.close()

        # 无符号下溢检测: 若写变量可能为负(数学模型), 实际值会回绕至巨大值
# W - _0 ≤ c 且 c < 0 → 可能是uint下溢 → 不能证明安全
        w_bound = cs.get_bound("_W", "_0")
        if w_bound is not None and w_bound < 0:
            return None

        # 核心求证: _W - _A ≤ slack
        result = cs.can_prove_leq("_W", "_A", chunk_slack)
        if result is True:
            return True
        if result is False:
            return False

        return None

    @staticmethod
    def _is_zero_size(expr: str) -> bool:
        import re
        e = expr.strip()
        return (e == '0' or bool(re.match(r'^0\s*\*\s*\d+$', e))
                or bool(re.match(r'^\d+\s*\*\s*0$', e)))

    @staticmethod
    def _parse_expr_relations(expr: str, target: str = "_A") -> List[Tuple[str, str, int]]:
        """解析表达式为差分约束: target = base_var + delta.

        "ie_len + 4" → [('_A', 'ie_len', 4)]
        "ie_len"     → [('_W', 'ie_len', 0)]
        "copy"       → [('_W', 'copy', 0)]
        """
        import re
        expr = expr.strip()
        if re.match(r'^[a-zA-Z_]\w*$', expr):
            return [(target, expr, 0)]
        m = re.match(r'^(\w+)\s*\+\s*(\d+)$', expr)
        if m:
            return [(target, m.group(1), int(m.group(2)))]
        m = re.match(r'^(\w+)\s*\-\s*(\d+)$', expr)
        if m:
            return [(target, m.group(1), -int(m.group(2)))]
        # 结构体成员: skb->len → _A = skb_dot_len + 0
        m = re.match(r'^(\w+)->(\w+)$', expr)
        if m:
            return [(target, f"{m.group(1)}_dot_{m.group(2)}", 0)]
        return []



__all__ = [
    'ConstraintSet', 'extract_affine_from_stmt', 'AffineSafetyProver',
]
