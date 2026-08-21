"""
堆大小差异约束图 — Floyd-Warshall 传递闭包推断跨变量的大小关系.

理论来源:
  Difference Bound Matrices (DBM) for abstract interpretation —
  Miné, "A New Numerical Abstract Domain Based on Difference-Bound Matrices"
  — 证明 O(n³) Floyd-Warshall 可在多项式时间内计算所有变量间的
  上界传递闭包.

在堆溢出FP削减中的作用:
  现有分析只能检测 malloc(N) + write(offset>N) 的直接溢出.
  但许多安全模式通过间接约束保证安全:
    - n = read_int(); if (n > 100) exit(); buf = malloc(n*4);
    - len = strlen(src); buf = malloc(len+1);
    - sz = sizeof(T) * count;  buf = malloc(sz);
  这些模式中, 分配大小与写入大小的关系是间接的——
  差异约束图通过传递闭包发现隐藏的 size(X) <= size(Y) 关系.

设计决策:
  - 不使用完整 DBM (O(n²) 存储), 而使用邻接表表示稀疏约束
  - Floyd-Warshall 只在构建完成后执行一次, 不在每次查询时计算
  - 变量名规范化: 去除指针/数组下标后缀, 统一为 base_var
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re


@dataclass
class SizeConstraint:
    """变量间的大小约束: var_a + delta >= var_b (即 var_b <= var_a + delta)."""
    var_a: str       # 源变量
    var_b: str       # 目标变量
    delta: int = 0   # var_b <= var_a + delta
    line: int = 0
    kind: str = ""   # assign|guard|arith|calloc_nmemb|sizeof


class HeapSizeConstraintGraph:
    """堆大小差异约束图.

    节点 = 变量名 (规范化后)
    边 = SizeConstraint (var_a → var_b with delta)

    关键操作:
      add_constraint: 添加一条约束
      build_closure: Floyd-Warshall 传递闭包
      query_upper_bound(var_a, var_b): var_b 相对 var_a 的上界
      may_overflow(alloc_var, alloc_size, write_var, write_size): 溢出判定
    """

    def __init__(self):
        self._constraints: List[SizeConstraint] = []
        self._nodes: Set[str] = set()
        # 传递闭包: (var_a, var_b) → delta (即 var_b <= var_a + delta)
        self._closure: Dict[Tuple[str, str], int] = {}
        self._built: bool = False

    # 构建

    def add_constraint(self, c: SizeConstraint) -> None:
        """添加约束并标记需重建."""
        self._constraints.append(c)
        self._nodes.add(c.var_a)
        self._nodes.add(c.var_b)
        self._built = False

    def extract_from_source(self, lines: List[str]) -> int:
        """从C源码提取大小约束, 返回提取的约束数."""
        count = 0
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue

            # if (n > K) → 隐含 n <= K 在 else 分支
            gm = re.search(r'if\s*\(\s*(\w+)\s*([><]=?)\s*(\d+)\s*\)', text)
            if gm:
                var, op, val = gm.group(1), gm.group(2), int(gm.group(3))
                if op in ('>', '>='):
                    # var > K on taken → 对 malloc(var) 在 else 分支受限
                    # 不直接添加约束, 交给路径分析
                    pass

            # n = read_int();  → n 无约束
            # len = strlen(s); buf = malloc(len+1); → buf_size <= len + 1
            sm = re.search(r'(\w+)\s*=\s*strlen\s*\(\s*(\w+)\s*\)', text)
            if sm:
                out_var = sm.group(1)
                self.add_constraint(SizeConstraint(
                    var_a=out_var, var_b=sm.group(2), delta=0,
                    line=i, kind='assign'))
                count += 1

            # sz = n * sizeof(T);  → sz <= n * sizeof(T) 且 sz >= n
            mm = re.search(
                r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', text)
            if mm:
                result_var = mm.group(1)
                count_var = mm.group(2)
                self.add_constraint(SizeConstraint(
                    var_a=result_var, var_b=count_var, delta=0,
                    line=i, kind='sizeof'))
                count += 1

            # sz = n + K;  → sz <= n + K
            am = re.search(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)', text)
            if am:
                result_var = am.group(1)
                src_var = am.group(2)
                delta = int(am.group(3))
                self.add_constraint(SizeConstraint(
                    var_a=result_var, var_b=src_var, delta=delta,
                    line=i, kind='arith'))
                count += 1

            # x = y;  简单赋值
            assign_m = re.search(r'(\w+)\s*=\s*(\w+)\s*;', text)
            if assign_m:
                lhs, rhs = assign_m.group(1), assign_m.group(2)
                if lhs not in _NON_VAR and rhs not in _NON_VAR:
                    self.add_constraint(SizeConstraint(
                        var_a=lhs, var_b=rhs, delta=0,
                        line=i, kind='assign'))
                    count += 1

        return count

    def build_closure(self) -> int:
        """Floyd-Warshall 传递闭包. 返回发现的传递约束数."""
        if self._built:
            return len(self._closure)

        # 初始化: 每个变量到自身 delta=0
        dist: Dict[Tuple[str, str], int] = {}
        for n in self._nodes:
            dist[(n, n)] = 0

        # 直接边
        for c in self._constraints:
            key = (c.var_a, c.var_b)
            # 保留最紧约束 (最小 delta)
            if key not in dist or c.delta < dist[key]:
                dist[key] = c.delta

        # Floyd-Warshall: dist[a][c] = min(dist[a][c], dist[a][b] + dist[b][c])
        nodes = sorted(self._nodes)
        changed = True
        iterations = 0
        while changed and iterations < len(nodes):
            changed = False
            iterations += 1
            for k in nodes:
                for i in nodes:
                    ik = dist.get((i, k))
                    if ik is None: continue
                    for j in nodes:
                        kj = dist.get((k, j))
                        if kj is None: continue
                        new_delta = ik + kj
                        ij_key = (i, j)
                        if ij_key not in dist or new_delta < dist[ij_key]:
                            dist[ij_key] = new_delta
                            changed = True

        self._closure = dist
        self._built = True
        return len(self._closure) - len(self._nodes)  # 减去自环

    # 查询

    def query_upper_bound(self, var_a: str, var_b: str) -> Optional[int]:
        """查询 var_b <= var_a + delta 中的 delta.
        返回 None 表示无已知约束.
        """
        if not self._built:
            self.build_closure()
        return self._closure.get((var_a, var_b))

    def may_overflow(self, alloc_var: str, alloc_size: int,
                     write_size: int, write_var: str = "") -> bool:
        """检查是否可能溢出: write_size > alloc_size 但约束图可能排除。

        True 表示溢出可能 (约束未排除), False 表示约束可证安全。
        """
        if not self._built:
            self.build_closure()

        # 直接比较: write_size > alloc_size → 可能溢出
        if write_size <= alloc_size:
            return False

        # 约束检查: 若 write_var <= alloc_var + delta 且 delta < 0,
        # 则 write_size <= alloc_size + delta, 可能排除溢出
        if write_var:
            delta = self._closure.get((alloc_var, write_var))
            if delta is not None and write_size <= alloc_size + delta:
                return False  # 约束保证安全

        # 检查 alloc_var 是否有上界约束 (如 alloc_var <= some_constant)
        for (a, b), d in self._closure.items():
            if b == alloc_var and a != alloc_var and d < alloc_size:
                # alloc_var <= a + d, 其中 d < alloc_size
                # 若 a 本身也有上界, 可进一步推断
                pass

        return True  # 无法排除

    def get_related_vars(self, var: str) -> List[Tuple[str, int]]:
        """获取与 var 有约束关系的所有变量及delta."""
        if not self._built:
            self.build_closure()
        result = []
        for (a, b), d in self._closure.items():
            if a == var and a != b:
                result.append((b, d))
        return result

    def clear(self) -> None:
        self._constraints.clear()
        self._nodes.clear()
        self._closure.clear()
        self._built = False


_NON_VAR = frozenset({
    'if', 'else', 'while', 'for', 'return', 'int', 'char', 'void', 'long',
    'short', 'float', 'double', 'size_t', 'unsigned', 'signed', 'static',
    'const', 'sizeof', 'NULL', 'nullptr', 'malloc', 'calloc', 'realloc',
    'free', 'alloca', 'printf', 'main', 'include', 'struct', 'typedef',
    'switch', 'case', 'default', 'goto', 'break', 'continue', 'exit',
    'puts', 'strlen', 'memset', 'memcpy', 'strcmp', 'strncmp', 'strcat',
    'strcpy', 'sprintf', 'strncpy', 'snprintf', 'gets', 'scanf', 'read',
    'fgets', 'recv', 'atoi', 'exit',
})

__all__ = ['HeapSizeConstraintGraph', 'SizeConstraint']
