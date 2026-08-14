"""
仿射关系域: 以并查集等价类维护两两线性关系 x = k*y + c (k∈ℕ₀, c∈ℤ)。
当分配与写入大小区间均为 TOP 时, 用于证明溢出或安全。
"""


from typing import Dict, Optional, Tuple


class AffineRelation:
    """两两仿射关系: x = coeff * base + offset。

    规范形式: 等价类中的每个变量都表示为相对类代表元 (base) 的关系, 常量变量 base=None 且 coeff=0。
    """

    __slots__ = ('base', 'coeff', 'offset')

    def __init__(self, base: Optional[str] = None,
                 coeff: int = 1, offset: int = 0):
        self.base = base
        self.coeff = coeff
        self.offset = offset

    @property
    def is_ground(self) -> bool:
        return self.base is None

    def __repr__(self) -> str:
        if self.is_ground:
            return f'[{self.offset}]'
        parts = []
        if self.coeff != 1:
            parts.append(f'{self.coeff}*{self.base}')
        else:
            parts.append(self.base)
        if self.offset > 0:
            parts.append(f'+{self.offset}')
        elif self.offset < 0:
            parts.append(f'{self.offset}')
        return ''.join(parts) if parts else '0'


class AffineDomain:
    """前向仿射关系抽象域。

    维护程序点处全部活跃堆大小变量的 variable → AffineRelation 映射, 用带路径压缩的并查集解析等价类。
    单条指令复杂度 O(n·α(n)) (α 为反阿克曼函数)。
    """

    def __init__(self):
        self._rels: Dict[str, AffineRelation] = {}
        self._parent: Dict[str, str] = {}
        self._ground: Dict[str, int] = {}

    def copy(self) -> 'AffineDomain':
        """深拷贝, 用于分支点处的路径分叉。"""
        d = AffineDomain()
        d._rels = {k: AffineRelation(v.base, v.coeff, v.offset)
                   for k, v in self._rels.items()}
        d._parent = dict(self._parent)
        d._ground = dict(self._ground)
        return d

    # 赋值操作 ───────────────────────────────────────────────────

    def assign_constant(self, var: str, value: int) -> None:
        """var = constant: 将等价类固定为常量。"""
        rep = self._find(var)
        self._rels[rep] = AffineRelation(offset=value)
        self._ground[rep] = value

    def assign_alias(self, lhs: str, rhs: str) -> None:
        """lhs = rhs (系数 1, 偏移 0)。"""
        rhs_rep = self._find(rhs) if rhs in self._parent else rhs
        self._rels.pop(lhs, None)
        self._parent.pop(lhs, None)
        self._ground.pop(lhs, None)
        if rhs in self._rels:
            self._union(lhs, rhs_rep)
            self._rels[lhs] = AffineRelation(
                base=rhs_rep, coeff=1, offset=0)
        elif rhs in self._parent:
            self._union(lhs, rhs_rep)
            self._rels[lhs] = AffineRelation(
                base=rhs_rep, coeff=1, offset=0)

    def assign_expr(self, lhs: str, rhs_var: str,
                    coeff: int, offset: int) -> None:
        """lhs = coeff * rhs_var + offset。穿透已有关系组合: 若 rhs = k*base + c, 则 lhs = (coeff*k)*base + (coeff*c + offset)。"""
        self._rels.pop(lhs, None)
        self._parent.pop(lhs, None)
        self._ground.pop(lhs, None)

        if rhs_var not in self._rels:
            # 新变量: 为其建立基变量条目
            self._rels[rhs_var] = AffineRelation(
                base=rhs_var, coeff=1, offset=0)
            self._parent[rhs_var] = rhs_var

        rhs_rel = self._rels[rhs_var]
        if rhs_rel.is_ground:
            # rhs 为常量 → lhs 成为常量
            val = coeff * rhs_rel.offset + offset
            rep = self._find(lhs) if lhs in self._parent else lhs
            self._rels[rep] = AffineRelation(offset=val)
            self._ground[rep] = val
        else:
            rhs_rep = self._find(rhs_var)
            comp_coeff = coeff * rhs_rel.coeff
            comp_offset = coeff * rhs_rel.offset + offset
            self._union(lhs, rhs_rep)
            self._rels[lhs] = AffineRelation(
                base=rhs_rep, coeff=comp_coeff, offset=comp_offset)

    def assign_add(self, lhs: str, rhs_var: str, const: int) -> None:
        """lhs = rhs_var + const。"""
        self.assign_expr(lhs, rhs_var, coeff=1, offset=const)

    def assign_mul(self, lhs: str, rhs_var: str, factor: int) -> None:
        """lhs = rhs_var * factor。"""
        self.assign_expr(lhs, rhs_var, coeff=factor, offset=0)

    def assign_unknown(self, var: str) -> None:
        """var = unknown: 从域中移除, 断开关系。"""
        self._rels.pop(var, None)
        self._parent.pop(var, None)
        self._ground.pop(var, None)

    # 查询操作 ───────────────────────────────────────────────────

    def evaluate(self, var: str) -> Optional[int]:
        """若变量可到达常量值, 求出其具体值。"""
        if var not in self._rels:
            return None
        rel = self._rels[var]
        if rel.is_ground:
            return rel.offset
        base_val = self._ground.get(rel.base) if rel.base else None
        if base_val is not None:
            return rel.coeff * base_val + rel.offset
        # 通过基变量自身的关系求解
        if rel.base and rel.base in self._rels:
            base_rel = self._rels[rel.base]
            if base_rel.is_ground:
                return rel.coeff * base_rel.offset + rel.offset
        return None

    def get_base(self, var: str) -> Optional[str]:
        """返回规范基变量, 若无则返回 None。"""
        rel = self._rels.get(var)
        if rel is None or rel.is_ground:
            return None
        return rel.base

    def get_coeff(self, var: str) -> Optional[int]:
        """返回基变量上的系数。"""
        rel = self._rels.get(var)
        if rel is None:
            return None
        return rel.coeff

    def get_offset(self, var: str) -> Optional[int]:
        """返回加法偏移量。"""
        rel = self._rels.get(var)
        if rel is None:
            return None
        return rel.offset

    def same_base(self, var_a: str, var_b: str) -> bool:
        """检查两个变量是否共享同一规范基变量。"""
        ba = self.get_base(var_a)
        bb = self.get_base(var_b)
        return ba is not None and ba == bb

    # 溢出/安全证明 ──────────────────────────────────────────────

    def can_prove_overflow(self, write_var: str,
                           alloc_var: str) -> Tuple[bool, str]:
        """检查仿射关系能否证明 write_size > alloc_size。返回 (can_prove, reason_string)。"""
        rel_w = self._rels.get(write_var)
        rel_a = self._rels.get(alloc_var)
        if rel_w is None or rel_a is None:
            return False, 'no affine relation'

        # 常量情形: 两者均为常量
        wv = self.evaluate(write_var)
        av = self.evaluate(alloc_var)
        if wv is not None and av is not None:
            if wv > av:
                return True, f'const: {write_var}={wv} > {alloc_var}={av}'
            return False, f'const: {wv} <= {av}'

        # 同基变量情形: write = cw*b + ow, alloc = ca*b + oa
        if self.same_base(write_var, alloc_var):
            base = rel_w.base
            cw, ow = rel_w.coeff, rel_w.offset
            ca, oa = rel_a.coeff, rel_a.offset
            if cw > ca:
                min_diff = (cw + ow) - (ca + oa)
                if min_diff > 0:
                    return True, (
                        f'{write_var}={cw}*{base}+{ow}, '
                        f'{alloc_var}={ca}*{base}+{oa}, '
                        f'min_diff={min_diff}>0')
            elif cw == ca and ow > oa:
                return True, f'same_coeff: offset_diff={ow-oa}>0'

        # 直接偏移: write_var = 1*alloc_var + c 且 c > 0
        if (rel_w.base == alloc_var and rel_w.coeff == 1
                and rel_w.offset > 0):
            return True, f'direct_offset: {write_var}={alloc_var}+{rel_w.offset}'

        return False, 'cannot prove'

    def can_prove_safe(self, write_var: str,
                       alloc_var: str,
                       chunk_slack: int = 0) -> Tuple[bool, str]:
        """检查仿射关系能否证明 write_size <= effective_alloc。chunk_slack 为分配器块对齐的额外字节。"""
        rel_w = self._rels.get(write_var)
        rel_a = self._rels.get(alloc_var)
        if rel_w is None or rel_a is None:
            return False, 'no affine relation'

        wv = self.evaluate(write_var)
        av = self.evaluate(alloc_var)
        if wv is not None and av is not None:
            if wv <= av + chunk_slack:
                return True, (f'const: {write_var}={wv} <= '
                             f'{alloc_var}={av}+{chunk_slack}')
            return False, f'const: {wv} > {av}+{chunk_slack}'

        # 同基变量且 write_coeff <= alloc_coeff
        if self.same_base(write_var, alloc_var):
            base = rel_w.base
            cw, ow = rel_w.coeff, rel_w.offset
            ca, oa = rel_a.coeff, rel_a.offset
            if cw < ca:
                return True, (
                    f'{write_var}={cw}*{base}+{ow} < '
                    f'{alloc_var}={ca}*{base}+{oa}')
            if cw == ca and ow <= oa + chunk_slack:
                return True, (
                    f'same_coeff: write_offset({ow}) <= '
                    f'alloc_offset({oa})+slack({chunk_slack})')

        return False, 'cannot prove'

    # Union-Find 内部实现 ────────────────────────────────────────

    def _find(self, var: str) -> str:
        """查找规范代表元, 带路径压缩。"""
        if var not in self._parent:
            self._parent[var] = var
            return var
        if self._parent[var] != var:
            self._parent[var] = self._find(self._parent[var])
        return self._parent[var]

    def _union(self, a: str, b: str) -> None:
        """合并: 使 b 成为 a 的父节点 (b 为规范代表元)。"""
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            self._parent[ra] = rb

    def __repr__(self) -> str:
        parts = []
        for v, rel in sorted(self._rels.items()):
            parts.append(f'{v}={rel}')
        return '{' + ', '.join(parts) + '}'

    def __contains__(self, var: str) -> bool:
        return var in self._rels


__all__ = ['AffineRelation', 'AffineDomain']
