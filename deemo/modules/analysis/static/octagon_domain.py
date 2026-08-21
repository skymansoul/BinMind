# 八边形抽象域 (Octagon Abstract Domain)
#
# 关系型抽象域: 维护 ±x ± y ≤ c 形式的二变量约束,
# 在 fixpoint 计算中内建变量间等价/支配关系.
# 相比非关系型区间域, 可直接推导 malloc(x); memcpy(p,src,x) 中
# write_size = alloc_size 的等价关系, 无需事后补救.
#
# 理论依据: Miné, SAS 2006 "The Octagon Abstract Domain"
# 稀疏实现: 仅追踪堆分析相关变量 (分配大小/写入大小参数寄存器),
# 避免全变量 O(n²) 开销.
#
# 集成策略: 作为 finalize 管线的 Stage 3.5 运行,
# 在结构推断之后、FP filter 之前,
# 消除区间重叠类的 heap_overflow_possible 告警.
#

from typing import Dict, List, Optional, Tuple
import math

_INF = math.inf


class _DBM:
    """差界矩阵 (Difference Bound Matrix) 的稀疏实现.

    维护 n×n 矩阵, 元素 m[i][j] = c_i - c_j 的上界.
    对角线 m[i][i] = 0, 不存在的约束记为 +∞.
    仅分配/写入相关的变量被纳入矩阵, 其余变量不占维度.
    """

    __slots__ = ("vars", "matrix", "_var_idx")

    def __init__(self):
        self.vars: List[str] = []
        self._var_idx: Dict[str, int] = {}
        self.matrix: List[List[float]] = []

    def add_var(self, name: str) -> int:
        if name in self._var_idx:
            return self._var_idx[name]
        idx = len(self.vars)
        self.vars.append(name)
        self._var_idx[name] = idx
        for row in self.matrix:
            row.append(_INF)
        self.matrix.append([_INF] * (idx + 1))
        self.matrix[idx][idx] = 0.0
        return idx

    def get(self, i: str, j: str) -> float:
        """返回 c_i - c_j 的上界."""
        idx_i = self._var_idx.get(i)
        idx_j = self._var_idx.get(j)
        if idx_i is None or idx_j is None:
            return _INF
        return self.matrix[idx_i][idx_j]

    def set(self, i: str, j: str, val: float):
        """设置 c_i - c_j ≤ val."""
        idx_i = self.add_var(i)
        idx_j = self.add_var(j)
        self.matrix[idx_i][idx_j] = val

    def close(self):
        """Floyd-Warshall 闭包计算, 使所有约束传播完毕."""
        n = len(self.vars)
        for k in range(n):
            mk = self.matrix[k]
            for i in range(n):
                mik = self.matrix[i][k]
                if mik == _INF:
                    continue
                mi = self.matrix[i]
                for j in range(n):
                    kj = mk[j]
                    if kj == _INF:
                        continue
                    nv = mik + kj
                    if nv < mi[j]:
                        mi[j] = nv

    def copy(self) -> "_DBM":
        c = _DBM()
        c.vars = list(self.vars)
        c._var_idx = dict(self._var_idx)
        c.matrix = [list(row) for row in self.matrix]
        return c

    def join(self, other: "_DBM") -> "_DBM":
        """合并两个 DBM: 取每个元素的最大值 (并集 semantics)."""
        all_vars = set(self.vars) | set(other.vars)
        result = _DBM()
        for v in all_vars:
            result.add_var(v)
        for v1 in all_vars:
            for v2 in all_vars:
                s = self.get(v1, v2)
                o = other.get(v1, v2)
                result.set(v1, v2, max(s, o))
        return result

    def is_empty(self) -> bool:
        """检查是否存在自矛盾 (m[i][i] < 0)."""
        for i in range(len(self.vars)):
            if self.matrix[i][i] < 0:
                return True
        return False


class OctagonDomain:
    """八边形抽象域: 稀疏关系型约束管理器.

    在堆溢出分析的上下文中, 追踪以下变量关系:
    - 分配大小参数 (如 malloc 的 arg0 寄存器)
    - 写入大小参数 (如 memcpy 的 arg2 寄存器)
    - 常量赋值 (如 mov ecx, 64)
    - 算术衍生 (如 lea r8, [rcx*4] → r8 = rcx * 4)
    """

    def __init__(self):
        self._dbm = _DBM()
        self._const: Dict[str, int] = {}
        self._tracked: set = set()

    def track(self, var: str):
        """标记需要追踪的变量."""
        self._tracked.add(var)
        self._dbm.add_var(var)

    def set_constant(self, var: str, val: int):
        """记录变量为常量: var = val.

        用 zero 虚拟变量表示 0, 通过 var - zero ≤ val 和
        zero - var ≤ -val 双向约束锁定 var = val.
        """
        self._const[var] = val
        self._dbm.add_var("zero")
        self._dbm.add_var(var)
        self._dbm.set(var, "zero", float(val))
        self._dbm.set("zero", var, -float(val))

    def set_equality(self, var1: str, var2: str):
        """记录两个变量相等: var1 = var2."""
        self._dbm.set(var1, var2, 0.0)
        self._dbm.set(var2, var1, 0.0)

    def set_diff(self, var1: str, var2: str, delta: int):
        """记录 var1 - var2 = delta."""
        self._dbm.set(var1, var2, float(delta))
        self._dbm.set(var2, var1, -float(delta))

    def set_le(self, var1: str, var2: str):
        """记录 var1 ≤ var2."""
        self._dbm.set(var1, var2, 0.0)

    def finalize_constraints(self):
        """闭包计算, 传播所有约束."""
        self._dbm.close()

    def query_le(self, var1: str, var2: str) -> Optional[bool]:
        """查询 var1 ≤ var2 是否成立.

        返回 True=成立, False=不成立, None=未知.
        """
        if var1 == var2:
            return True
        if var1 in self._const and var2 in self._const:
            return self._const[var1] <= self._const[var2]
        ub = self._dbm.get(var1, var2)
        if ub == _INF:
            return None
        return ub <= 0.0

    def query_eq(self, var1: str, var2: str) -> Optional[bool]:
        """查询 var1 == var2 是否成立."""
        if var1 == var2:
            return True
        if var1 in self._const and var2 in self._const:
            return self._const[var1] == self._const[var2]
        ub = self._dbm.get(var1, var2)
        lb = self._dbm.get(var2, var1)
        if ub == 0.0 and lb == 0.0:
            return True
        if ub == _INF or lb == _INF:
            return None
        if ub < 0 or lb < 0:
            return False
        return None

    def query_diff(self, var1: str, var2: str) -> Optional[int]:
        """查询 var1 - var2 的精确值, 若可确定."""
        if var1 in self._const and var2 in self._const:
            return self._const[var1] - self._const[var2]
        ub = self._dbm.get(var1, var2)
        lb = self._dbm.get(var2, var1)
        if ub == _INF or lb == _INF:
            return None
        if ub == -lb and ub == int(ub):
            return int(ub)
        return None

    def copy(self) -> "OctagonDomain":
        c = OctagonDomain()
        c._dbm = self._dbm.copy()
        c._const = dict(self._const)
        c._tracked = set(self._tracked)
        return c

    def join(self, other: "OctagonDomain") -> "OctagonDomain":
        result = OctagonDomain()
        result._dbm = self._dbm.join(other._dbm)
        result._const = {}
        for k in set(self._const) & set(other._const):
            if self._const[k] == other._const[k]:
                result._const[k] = self._const[k]
        result._tracked = self._tracked | other._tracked
        return result


__all__ = ["OctagonDomain"]
