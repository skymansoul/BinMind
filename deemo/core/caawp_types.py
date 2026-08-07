"""
CAAWP数据类型 — 上下文敏感仿射域状态与证明结果.

Context-sensitive Affine Allocation-Write Prover的核心数据结构:
  CallContext: 调用点上下文标识(call-site链)
  AffineSnapshot: 仿射域在某程序点的快照(含上下文标签)
  ProofResult: 安全性证明结果(safe/overflow/inconclusive)

与现有cj_bvf_types.SymbolicExpr的区别:
  SymbolicExpr是单变量线性表达式(coef*var+const),
  AffineSnapshot是完整仿射状态(多变量+系数矩阵+常数偏移),
  且绑定调用点上下文以区分不同调用路径下的值流关系.

理论基础:
  Karr 1976 — 仿射关系域, O(n*alpha(n)) per program point
  Müller-Olm & Seidl POPL 2004 — 最弱前置条件仿射分析
  Mine 2006 — 弱关系域在安全验证中的应用
  SAIL USENIX'23 — 需求驱动稀疏值流, 上下文区分
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CallContext:
    """调用点上下文 — 函数调用链的指纹.

    通过call-site地址链区分不同调用上下文:
      main→foo@0x401000→bar@0x401050 区别于
      main→foo@0x401000→bar@0x401080

    depth限制防止递归爆炸(CAAWP_MAX_CONTEXT_DEPTH=4).
    """
    call_chain: Tuple[str, ...] = field(default_factory=tuple)
    depth: int = 0

    def extend(self, call_site: str) -> 'CallContext':
        if self.depth >= 4:
            return self
        return CallContext(
            call_chain=self.call_chain + (call_site,),
            depth=self.depth + 1)

    def key(self) -> str:
        return '>'.join(self.call_chain) if self.call_chain else 'root'

    def is_root(self) -> bool:
        return len(self.call_chain) == 0


@dataclass
class AffineSnapshot:
    """仿射域快照 — 多变量线性关系矩阵.

    存储var→(coefs, const)映射:
      "n" → {("n", 1.0)}, const=0       表示n=n
      "buf_size" → {("n", 2.0)}, const=8 表示buf_size=2*n+8

    上下文标签ctx区分不同call-site下的value flow.
    """
    ctx: CallContext = field(default_factory=CallContext)
    var_relations: Dict[str, Tuple[Dict[str, float], float]] = field(default_factory=dict)
    tainted_vars: Set[str] = field(default_factory=set)
    alloc_sites: Dict[str, Dict] = field(default_factory=dict)
    write_sites: Dict[str, Dict] = field(default_factory=dict)

    def get_expr(self, var: str) -> Optional[Tuple[Dict[str, float], float]]:
        return self.var_relations.get(var)

    def is_tainted(self, var: str) -> bool:
        return var in self.tainted_vars

    def can_prove_safe(
        self,
        alloc_var: str,
        write_var: str,
        chunk_slack: int = 0,
        offset: int = 0,
    ) -> Tuple[bool, str]:
        alloc_expr = self.get_expr(alloc_var)
        write_expr = self.get_expr(write_var)
        if alloc_expr is None or write_expr is None:
            return False, "expression not found"

        alloc_coefs, alloc_const = alloc_expr
        write_coefs, write_const = write_expr
        effective_write_const = write_const + offset

        if self.is_tainted(write_var) and not self.is_tainted(alloc_var):
            return False, "write tainted, alloc not — cannot prove safe"

        shared = set(alloc_coefs.keys()) & set(write_coefs.keys())
        if not shared:
            if write_var in self.tainted_vars:
                return False, "no shared var, write tainted"
            # 两者都有变量但无共享 — 无法证明安全
            if alloc_coefs and write_coefs:
                return False, (
                    f"no shared vars: alloc={list(alloc_coefs)}, "
                    f"write={list(write_coefs)}")
            # 只有一方有变量或都无变量, 做常量比较
            ac = alloc_const + chunk_slack
            wc = effective_write_const
            # copy_size=-1是"大小未知"的哨兵值, 不等价于常量-1
            # 将-1(和所有负值write_const)视为无法证明安全
            if wc < -0.5:
                return False, "write_size sentinel (-1=unbounded) cannot prove safe"
            # 当alloc常量和write常量都为0且无实质信息时,
            # 无法证明安全 — 避免将"未知"误判为"安全"
            if abs(ac) < 1e-9 and abs(wc) < 1e-9:
                return False, "const: both zero — cannot prove safe"
            if wc <= ac + 1e-9:
                return True, f"const: write({wc}) <= alloc({ac})"
            return False, "no shared var, const mismatch"

        for v in shared:
            ac = alloc_coefs.get(v, 0)
            wc = write_coefs.get(v, 0)
            if wc > ac + 1e-9:
                return False, f"coef overflow: write[{v}]={wc} > alloc[{v}]={ac}"

        non_shared_write = sum(
            c for v, c in write_coefs.items()
            if v not in shared and c > 0)
        if non_shared_write > 0:
            return False, "write has unbounded non-shared variable"

        # 系数已满足 write_coef <= alloc_coef, 最终安全性取决于常数
        # 即使有系数盈余(alloc_coef > write_coef), 无变量下界也无法保证盈余能吸收常数差
        if effective_write_const <= alloc_const + chunk_slack + 1e-9:
            return True, (
                f"subset: shared={list(shared)}, "
                f"write_const({effective_write_const}) <= "
                f"alloc_const+slack({alloc_const}+{chunk_slack})")

        return False, "coefficient subset check failed"

    def can_prove_overflow(
        self,
        alloc_var: str,
        write_var: str,
        offset: int = 0,
    ) -> Tuple[bool, str]:
        alloc_expr = self.get_expr(alloc_var)
        write_expr = self.get_expr(write_var)
        if alloc_expr is None or write_expr is None:
            return False, "expression not found"

        alloc_coefs, alloc_const = alloc_expr
        write_coefs, write_const = write_expr
        effective_write_const = write_const + offset

        if self.is_tainted(write_var) and not self.is_tainted(alloc_var):
            ac = alloc_const
            return True, f"tainted write into fixed alloc({ac})"

        shared = set(alloc_coefs.keys()) & set(write_coefs.keys())
        for v in shared:
            ac = alloc_coefs.get(v, 0)
            wc = write_coefs.get(v, 0)
            if wc > ac + 1e-9:
                return True, (
                    f"overflow: write_coef[{v}]={wc} > "
                    f"alloc_coef[{v}]={ac}")

        if not shared:
            if effective_write_const > alloc_const + 1e-9 and not alloc_coefs:
                return True, (
                    f"overflow: const write({effective_write_const}) > "
                    f"alloc({alloc_const})")

        all_equal = all(
            alloc_coefs.get(v, 0) == write_coefs.get(v, 0)
            for v in shared)
        if all_equal and shared:
            if effective_write_const > alloc_const + 1e-9:
                return True, (
                    f"overflow: equal coefs but "
                    f"write_const+off({effective_write_const}) > "
                    f"alloc_const({alloc_const})")

        return False, "no overflow proven"


@dataclass
class ProofResult:
    """CAAWP安全性证明结果."""
    proven_safe: bool = False
    proven_overflow: bool = False
    reason: str = ""
    ctx_key: str = ""
    alloc_var: str = ""
    write_var: str = ""
    chunk_slack: int = 0
    certificate: str = ""
    proof_chain: List[str] = field(default_factory=list)


__all__ = [
    'CallContext', 'AffineSnapshot', 'ProofResult',
]
