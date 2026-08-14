"""
CAAWP 数据类型: 上下文敏感仿射域状态与证明结果。
核心结构: CallContext 调用点上下文 (call-site 链), AffineSnapshot 仿射域快照 (多变量线性关系 + 上下文标签), ProofResult 证明结果。
与 cj_bvf_types.SymbolicExpr (单变量线性表达式) 不同, AffineSnapshot 为完整仿射状态, 且绑定调用点上下文以区分不同调用路径的值流。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CallContext:
    """调用点上下文 — 函数调用链的指纹。

    以 call-site 地址链区分不同调用上下文 (如 main→foo@0x401000→bar@0x401050 与 main→foo@0x401000→bar@0x401080), depth 限制防止递归爆炸。
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
    """仿射域快照 — 多变量线性关系矩阵。

    存储 var→(coefs, const) 映射, 如 "buf_size" → {("n", 2.0)}, const=8 表示 buf_size=2*n+8; 上下文标签 ctx 区分不同 call-site 下的值流。
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
            # 无共享变量时: 双方均有变量则无法证明, 否则做常量比较
            if alloc_coefs and write_coefs:
                return False, (
                    f"no shared vars: alloc={list(alloc_coefs)}, "
                    f"write={list(write_coefs)}")
            ac = alloc_const + chunk_slack
            wc = effective_write_const
            # copy_size=-1 为"大小未知"哨兵值, 负 write_const 视为无法证明安全
            if wc < -0.5:
                return False, "write_size sentinel (-1=unbounded) cannot prove safe"
            # 常量均为 0 且无实质信息时无法证明安全, 避免将"未知"误判为"安全"
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

        # 系数已满足 write_coef <= alloc_coef, 最终安全性取决于常数; 无变量下界时系数盈余无法保证吸收常数差
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
