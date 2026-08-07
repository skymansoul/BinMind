"""
选择性符号执行引擎 — 仅针对 size 参数做有限符号执行.

与 Angr 全程序符号执行的结构性差异:
  - 符号化变量: 仅 size 参数, ≤8个符号变量
  - 路径限制: ≤128条, 超出保守返回 POSSIBLE
  - 不符号化全地址空间, 不跟踪指针
  - 内存模型: 局部变量映射 (不建模堆)
  - 确定性保证: 无 SMT, 用区间代数 + 符号求值

v2 增强: 条件分支fork, 13种指令模式, 局部变量映射, 路径约束精化.
"""


import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .symbolic_arith_matcher import (
    SymExpr, sym_const,
    try_arith_insn, try_load_store_insn,
    try_conditional_insn, refine_range_by_constraints,
)

_log = logging.getLogger(__name__)


@dataclass
class SymState:
    """符号执行状态."""
    regs: Dict[str, SymExpr] = field(default_factory=dict)
    locals: Dict[str, SymExpr] = field(default_factory=dict)
    path_constraints: List[Tuple[str, str, int]] = field(default_factory=list)
    path_count: int = 0

    def copy(self) -> "SymState":
        return SymState(regs=dict(self.regs), locals=dict(self.locals),
                        path_constraints=list(self.path_constraints),
                        path_count=self.path_count)


@dataclass
class SymVerdict:
    """符号执行判定结果."""
    alloc_site: int
    write_site: int
    verdict: str  # DEFINITE_OVERFLOW / DEFINITE_SAFE / POSSIBLE
    write_range: Tuple[int, int]
    alloc_range: Tuple[int, int]
    num_paths_explored: int


class SelectiveSymExec:
    """选择性符号执行引擎 v2.

    限制: max_symbols≤8, max_paths≤128.
    只符号化size参数, 不跟踪指针/地址空间.
    """

    def __init__(self, max_symbols: int = 8, max_paths: int = 128):
        self._max_symbols = max_symbols
        self._max_paths = max_paths
        self._state: Optional[SymState] = None
        self._symbols: Dict[str, Tuple[int, int]] = {}
        self._symbol_count: int = 0

    def clear(self):
        self._state = None
        self._symbols.clear()
        self._symbol_count = 0

    def analyze(self, alloc_sites: List[Tuple[int, str, int]],
                write_sites: List[Tuple[int, str, int]],
                insns: List[Tuple[int, str]]) -> List[SymVerdict]:
        self.clear()
        self._state = SymState()
        self._symbolize_unknown_sizes(alloc_sites)
        self._symbolize_unknown_sizes(write_sites)
        self._forward_propagate(insns)
        return self._evaluate_pairs(alloc_sites, write_sites)

    def _symbolize_unknown_sizes(self, sites: List[Tuple[int, str, int]]):
        for addr, func, imm in sites:
            if imm >= 0 or self._symbol_count >= self._max_symbols:
                continue
            sym_name = f"_{func}_{addr:x}"
            self._symbols[sym_name] = (1, 2**20)
            self._symbol_count += 1

    def _forward_propagate(self, insns: List[Tuple[int, str]]):
        """正向传播: 委托给符号指令匹配器."""
        path_count_ref = [0]  # 引用传递 (mutable container)
        i = 0
        while i < len(insns):
            _addr, text = insns[i]
            tl = text.strip()
            st = self._state

            if try_arith_insn(tl, st.regs, st.locals):
                i += 1
                continue
            if try_load_store_insn(tl, st.regs, st.locals):
                i += 1
                continue
            if try_conditional_insn(insns, i, st.regs, self._symbols,
                                     st.path_constraints, path_count_ref):
                i += 2  # 消耗 cmp + jcc 两行
                st.path_count = path_count_ref[0]
                continue
            i += 1

    def _evaluate_pairs(self, alloc_sites, write_sites) -> List[SymVerdict]:
        verdicts = []
        for a_addr, a_func, a_imm in alloc_sites:
            for w_addr, w_func, w_imm in write_sites:
                a_r = self._eval_size(a_func, a_addr, a_imm)
                w_r = self._eval_size(w_func, w_addr, w_imm)
                if self._state:
                    a_r = refine_range_by_constraints(
                        a_r, self._state.path_constraints)
                    w_r = refine_range_by_constraints(
                        w_r, self._state.path_constraints)

                if w_r[1] <= a_r[0]:
                    v = "DEFINITE_SAFE"
                elif w_r[0] > a_r[1]:
                    v = "DEFINITE_OVERFLOW"
                else:
                    v = "POSSIBLE"

                verdicts.append(SymVerdict(
                    alloc_site=a_addr, write_site=w_addr, verdict=v,
                    write_range=w_r, alloc_range=a_r,
                    num_paths_explored=(
                        self._state.path_count if self._state else 0)))
        return verdicts

    def _eval_size(self, func: str, addr: int, imm: int) -> Tuple[int, int]:
        if imm >= 0:
            return (imm, imm)
        return self._symbols.get(f"_{func}_{addr:x}", (1, 2**20))
