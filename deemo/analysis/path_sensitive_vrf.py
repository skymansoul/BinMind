"""
路径敏感值范围传播 — DFS分支敏感仿射区间传播 + 不等式检查.

Tier 1 核心: 在 CFG 上做分支敏感的仿射区间传播.
  - 变量 → AffineInterval 映射, 每路径独立维护
  - 分支处 fork PathCondition, 不 merge (避免精度损失)
  - malloc 处记录 AllocSite, memcpy 处做溢出判定
  - 回溯: DFS 探索每个分支后恢复父状态

判定逻辑:
  - definitely_safe: write_hi <= alloc_lo (所有路径)
  - definitely_overflow: write_lo > alloc_hi (某个路径)
  - possible: 其他情况 (保守保留)
"""


import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .symbolic_range import (
    AffineInterval, PathCondition, LinearInequality,
    affine_const, affine_var, affine_unbounded)
from .heap_expr_parser import HeapExprParser
from .heap_ir_matcher import (
    match_assign, match_if, match_alloc, match_write, match_condition)

_log = logging.getLogger(__name__)


@dataclass
class AllocRecord:
    """在特定路径条件下的分配记录."""
    addr: int
    func: str
    size_affine: AffineInterval
    path_condition: PathCondition


@dataclass
class VrfVerdict:
    """路径敏感区间分析的判定结果."""
    alloc_addr: int
    write_addr: int
    alloc_func: str
    write_func: str
    alloc_affine: AffineInterval
    write_affine: AffineInterval
    verdict: str  # SAFE / OVERFLOW / POSSIBLE
    confidence: float
    reason: str


class PathSensitiveVRF:
    """DFS 分支敏感仿射区间传播引擎.

    关键操作:
      - propagate_insn(): 沿基本块正向传播
      - _check_allocs(): malloc/memcpy 对的不等式检查
    """

    def __init__(self):
        self._expr_parser = HeapExprParser()
        self._var_ranges: Dict[str, AffineInterval] = {}
        self._path_cond = PathCondition()
        self._allocs: List[AllocRecord] = []
        self._verdicts: List[VrfVerdict] = []
        self._visited_pairs: Set[Tuple[int, int]] = set()

    def clear(self):
        self._var_ranges.clear()
        self._path_cond = PathCondition()
        self._allocs.clear()
        self._verdicts.clear()
        self._visited_pairs.clear()

    # 状态快照

    def _snapshot(self) -> Tuple[Dict[str, AffineInterval], PathCondition,
                                   List[AllocRecord]]:
        return (dict(self._var_ranges), self._path_cond.fork(),
                list(self._allocs))

    def _restore(self, snap: Tuple[Dict[str, AffineInterval],
                                     PathCondition, List[AllocRecord]]):
        self._var_ranges, self._path_cond, self._allocs = snap

    # 指令级传播

    def propagate_insn(self, addr: int, text: str):
        """处理单条伪代码指令, 更新变量范围."""
        tl = text.strip()

        # 变量赋值
        assign_m = match_assign(tl)
        if assign_m:
            var, expr_text = assign_m
            aff = self._expr_parser.parse(expr_text)
            self._var_ranges[var] = aff
            return

        # 条件分支
        cond_m = match_if(tl)
        if cond_m:
            cond_text, is_if = cond_m
            if is_if:
                self._record_condition(cond_text)
            return

        # malloc(size)
        alloc_m = match_alloc(tl)
        if alloc_m:
            dst_var, func, size_text = alloc_m
            size_aff = self._expr_parser.parse(size_text)
            size_aff = self._refine_from_path(size_aff)
            self._allocs.append(AllocRecord(
                addr=addr, func=func, size_affine=size_aff,
                path_condition=self._path_cond.fork()))
            return

        # memcpy/write
        write_m = match_write(tl)
        if write_m:
            func, n_text = write_m
            n_aff = self._expr_parser.parse(n_text)
            n_aff = self._refine_from_path(n_aff)
            self._check_allocs(addr, func, n_aff)
            return

    def _refine_from_path(self, aff: AffineInterval) -> AffineInterval:
        """用当前 PathCondition 精化仿射区间."""
        for name, coef in aff.coefs.items():
            lo, hi = self._path_cond.bound_of(name)
            if lo is not None:
                aff = aff.refine_lo(aff.base + coef * lo)
            if hi is not None:
                aff = aff.refine_hi(aff.base + coef * hi)
        return aff

    # 条件分支处理

    def _record_condition(self, cond_text: str):
        """从条件文本中提取约束加入 PathCondition."""
        result = match_condition(cond_text)
        if result is None:
            return
        var, op, val = result

        if op == 'lt':
            self._path_cond = self._path_cond.add_bound(var, hi=val - 1)
        elif op == 'le':
            self._path_cond = self._path_cond.add_bound(var, hi=val)
        elif op == 'gt':
            self._path_cond = self._path_cond.add_bound(var, lo=val + 1)
        elif op in ('ge', 'ge_rev'):
            self._path_cond = self._path_cond.add_bound(var, lo=val)
        elif op == 'gt_rev':
            self._path_cond = self._path_cond.add_bound(var, hi=val - 1)

    # 不等式检查

    def _check_allocs(self, write_addr: int, write_func: str,
                      write_aff: AffineInterval):
        """对当前路径条件下的所有分配点执行溢出判定."""
        for alloc in self._allocs:
            pair_key = (alloc.addr, write_addr)
            if pair_key in self._visited_pairs:
                continue
            self._visited_pairs.add(pair_key)
            verdict = self._classify(alloc, write_func, write_aff,
                                     self._path_cond)
            self._verdicts.append(verdict)

    def _classify(self, alloc: AllocRecord, write_func: str,
                  write_aff: AffineInterval,
                  pc: PathCondition) -> VrfVerdict:
        """三分类判定: SAFE / OVERFLOW / POSSIBLE."""
        alloc_aff = alloc.size_affine

        # 常量判定
        alloc_c = alloc_aff.constant_value()
        write_c = write_aff.constant_value()
        if alloc_c is not None and write_c is not None:
            if write_c <= alloc_c:
                return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                                  alloc_aff, write_aff, "SAFE", 0.05,
                                  f"常量判定: write({write_c}) <= alloc({alloc_c})")
            return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                              alloc_aff, write_aff, "OVERFLOW", 0.85,
                              f"常量判定: write({write_c}) > alloc({alloc_c})")

        # 仿射区间边界推理
        if alloc_aff.definitely_within(write_aff):
            return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                              alloc_aff, write_aff, "OVERFLOW", 0.70,
                              "仿射区间: alloc在最坏情况下仍溢出")
        if write_aff.definitely_within(alloc_aff):
            return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                              alloc_aff, write_aff, "SAFE", 0.10,
                              "仿射区间: write在所有情况下安全")

        # 路径矛盾
        if pc and pc.is_contradiction():
            return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                              alloc_aff, write_aff, "SAFE", 0.30,
                              "路径矛盾: 当前路径不可行")

        return VrfVerdict(alloc.addr, 0, alloc.func, write_func,
                          alloc_aff, write_aff, "POSSIBLE", 0.40,
                          "仿射区间无法确定, 保守保留")

    # 结果查询

    def get_verdicts(self) -> List[VrfVerdict]:
        return self._verdicts

    def get_stats(self) -> Dict[str, int]:
        counts = {"SAFE": 0, "OVERFLOW": 0, "POSSIBLE": 0}
        for v in self._verdicts:
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
        return counts
