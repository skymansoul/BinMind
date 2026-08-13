"""容量溯源等价判定 — ACPE 的核心分类器.

创建: 2025-03-03
用途: 判定 memcpy 等写入的 size 表达式与目标分配的容量表达式之间的
      溯源等价关系。这是 ACPE 的关键创新点:

      大量误报来自 `dst=malloc(n); memcpy(dst, src, n)` 这类
      "自一致分配拷贝"——n 同时控制分配与拷贝, 通用污点分析见 n 受控
      即告警, 但拷贝不可能超过分配(容量等价)。若 n 在拷贝前被守卫
      或钳位限定, 同样安全。

分类结果 (Relation):
  EQUIV        写入 size 与分配 size 溯源等价 → 安全
  CONST_LE     写入 size 为常数且 ≤ 分配可用容量 → 安全
  CONST_GT     写入 size 为常数且 > 分配可用容量 → 确定溢出
  ARITH_LE     写入 = 分配基址 + 非正偏移 → 安全
  ARITH_SLACK  写入 = 分配基址 + 正偏移 ≤ MAX_SLACK → 存疑
  ARITH_GT     写入 = 分配基址 + 正偏移 > MAX_SLACK → 确定越界
  GUARDED      写入被早退/钳位守卫限定 ≤ 可用容量 → 安全
  UNRELATED    写入独立于分配容量 → 无法证明安全

TODO: 守卫界的有符号/无符号语义未区分 (cmp 的 jbe 与 jle 对同值
不同解释), 对极小负数 size 的边界行为需复核。
"""

from dataclasses import dataclass
from typing import Optional

from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
    CapExpr, const_relation, arith_relation)

from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
    GuardEvidence, guard_safety_check)


@dataclass
class EquivResult:
    """一次(分配, 写入)的等价判定结果."""
    relation: str = 'UNRELATED'
    reasoning: str = ''
    guard_evidence: Optional[GuardEvidence] = None


def classify_pair(alloc_expr: CapExpr,
                  write_expr: CapExpr,
                  write_unbounded: bool,
                  guard_ev: Optional[GuardEvidence],
                  insns=None) -> EquivResult:
    """对 (alloc, write) 做溯源等价分类.

    优先级:
      1. 无界写入(strcpy/gets): 若有守卫证据 → GUARDED, 否则 UNRELATED
      2. 常数 size: CONST_LE / CONST_GT
      3. 基址等价: EQUIV (同基址同偏移)
      4. 基址派生: ARITH_LE / ARITH_SLACK / ARITH_GT
      5. 守卫证据: GUARDED (早退/钳位)
      6. 兜底: UNRELATED
    """
    # 1. 无界写入
    if write_unbounded:
        if guard_ev is not None:
            v, msg = guard_safety_check(guard_ev, alloc_expr, 0)
            if v == 'SAFE':
                return EquivResult('GUARDED', msg, guard_ev)
        return EquivResult(
            'UNRELATED', 'unbounded copy (strcpy/gets), no guard proof',
            guard_ev)

    # 2. 常数写入 size
    if write_expr.kind == 'CONST':
        rel, msg = const_relation(alloc_expr, write_expr)
        if rel == 'CONST_LE':
            return EquivResult('CONST_LE', msg, guard_ev)
        if rel == 'CONST_GT':
            return EquivResult('CONST_GT', msg, guard_ev)
        # 容量非常数 → 落入守卫/兜底
        if guard_ev is not None:
            v, msg = guard_safety_check(guard_ev, alloc_expr,
                                        write_expr.value)
            if v == 'SAFE':
                return EquivResult('GUARDED', msg, guard_ev)
        return EquivResult('UNRELATED',
                           f'constant write {write_expr.value}B vs '
                           'non-constant capacity', guard_ev)

    # 3/4. 基址等价与派生
    if write_expr.is_symbolic() and alloc_expr.is_symbolic():
        if write_expr.base == alloc_expr.base:
            if write_expr.offset == alloc_expr.offset:
                return EquivResult(
                    'EQUIV',
                    f'write size == alloc size ({write_expr.canonical()}) — '
                    'capacity self-consistent', guard_ev)
            rel, msg = arith_relation(alloc_expr, write_expr)
            if rel in ('ARITH_LE', 'ARITH_SLACK', 'ARITH_GT'):
                return EquivResult(rel, msg, guard_ev)

    # 5. 守卫证据
    if guard_ev is not None:
        off = write_expr.offset if write_expr.kind == 'ARITH' else 0
        v, msg = guard_safety_check(guard_ev, alloc_expr, off)
        if v == 'SAFE':
            return EquivResult('GUARDED', msg, guard_ev)

    # 6. 兜底
    return EquivResult(
        'UNRELATED',
        f'write size {write_expr.canonical()} unrelated to alloc '
        f'{alloc_expr.canonical()}', guard_ev)


# 自检
def _check():
    # EQUIV: malloc(n); memcpy(dst, src, n)
    r = classify_pair(CapExpr.sym('A:1'), CapExpr.sym('A:1'),
                      False, None, None)
    assert r.relation == 'EQUIV', r

    # CONST_LE: malloc(100); memcpy(dst, src, 112) → usable 112
    r2 = classify_pair(CapExpr.const(100), CapExpr.const(112),
                       False, None, None)
    assert r2.relation == 'CONST_LE', r2

    # CONST_GT: malloc(64); memcpy(dst, src, 128)
    r3 = classify_pair(CapExpr.const(64), CapExpr.const(128),
                       False, None, None)
    assert r3.relation == 'CONST_GT', r3

    # ARITH_GT: malloc(n); memcpy(dst, src, n+32)
    r4 = classify_pair(CapExpr.sym('A:1'), CapExpr.arith('A:1', 0x20),
                       False, None, None)
    assert r4.relation == 'ARITH_GT', r4

    # 无守卫的符号 size → UNRELATED (保守保留)
    r5 = classify_pair(CapExpr.sym('A:1'), CapExpr.sym('A:2'),
                       False, None, None)
    assert r5.relation == 'UNRELATED', r5
    print('[OK] equivalence passed')


if __name__ == '__main__':
    _check()
