# 符号化分配-写入相关性引擎 (Symbolic Alloc-Write Correlation Engine)
#
# 核心决策:
#   SAWCE的核心问题: malloc(X)和memcpy(ptr,src,Y)中X和Y是否来自同一数据流.
#   若X和Y的结构等价(α-equivalent) → 不可能溢出 → 过滤误报.
#   若Y是X的子表达式(如Y=X+1) → 至多溢出1字节 → 边界安全.
#
#   判定层级:
#     1. 精确等价: expr(X) == expr(Y) → SAFE (分配=写入)
#     2. 常量比较: X=const(a), Y=const(b), a>=b → SAFE
#     3. 共享子表达式: X和Y共享同一Param节点且差异是常量偏移 → 可能安全
#     4. 无关: expr(X)和expr(Y)无共享节点 → 保持告警(可能溢出)
#
#   与区间分析的区别:
#     区间分析只知道X∈[0,256], Y∈[0,256], 无法判断是否同源.
#     符号化追踪知道X=arg0, Y=arg0 → 精确判定SAFE.
#
# 理论依据:
#   符号化分配-写入关联判定同源; 指针来源感知的堆访问验证.
#
# 创建: 2026-06-28

from typing import Dict, List, Optional, Tuple, Set
from .symbolic_size_expr import SymExpr, SymbolicSizeTracker
from .heap_constraint import HeapConstraintTracker, Interval


class CorrelationResult:
    """分配-写入相关性判定结果."""
    SAFE = "safe"           # 确定安全: 不可能溢出
    BOUNDARY_SAFE = "boundary_safe"  # 边界安全: 偏移在padding内
    UNCERTAIN = "uncertain"  # 不确定: 保持告警
    DIFFERENT_SOURCE = "different_source"  # 不同来源: 保持告警

    def __init__(self, verdict: str, reason: str = "",
                 alloc_expr: SymExpr = None, write_expr: SymExpr = None,
                 alloc_addr: int = 0, write_addr: int = 0):
        self.verdict = verdict
        self.reason = reason
        self.alloc_expr = alloc_expr
        self.write_expr = write_expr
        self.alloc_addr = alloc_addr
        self.write_addr = write_addr


class SymbolicCorrelator:
    """符号化分配-写入相关性验证引擎.

    输入: SymbolicSizeTracker捕获的分配/写入表达式对.
    输出: 每对(alloc, write)的相关性判定.
    """

    # 分配器padding上限: glibc最小chunk可用区16字节
    _PADDING_THRESHOLD = 16

    def __init__(self):
        self._results: List[CorrelationResult] = []

    def correlate(self, tracker: SymbolicSizeTracker,
                  alloc_tracker: HeapConstraintTracker
                  ) -> List[CorrelationResult]:
        """对所有分配-写入对执行符号化相关性验证.

        策略:
          对每个写入, 找到其指针来源的分配点,
          比较该分配的size表达式与写入的size表达式.
        """
        results = []
        alloc_exprs = tracker.alloc_exprs
        write_exprs = tracker.write_exprs

        for w_addr, w_func, w_expr in write_exprs:
            # 找到此写入的指针对应的分配
            # 通过alloc_tracker的ptr_to_alloc映射
            for a_addr, a_func, a_expr in alloc_exprs:
                result = self._check_pair(
                    a_addr, a_func, a_expr,
                    w_addr, w_func, w_expr)
                results.append(result)
                if result.verdict == CorrelationResult.SAFE:
                    break  # 确定安全, 不需要继续配对

        self._results = results
        return results

    def _check_pair(self, alloc_addr: int, alloc_func: str,
                    alloc_expr: SymExpr,
                    write_addr: int, write_func: str,
                    write_expr: SymExpr) -> CorrelationResult:
        """检查单个分配-写入对的相关性."""

        # Case 1: 两者都未知 → 无法判定
        if alloc_expr.is_unknown() and write_expr.is_unknown():
            return CorrelationResult(
                CorrelationResult.UNCERTAIN, "both_unknown",
                alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 2: 精确结构等价 → SAFE
        if alloc_expr == write_expr:
            return CorrelationResult(
                CorrelationResult.SAFE,
                f"structural_equiv: {alloc_expr.to_str()}=="
                f"{write_expr.to_str()}",
                alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 3: 两者都是常量 → 数值比较
        alloc_val = alloc_expr.const_val()
        write_val = write_expr.const_val()
        if alloc_val is not None and write_val is not None:
            if alloc_val >= write_val:
                return CorrelationResult(
                    CorrelationResult.SAFE,
                    f"const: alloc={alloc_val}>=write={write_val}",
                    alloc_expr, write_expr, alloc_addr, write_addr)
            return CorrelationResult(
                CorrelationResult.UNCERTAIN,
                f"const_overflow: alloc={alloc_val}<write={write_val}",
                alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 4: 写入表达式包含分配表达式作为子表达式
        if write_expr.contains(alloc_expr):
            # Y = f(X), 如Y=X+C → 溢出C字节
            offset = self._compute_constant_offset(alloc_expr, write_expr)
            if offset is not None and offset <= self._PADDING_THRESHOLD:
                return CorrelationResult(
                    CorrelationResult.BOUNDARY_SAFE,
                    f"subexpr_overlap: offset={offset}<=padding("
                    f"{self._PADDING_THRESHOLD})",
                    alloc_expr, write_expr, alloc_addr, write_addr)
            return CorrelationResult(
                CorrelationResult.UNCERTAIN,
                f"subexpr_overflow: offset={offset}",
                alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 5: 分配表达式包含写入表达式
        if alloc_expr.contains(write_expr):
            return CorrelationResult(
                CorrelationResult.SAFE,
                f"alloc_contains_write: "
                f"{alloc_expr.to_str()}⊇{write_expr.to_str()}",
                alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 6: 共享基础节点 (同为Param(arg0)等)
        if self._share_base_node(alloc_expr, write_expr):
            offset = self._compute_mutual_offset(alloc_expr, write_expr)
            if offset is not None and offset <= self._PADDING_THRESHOLD:
                return CorrelationResult(
                    CorrelationResult.BOUNDARY_SAFE,
                    f"shared_base: offset={offset}<=padding",
                    alloc_expr, write_expr, alloc_addr, write_addr)

        # Case 7: 无共享 → 不同来源
        return CorrelationResult(
            CorrelationResult.DIFFERENT_SOURCE,
            f"no_correlation: "
            f"alloc={alloc_expr.to_str()} vs "
            f"write={write_expr.to_str()}",
            alloc_expr, write_expr, alloc_addr, write_addr)

    def _compute_constant_offset(self, base: SymExpr,
                                  derived: SymExpr) -> Optional[int]:
        """若derived = base + C, 返回C. 否则返回None."""
        if derived.kind == "binop" and len(derived.children) == 2:
            lhs, rhs = derived.children
            if lhs == base and rhs.is_const():
                if derived.op == "+":
                    return rhs.const_val()
                if derived.op == "-":
                    return -rhs.const_val()
            if rhs == base and lhs.is_const():
                if derived.op == "+":
                    return lhs.const_val()
        return None

    def _compute_mutual_offset(self, e1: SymExpr,
                                e2: SymExpr) -> Optional[int]:
        """计算两个共享基础的表达式之间的常量偏移."""
        v1 = self._try_eval(e1)
        v2 = self._try_eval(e2)
        if v1 is not None and v2 is not None:
            return abs(v2 - v1)
        return None

    def _try_eval(self, expr: SymExpr) -> Optional[int]:
        """尝试求值常量表达式."""
        if expr.is_const():
            return expr.const_val()
        if expr.kind == "binop" and len(expr.children) == 2:
            lhs = self._try_eval(expr.children[0])
            rhs = self._try_eval(expr.children[1])
            if lhs is not None and rhs is not None:
                if expr.op == "+": return lhs + rhs
                if expr.op == "-": return lhs - rhs
                if expr.op == "*": return lhs * rhs
                if expr.op == "<<": return lhs << rhs
        return None

    def _share_base_node(self, e1: SymExpr, e2: SymExpr) -> bool:
        """检查两个表达式是否共享至少一个基础节点(Param/CallRet)."""
        nodes1 = self._collect_base_nodes(e1)
        nodes2 = self._collect_base_nodes(e2)
        return bool(nodes1 & nodes2)

    def _collect_base_nodes(self, expr: SymExpr) -> Set[SymExpr]:
        """收集表达式中的基础节点(Param/CallRet)."""
        result = set()
        if expr.kind in ("param", "callret", "extern"):
            result.add(expr)
        for child in expr.children:
            result |= self._collect_base_nodes(child)
        return result

    def filter_finding(self, finding: dict,
                        correlator_results: List[CorrelationResult]
                        ) -> Optional[str]:
        """根据相关性结果判定单个finding是否为误报.

        返回: 过滤原因(str)或None(不过滤).
        仅匹配与finding的write_addr对应的result, 避免跨函数误过滤.
        """
        write_addr = finding.get("write_addr", 0)
        alloc_addr = finding.get("_snapshot_alloc_addr",
                                  finding.get("alloc_addr", 0))
        for result in correlator_results:
            if result.write_addr != write_addr:
                continue
            if result.alloc_addr != alloc_addr:
                continue
            if result.verdict == CorrelationResult.SAFE:
                return f"sawce_safe: {result.reason}"
            if result.verdict == CorrelationResult.BOUNDARY_SAFE:
                return f"sawce_boundary: {result.reason}"
        return None

    @property
    def stats(self) -> dict:
        safe = sum(1 for r in self._results
                   if r.verdict == CorrelationResult.SAFE)
        boundary = sum(1 for r in self._results
                        if r.verdict == CorrelationResult.BOUNDARY_SAFE)
        uncertain = sum(1 for r in self._results
                         if r.verdict == CorrelationResult.UNCERTAIN)
        different = sum(1 for r in self._results
                         if r.verdict == CorrelationResult.DIFFERENT_SOURCE)
        return {
            "safe": safe,
            "boundary_safe": boundary,
            "uncertain": uncertain,
            "different_source": different,
            "total": len(self._results),
        }

    def reset(self):
        self._results.clear()


__all__ = ["SymbolicCorrelator", "CorrelationResult"]
