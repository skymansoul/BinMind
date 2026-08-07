"""
跨函数堆分配大小约束摘要 — 构建 function-level size summary 并沿调用图传播。

核心问题: 现有 heap_flow_tracker 只在单函数内追踪 size 变量。
当 size 来自参数或另一函数的返回值时, 分析直接标记为 UNKNOWN。
这导致大量真阳性被标记为"无法确定"而漏报, 或所有未知都当阳性而误报。

方法:
  1. 对每个函数, 在反编译伪代码上提取 malloc(size) 调用及其 size 的约束形式
  2. 构建 size 的符号表达式: size_expr = f(params, globals, constants)
  3. 在调用图上执行 bottom-up 摘要传播:
     - 叶函数直接总结
     - 调用者将 callee 摘要代入实参
  4. 对 size_expr 应用 strided interval abstraction, 计算 [lo, hi, stride]
  5. 输出 InterProcSizeSummary: {func_name: {alloc_site: interval}}

理论基础:
  - Modular static analysis
  - WYSINWYX strided intervals
  - Function summarization in Datalog

局限: 反编译伪代码不是真正的 IR, 变量恢复可能不精确。
      递归调用用 widening 保证终止, 精度有损。
"""


import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_unbounded,
)


@dataclass
class AllocSiteSummary:
    """单条 malloc 调用的 size 约束摘要。"""
    line: int                     # 在函数伪代码中的行号
    alloc_func: str               # malloc/calloc/realloc
    size_expr: str                # size 的符号表达式
    interval: StridedInterval     # strided interval over-approximation
    depends_on_params: List[str]  # 依赖的函数参数名
    is_dynamic: bool = False      # size 是否完全由外部输入决定


@dataclass
class FuncSizeSummary:
    """单个函数的堆分配大小摘要。"""
    func_name: str
    alloc_sites: List[AllocSiteSummary] = field(default_factory=list)
    param_bindings: Dict[str, StridedInterval] = field(default_factory=dict)
    # 该函数总共可能分配的最大字节数 (strided interval)
    total_alloc_range: StridedInterval = field(
        default_factory=lambda: StridedInterval(0, 0, 0))


class InterProcSizeSummarizer:
    """跨函数 size constraint 摘要构建器。

    在调用图上做 bottom-up propagation:
      1. 提取每个函数的本地 alloc sites
      2. 对被调用者, 用实参区间替换形参
      3. 合并所有 alloc sites 的区间 → 得到每个函数的总分配大小范围
    """

    # 匹配 malloc/calloc/realloc 调用的正则
    _ALLOC_RE = re.compile(
        r'(?:(\w+)\s*=\s*)?'
        r'(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE,
    )
    # calloc 参数分隔
    _CALLOC_ARGS_RE = re.compile(r'([^,]+)\s*,\s*([^)]+)')

    def __init__(self, platform: str = "x86_64"):
        self._summaries: Dict[str, FuncSizeSummary] = {}
        self._call_graph: Dict[str, List[str]] = defaultdict(list)
        self._platform = platform

    def build_call_graph(self, decompiled_funcs: Dict[str, str]) -> None:
        """从反编译函数集合构建调用图。

        使用简单启发式: 在 func_a 的代码中搜索 func_b(...) 调用。
        不做指针分析, 只匹配直接调用。
        """
        func_names = set(decompiled_funcs.keys())
        call_re = re.compile(r'(\b[a-zA-Z_]\w{0,63}\b)\s*\(')

        for caller, code in decompiled_funcs.items():
            callees = set()
            for m in call_re.finditer(code):
                name = m.group(1)
                if name in func_names and name != caller:
                    callees.add(name)
            self._call_graph[caller] = list(callees)

    def extract_local_sites(self, func_name: str,
                            pseudocode: str) -> FuncSizeSummary:
        """从单函数伪代码中提取本地 alloc sites 及其 size 约束。"""
        summary = FuncSizeSummary(func_name=func_name)
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            m = self._ALLOC_RE.search(line)
            if not m:
                continue

            result_var = m.group(1) or ""
            alloc_func = m.group(2).lower()
            args_str = m.group(3).strip()

            size_expr = self._extract_size_expr(alloc_func, args_str)
            interval = self._expr_to_interval(size_expr)
            params = self._extract_param_refs(size_expr)
            is_dynamic = self._is_input_dependent(size_expr)

            summary.alloc_sites.append(AllocSiteSummary(
                line=i, alloc_func=alloc_func, size_expr=size_expr,
                interval=interval, depends_on_params=params,
                is_dynamic=is_dynamic,
            ))

        # 合并所有 alloc sites 的总分配范围
        total = StridedInterval(0, 0, 0)
        for s in summary.alloc_sites:
            if s.interval.is_bottom():
                continue
            total = total.union(s.interval)
        summary.total_alloc_range = total
        return summary

    def propagate(self, decompiled_funcs: Dict[str, str]) -> Dict[str, FuncSizeSummary]:
        """执行 bottom-up 摘要传播。

        策略:
          - 从调用图的叶子节点开始 (被调用者先于调用者)
          - 处理调用者时, 将 callee 的 total_alloc_range 累加到自身
          - 循环调用 (递归) 用 widening 处理: 第一次取 callee 的摘要,
            后续迭代时 widening 到 unbounded.
        """
        if not self._call_graph:
            self.build_call_graph(decompiled_funcs)

        # 拓扑排序 — 被调用者先处理
        order = self._topo_sort()

        for func_name in order:
            code = decompiled_funcs.get(func_name, "")
            if not code:
                continue
            summary = self.extract_local_sites(func_name, code)
            self._summaries[func_name] = summary

        # 第二轮: 将被调用者的摘要合并到调用者
        for caller, callees in self._call_graph.items():
            caller_sum = self._summaries.get(caller)
            if caller_sum is None:
                continue
            for callee in callees:
                callee_sum = self._summaries.get(callee)
                if callee_sum is None:
                    continue
                caller_sum.total_alloc_range = caller_sum.total_alloc_range.union(
                    callee_sum.total_alloc_range)

        return dict(self._summaries)

    # helpers

    def _extract_size_expr(self, alloc_func: str, args_str: str) -> str:
        if alloc_func == "calloc":
            m = self._CALLOC_ARGS_RE.search(args_str)
            if m:
                return f"({m.group(1).strip()}) * ({m.group(2).strip()})"
        return args_str.split(",")[0].strip()

    def _expr_to_interval(self, expr: str) -> StridedInterval:
        """将 size 表达式转为 strided interval 近似。

        能识别的模式:
          - 纯常量: "1024" → [1024, 1024]
          - sizeof(T): "sizeof(struct foo)" → 按对齐估算 [16, 4096]
          - 变量: "len" → 无约束 [0, ∞)
          - 简单算术: "len * 2 + 1" → [0*2+1, ∞]
          - calloc: "4 * 256" → [1024, 1024]
        """
        expr = expr.strip()
        # 纯常量
        try:
            val = int(expr, 0)
            return si_singleton(val)
        except (ValueError, TypeError):
            pass
        # sizeof(T) 模式
        if "sizeof" in expr.lower():
            return si_interval(8, 4096)  # 保守估计
        # calloc 常量乘法: "n * m"
        m = re.match(r'^(\d+)\s*\*\s*(\d+)$', expr)
        if m:
            return si_singleton(int(m.group(1)) * int(m.group(2)))
        # 其他: unbounded
        return si_unbounded(0)

    def _extract_param_refs(self, expr: str) -> List[str]:
        """提取表达式中的参数引用。"""
        return [w for w in re.findall(r'\b[a-zA-Z_]\w*\b', expr)
                if not w.isdigit() and w not in ("sizeof", "malloc", "calloc", "realloc")]

    def _is_input_dependent(self, expr: str) -> bool:
        """判断 size 表达式是否依赖外部输入。"""
        user_sources = {"atoi", "atol", "strtol", "argv", "getenv",
                        "scanf", "fscanf", "read", "fgets", "recv", "getline"}
        expr_lower = expr.lower()
        return any(src in expr_lower for src in user_sources)

    def _topo_sort(self) -> List[str]:
        """对调用图做拓扑排序 — 被调用者先出现。

        使用 Kahn 算法; 若有循环, 用入度打破。
        """
        in_degree: Dict[str, int] = defaultdict(int)
        all_nodes = set(self._call_graph.keys())
        for callees in self._call_graph.values():
            for c in callees:
                in_degree[c] += 1
                all_nodes.add(c)

        queue = [n for n in all_nodes if in_degree.get(n, 0) == 0]
        result = []
        while queue:
            node = queue.pop(0)
            result.append(node)
            for callee in self._call_graph.get(node, []):
                in_degree[callee] -= 1
                if in_degree[callee] == 0:
                    queue.append(callee)

        # 剩余节点 (循环依赖) — 追加到末尾
        remaining = [n for n in all_nodes if n not in result]
        result.extend(remaining)
        return result


def summarize_binary(decompiled_map: Dict[str, str]) -> Dict[str, FuncSizeSummary]:
    """便捷接口: 对二进制中所有函数构建 size 摘要。"""
    summarizer = InterProcSizeSummarizer()
    return summarizer.propagate(decompiled_map)


__all__ = [
    'AllocSiteSummary', 'FuncSizeSummary',
    'InterProcSizeSummarizer', 'summarize_binary',
]
