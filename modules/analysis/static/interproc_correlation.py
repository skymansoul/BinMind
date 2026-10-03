# 跨函数分配-写入关联分析 (Inter-Procedural Allocation-Write Correlation)
#
# 核心决策:
#   堆溢出检测的最大漏报来源之一: 当前仅做函数内分析.
#   实际代码常将 malloc 封装在 wrapper 函数中, 或通过多层调用传递指针.
#   若 wrapper 内分配了足够的空间, 但调用者只看到指针而不知道分配大小,
#   误报就产生了.
#
#   本模块通过轻量级调用图摘要实现跨函数分析:
#     1. 为每个函数计算摘要: 堆分配→返回指针, 写入大小→参数约束.
#     2. 在调用点将摘要实例化: 用实参替换形参.
#     3. 传播深度限制为 k=2: 超过2层的间接调用不再追踪.
#        (理由: 深度>2的指针传递在静态分析中可靠性急剧下降)
#
from typing import Dict, List, Optional, Set, Tuple, NamedTuple
from dataclasses import dataclass, field


class FuncSummary(NamedTuple):
    """函数摘要: 对堆操作的精简描述."""
    name: str
    # alloc_info: (被调用方地址, 分配大小参数来源, 结果写入的寄存器)
    allocs: List[Tuple[int, str, str]] = []  # (alloc_addr, size_param, result_reg)
    # write_info: (写入地址, 写入的指针来源参数, 写入大小参数)
    writes: List[Tuple[int, str, str]] = []  # (write_addr, ptr_param, size_param)
    # 返回的指针是否是堆分配的 → 对应的 alloc 索引
    return_alloc_idx: Optional[int] = None
    # 已知的安全条件: 若参数的 range 满足条件则安全
    safe_conditions: List[str] = []


@dataclass
class CallSite:
    """调用点信息."""
    addr: int
    callee_name: str
    arguments: Dict[int, str] = field(default_factory=dict)  # arg_idx → reg/imm


class InterProcCorrelator:

    MAX_DEPTH = 2  # 跨越层数: 当前函数 → caller → caller's caller

    def __init__(self):
        self._summaries: Dict[str, FuncSummary] = {}
        self._call_graph: Dict[str, List[CallSite]] = {}  # caller → callees
        self._results: Dict[int, bool] = {}  # call_site_addr → is_safe

    def register_summary(self, summary: FuncSummary):
        """注册一个函数的摘要."""
        self._summaries[summary.name] = summary

    def register_call(self, caller_name: str, site: CallSite):
        """注册一个调用关系."""
        if caller_name not in self._call_graph:
            self._call_graph[caller_name] = []
        self._call_graph[caller_name].append(site)

    def is_write_safe(self, write_site_addr: int,
                      write_size_operand: str,
                      ptr_operand: str,
                      depth: int = 0) -> Tuple[bool, str]:
        if depth >= self.MAX_DEPTH:
            return False, f"depth_limit_exceeded:{depth}"

        # 查询该地址所在的函数
        caller = self._find_containing_function(write_site_addr)
        if caller is None:
            return False, "unknown_function_context"

        summary = self._summaries.get(caller)
        if summary is None:
            return False, f"no_summary_for:{caller}"

        # 检查该函数摘要中的 alloc-write 关联
        for alloc_addr, size_param, result_reg in summary.allocs:
            # 如果指针是分配返回的, 且写入大小 ≤ 分配大小
            if result_reg == ptr_operand:
                # 需要知道分配大小的具体值
                for write_addr, ptr_param, size_param_name in summary.writes:
                    if write_addr == write_site_addr:
                        if self._same_source(size_param, size_param_name, summary):
                            return True, (
                                f"alloc_write_correlated: "
                                f"alloc={alloc_addr:#x} write={write_addr:#x}"
                            )

        # 递归检查调用者的调用者
        if depth < self.MAX_DEPTH - 1:
            # 查找谁调用了 caller
            for func_name, sites in self._call_graph.items():
                for site in sites:
                    if site.callee_name == caller:
                        # 在调用者上下文中重新检查
                        # 将形参替换为实参
                        resolved_ptr = self._resolve_arg(
                            ptr_operand, site.arguments, summary)
                        resolved_size = self._resolve_arg(
                            write_size_operand, site.arguments, summary)
                        is_safe, reason = self.is_write_safe(
                            site.addr, resolved_size, resolved_ptr, depth + 1)
                        if is_safe:
                            return True, f"caller_correlated:{reason}"
                        break

        return False, "no_correlation_found"

    def correlate_all(self) -> Dict[int, Tuple[bool, str]]:
        """对所有已知写入点执行关联分析."""
        results = {}
        for func_name, summary in self._summaries.items():
            for write_addr, ptr_param, size_param in summary.writes:
                is_safe, reason = self.is_write_safe(
                    write_addr, size_param, ptr_param)
                results[write_addr] = (is_safe, reason)
        self._results = results
        return results

    @staticmethod
    def _same_source(param1: str, param2: str,
                     summary: FuncSummary) -> bool:
        """判断两个参数是否来自同一数据源."""
        # 简化: 直接比较参数名 (需要完整 IR 分析做更精确的比较)
        if param1 == param2:
            return True
        # 检查是否有等价条件
        for cond in summary.safe_conditions:
            if f"{param1}=={param2}" in cond or f"{param2}=={param1}" in cond:
                return True
        return False

    @staticmethod
    def _resolve_arg(param: str, arguments: Dict[int, str],
                     callee_summary: FuncSummary) -> str:
        """用调用点的实参替换被调用函数的形参."""
        # param 格式: "arg0", "arg1", ...
        if param.startswith("arg"):
            try:
                idx = int(param[3:])
                if idx in arguments:
                    return arguments[idx]
            except ValueError:
                pass
        return param

    def _find_containing_function(self, addr: int) -> Optional[str]:
        """根据地址查找所属函数 (简化: 遍历摘要中的地址范围)."""
        for name, summary in self._summaries.items():
            all_addrs = [a for a, _, _ in summary.allocs]
            all_addrs += [w for w, _, _ in summary.writes]
            if all_addrs:
                min_addr = min(all_addrs)
                max_addr = max(all_addrs)
                if min_addr <= addr <= max_addr + 0x1000:
                    return name
        return None

    @property
    def stats(self) -> dict:
        return {
            "functions_summarized": len(self._summaries),
            "call_sites_tracked": sum(len(s) for s in self._call_graph.values()),
            "safe_correlations": sum(1 for v in self._results.values() if v[0]),
        }


__all__ = ["InterProcCorrelator", "FuncSummary", "CallSite"]
