"""过程间上下文追踪 — 跨函数边界的size约束传播.

创建: 2025-02-06
用途: 堆操作的size约束常常跨越函数边界:
        caller: buf = malloc(n); process_data(buf, n);
        callee: void process_data(char *p, int len) { memcpy(dst, p, len); }

      现有检测只能在单个函数内追踪size约束,
      callee内部看到 len 是自由变量 → 标记为"可能溢出"。

      本模块记录caller→callee的参数绑定关系,
      使callee内部的size约束可以被caller端的已知区间约束,
      从而消除跨函数调用造成的误报。

方法: 上下文敏感的摘要 (context-sensitive summary)
  对每个函数生成摘要: {参数索引: (约束形式, 来源)}
  在调用点将实参的约束注入形参, 实现约束的跨函数传播。

设计取舍:
  - 递归深度限制为 3: 超过3层嵌套调用不追踪 (精度损失上限是3层)
  - 每函数最多缓存 16 个调用上下文: 不同caller可能传入不同约束,
    缓存最近16个以平衡精度与内存
  - 不做完整的过程间控制流图: 仅追踪显式的 call→ret 模式

  - "Context-Sensitive Pointer Analysis via Sparse Value-Flow"
    → 选择性上下文敏感
  - Saber: 基于值流的跨过程漏洞检测
    → 值流而非控制流传播 bug 条件
  - 本模块取其"跨函数参数绑定"思想, 简化为调用边约束传递
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import OrderedDict

@dataclass
class FunctionSummary:
    """一个函数的摘要——记录其影响堆size约束的方式."""
    func_name: str
    # 参数索引 → 在函数内被用作什么角色
    param_roles: Dict[int, str] = field(default_factory=dict)
    # 参数间的约束关系: {param_idx: ["param0 <= param1", ...]}
    param_constraints: Dict[int, List[str]] = field(default_factory=dict)
    # 该函数是否对某个参数做了边界检查
    has_bounds_check: bool = False
    # 被检查的参数索引
    checked_params: Set[int] = field(default_factory=set)

@dataclass
class CallSiteContext:
    """一个调用点的上下文——实参绑定了哪些约束."""
    call_addr: int
    caller_func: str
    callee_func: str
    arg_bindings: Dict[int, Tuple[int, int]] = field(default_factory=dict)
    # {形参索引: (实参值/区间lo, hi)}
    arg_constraints: Dict[int, str] = field(default_factory=dict)
    # {形参索引: "constraint_expression"}

class InterprocContextTracker:
    """过程间约束追踪器.

    使用方式:
      tracker = InterprocContextTracker()
      tracker.summarize_callee("process_data", {
          0: "heap_ptr", 1: "len_param"})
      tracker.register_call(0x401050, "main", "process_data",
                           {0: ("rbx", (0, 256)), 1: ("rcx", (0, 256))})
      # 现在在 process_data 内部, tracker 知道 len ≤ 256
      bound = tracker.get_arg_bound("process_data", 1)
      # → (0, 256)
    """

    MAX_DEPTH = 3
    MAX_CONTEXTS_PER_FUNC = 16

    def __init__(self):
        self._summaries: Dict[str, FunctionSummary] = {}
        self._contexts: Dict[str, OrderedDict] = {}
        # func_name → OrderedDict[call_key → CallSiteContext]
        self._param_bindings: Dict[Tuple[str, int], List[Tuple[int, int]]] = {}
        # (func, param_idx) → [(lo, hi), ...]

    def summarize_callee(self, func_name: str,
                         param_roles: Dict[int, str]) -> FunctionSummary:
        """为函数创建摘要——记录各参数的角色."""
        summary = FunctionSummary(func_name=func_name, param_roles=param_roles)
        self._summaries[func_name] = summary
        return summary

    def mark_bounds_check(self, func_name: str,
                          param_indices: List[int]) -> None:
        """标记函数对某些参数做了边界检查."""
        summary = self._summaries.get(func_name)
        if summary is None:
            summary = FunctionSummary(func_name=func_name)
            self._summaries[func_name] = summary
        summary.has_bounds_check = True
        summary.checked_params.update(param_indices)

    def register_call(self, call_addr: int, caller_func: str,
                      callee_func: str,
                      arg_bindings: Dict[int, Tuple[str, Tuple[int, int]]]
                      ) -> CallSiteContext:
        """注册一个函数调用.

        arg_bindings: {形参索引: (实参变量名, (lo, hi))}
        例如: {0: ("rbx", (0, 256)), 1: ("rcx", (0, 256))}
        """
        ctx = CallSiteContext(
            call_addr=call_addr, caller_func=caller_func,
            callee_func=callee_func)

        for param_idx, (arg_var, (lo, hi)) in arg_bindings.items():
            ctx.arg_bindings[param_idx] = (lo, hi)

        # 存储到callee的上下文列表
        if callee_func not in self._contexts:
            self._contexts[callee_func] = OrderedDict()
        call_key = f"{caller_func}@{hex(call_addr)}"
        contexts = self._contexts[callee_func]
        contexts[call_key] = ctx

        # LRU淘汰: 超过最大上下文数
        while len(contexts) > self.MAX_CONTEXTS_PER_FUNC:
            contexts.popitem(last=False)

        # 更新参数绑定 (多个caller可能传入不同约束)
        for param_idx, (lo, hi) in ctx.arg_bindings.items():
            key = (callee_func, param_idx)
            if key not in self._param_bindings:
                self._param_bindings[key] = []
            self._param_bindings[key].append((lo, hi))
            # 最多保留 32 个绑定记录
            if len(self._param_bindings[key]) > 32:
                self._param_bindings[key] = self._param_bindings[key][-16:]

    def get_arg_bound(self, func_name: str,
                      param_idx: int) -> Optional[Tuple[int, int]]:
        """获取某函数某参数在所有已知调用上下文中的区间.

        返回: 所有caller传入区间的并集 (最宽的lo和hi).
        """
        key = (func_name, param_idx)
        bindings = self._param_bindings.get(key, [])
        if not bindings:
            return None

        min_lo = min(b[0] for b in bindings)
        max_hi = max(b[1] for b in bindings)
        return (min_lo, max_hi)

    def get_tightest_bound(self, func_name: str,
                           param_idx: int) -> Optional[Tuple[int, int]]:
        """获取最紧的约束区间 (各caller的交集)."""
        key = (func_name, param_idx)
        bindings = self._param_bindings.get(key, [])
        if not bindings:
            return None

        max_lo = max(b[0] for b in bindings)
        min_hi = min(b[1] for b in bindings)
        if max_lo <= min_hi:
            return (max_lo, min_hi)
        return None  # 交集为空

    def can_prove_size_safe(self, func_name: str,
                            size_param_idx: int,
                            alloc_size: int) -> bool:
        """证明某函数中 size 参数 ≤ alloc_size.

        若所有已知的 caller 都传入 size ≤ alloc_size, 返回 True.
        """
        bound = self.get_arg_bound(func_name, size_param_idx)
        if bound is None:
            return False
        _, hi = bound
        return hi <= alloc_size

    def has_callee_bounds_check(self, func_name: str,
                                 param_idx: int) -> bool:
        """检查被调用函数是否对某参数做了边界检查."""
        summary = self._summaries.get(func_name)
        if summary is None:
            return False
        return param_idx in summary.checked_params

    def get_call_depth(self, func_name: str) -> int:
        """返回当前函数的调用深度 (基于活跃上下文数)."""
        return min(len(self._contexts.get(func_name, {})), self.MAX_DEPTH)

    def stats(self) -> dict:
        n_contexts = sum(len(ctxs) for ctxs in self._contexts.values())
        return {
            'functions_summarized': len(self._summaries),
            'call_contexts': n_contexts,
            'param_bindings': len(self._param_bindings),
        }
