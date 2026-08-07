"""
UAF 跨函数 CFG 构建器 — 为 TARPS 五阶段验证提供跨函数可达性分析.

核心创新:
  现有 TARPS 只在单函数内做基本块可达性分析 (Stage R).
  但真实世界的 UAF 通常跨越多个函数:
    func_A: p = malloc(n)     ← alloc
    func_B: free(p)           ← free
    func_C: p->field = val    ← use (跨函数!)

  本模块构建跨函数调用图 (Call Graph) 并做过程间 CFG 传播,
  将 alloc/free/use 三阶段映射到 CG 节点, 判定跨函数可达性.

方法:
  1. 解析源码提取函数定义和调用关系
  2. 构建 Call Graph (有向图, 边 = 调用关系)
  3. 标记 alloc/free/use 所在的函数节点
  4. BFS/DFS 判定 free→use 是否在 CG 中可达
  5. 若不可达 → SAFE (过滤), 若可达 → 继续 TARPS 内部阶段

  - Reps, Horwitz, Sagiv: "Precise Interprocedural Dataflow Analysis"
  - Nanda et al.: "UAFSan: Inter-procedural Use-After-Free Detection"
  - CWE-416 (Use After Free) vs CWE-415 (Double Free) 区分
"""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set, Tuple

import logging
_log = logging.getLogger(__name__)

from analysis.uaf_interproc_types import CallGraph, FunctionNode

class InterProcCFGBuilder:
    """跨函数调用图构建器.

    从C源码提取函数定义和调用关系, 构建 CallGraph.
    与 UafTarpsVerifier 配合: CG 分析作为 TARPS 的前置筛选阶段.
    """

    # 函数定义: type func_name(args) {
    _FUNC_DEF_RE = re.compile(
        r'^(?:static\s+)?(?:inline\s+)?(?:__attribute__\s*\([^)]*\)\s*)?'
        r'(?:void|int|char|long|size_t|uint\w*|int\w*|struct\s+\w+\s*\*?|'
        r'\w+\s*\*?)\s+'
        r'(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE | re.IGNORECASE)

    # malloc/calloc/realloc 调用: var = malloc(size)
    _ALLOC_RE = re.compile(
        r'(?:(\w+(?:->\w+)?(?:\s*\[\s*\w+\s*\])?)\s*=\s*)?'
        r'(malloc|calloc|realloc)\s*\(', re.IGNORECASE)

    # free 调用: free(ptr)
    _FREE_RE = re.compile(r'free\s*\(\s*(\w+(?:->\w+)?)\s*\)', re.IGNORECASE)

    # 指针解引用 (use): *ptr, ptr->field, ptr[index]
    _USE_RE = re.compile(
        r'(?:\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[)', re.IGNORECASE)

    # 函数调用: func_name(args)
    _CALL_RE = re.compile(r'\b(\w+)\s*\([^)]*\)', re.IGNORECASE)

    def __init__(self):
        self._cg = CallGraph()
        self._func_lines: Dict[str, Tuple[int, int]] = {}
        self._ptr_to_func: Dict[str, str] = {}  # 指针 → 分配所在函数

    @property
    def call_graph(self) -> CallGraph:
        return self._cg

    def build(self, source_code: str) -> CallGraph:
        """从C源码构建跨函数调用图."""
        lines = source_code.splitlines()
        self._cg = CallGraph()
        self._func_lines.clear()

        # Phase 1: 提取函数定义边界
        func_ranges = self._extract_function_ranges(source_code)

        # Phase 2: 在每个函数内扫描 alloc/free/use/call
        for func_name, (start, end) in func_ranges.items():
            node = FunctionNode(name=func_name, start_line=start, end_line=end)
            func_body = '\n'.join(lines[start:end + 1]) if start <= end < len(lines) else ''

            # 扫描 alloc/free/use sites
            for i in range(start, min(end + 1, len(lines))):
                line = lines[i].strip() if i < len(lines) else ''

                if self._ALLOC_RE.search(line):
                    node.alloc_sites.append(i)
                    # 提取被赋值的变量
                    m = re.search(r'(\w+(?:->\w+)?)\s*=\s*(?:malloc|calloc|realloc)', line)
                    if m:
                        self._ptr_to_func[m.group(1)] = func_name

                if self._FREE_RE.search(line):
                    node.free_sites.append(i)

                if self._USE_RE.search(line) and not self._ALLOC_RE.search(line):
                    node.use_sites.append(i)

            # 扫描函数调用
            for call_m in self._CALL_RE.finditer(func_body):
                callee = call_m.group(1)
                if callee != func_name and not self._is_keyword(callee):
                    node.calls.add(callee)

            # 检测包装函数: 只做 malloc+return 或 free+return
            if len(node.alloc_sites) >= 1 and len(node.free_sites) == 0:
                # 如果函数体很小且主要就是 malloc → 可能是 alloc wrapper
                if end - start < 10:
                    node.is_alloc_wrapper = True
            if len(node.free_sites) >= 1 and len(node.alloc_sites) == 0:
                if end - start < 10:
                    node.is_free_wrapper = True

            self._cg.nodes[func_name] = node

        # Phase 3: 构建逆向边 (called_by)
        for caller_name, node in self._cg.nodes.items():
            for callee in node.calls:
                if callee in self._cg.nodes:
                    self._cg.nodes[callee].called_by.add(caller_name)
                    self._cg.edges.append((caller_name, callee))

        return self._cg

    def _extract_function_ranges(self, source_code: str) -> Dict[str, Tuple[int, int]]:
        """通过括号匹配提取函数定义的行范围."""
        lines = source_code.splitlines()
        ranges = {}
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = self._FUNC_DEF_RE.search(line)
            if m:
                func_name = m.group(1)
                if self._is_keyword(func_name):
                    i += 1
                    continue
                # 括号匹配找函数结束
                depth = 0
                started = False
                end_line = i
                for j in range(i, len(lines)):
                    for ch in lines[j]:
                        if ch == '{':
                            depth += 1
                            started = True
                        elif ch == '}':
                            depth -= 1
                    if started and depth == 0:
                        end_line = j
                        break
                ranges[func_name] = (i, end_line)
                i = end_line + 1
            else:
                i += 1
        return ranges

    @staticmethod
    def _is_keyword(name: str) -> bool:
        """排除 C 关键字 (避免误识别为函数调用)."""
        return name.lower() in {
            'if', 'else', 'while', 'for', 'switch', 'case', 'return',
            'sizeof', 'typeof', 'defined', 'include', 'endif', 'ifdef',
            'void', 'int', 'char', 'long', 'short', 'float', 'double',
            'static', 'const', 'extern', 'volatile', 'unsigned', 'signed',
            'struct', 'union', 'enum', 'typedef', 'goto', 'break', 'continue',
            'do', 'default', 'auto', 'register',
        }

    # 跨函数 UAF 可达性判定 ──────────────────────

    def is_cross_func_uaf_reachable(
        self, alloc_func: str, free_func: str, use_func: str,
    ) -> Tuple[bool, str]:
        """判定 alloc → free → use 的跨函数调用链是否可达.

        方法:
          1. 同函数 → 单函数UAF, 由 TARPS 内部处理
          2. 直接CG路径: alloc_func 可调用 free_func, free_func 可调用 use_func
          3. 共同调用者模式: 存在函数 F 同时可到达三者 (经典场景: main调用三个wrapper)
             F → alloc_wrapper, F → free_wrapper, F → use_wrapper
             这是最常见的跨函数UAF模式 (CVE-2021-38001等)

        Returns:
          (is_reachable, reason)
        """
        cg = self._cg

        # 三者同函数 → 单函数UAF, 由 TARPS 内部处理
        if alloc_func == free_func == use_func:
            return True, "same function — deferred to intra-procedural TARPS"

        # 方法1: 直接CG路径 (嵌套调用模式)
        alloc_to_free = cg.has_path(alloc_func, free_func) or alloc_func == free_func
        free_to_use = cg.has_path(free_func, use_func) or free_func == use_func
        if alloc_to_free and free_to_use:
            return True, f"direct path: {alloc_func}→{free_func}→{use_func}"

        # 方法2: 共同调用者模式 (经典跨函数UAF)
        # 查找可以同时到达 alloc_func 和 free_func 的调用者
        alloc_reachable_from = self._cg.reachable_from(alloc_func)
        free_reachable_from = self._cg.reachable_from(free_func)
        use_reachable_from = self._cg.reachable_from(use_func)

        # 从 alloc_func 出发可到达的函数中, 是否有能到达 free_func 的?
        common_callers_af = alloc_reachable_from & {f for f, n in cg.nodes.items()
                                                     if cg.has_path(f, free_func)}
        common_callers_fu = free_reachable_from & {f for f, n in cg.nodes.items()
                                                     if cg.has_path(f, use_func)}

        if common_callers_af and common_callers_fu:
            return True, (f"common-caller path: alloc→free via {common_callers_af}, "
                         f"free→use via {common_callers_fu}")

        # 方法3: 反向可达 (谁调用了这三者?)
        # 查询: 是否存在函数 F 能调用到所有三者?
        # → F 在 alloc_func 的 called_by 链上 AND F 在 free_func 的 called_by 链上
        def ancestors(func: str) -> Set[str]:
            """返回所有能(间接)调用 func 的函数."""
            result = {func}
            queue = deque([func])
            while queue:
                f = queue.popleft()
                node = cg.nodes.get(f)
                if node:
                    for caller in node.called_by:
                        if caller not in result:
                            result.add(caller)
                            queue.append(caller)
            return result

        alloc_ancestors = ancestors(alloc_func)
        free_ancestors = ancestors(free_func)
        use_ancestors = ancestors(use_func)

        common_ancestors = alloc_ancestors & free_ancestors & use_ancestors
        # 排除叶子函数自身 (它们不是真正的"调用者")
        real_callers = common_ancestors - {alloc_func, free_func, use_func}

        if real_callers:
            return True, (f"common-ancestor path: {real_callers} "
                         f"can reach all three ({alloc_func}, {free_func}, {use_func})")

        return False, (f"no path: alloc({alloc_func}), free({free_func}), "
                      f"use({use_func}) are isolated in CG")

    def find_reachable_use_sites(
        self, free_func: str, ptr_var: str = "",
    ) -> List[Tuple[str, int]]:
        """查找从 free_func 可到达的所有函数中的 use sites.

        Returns:
          [(func_name, line_no), ...] 从 free 可到达的使用点列表
        """
        reachable_funcs = self._cg.reachable_from(free_func)
        reachable_funcs.add(free_func)
        uses = []
        for fname in reachable_funcs:
            node = self._cg.nodes.get(fname)
            if node and node.use_sites:
                for line_no in node.use_sites:
                    uses.append((fname, line_no))
        return uses

__all__ = ['FunctionNode', 'CallGraph', 'InterProcCFGBuilder']
