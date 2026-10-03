"""DFC-PV 跨函数分析器 — 包装函数链解析 + 跨函数 free 配对.

识别 free 包装函数 (如 destroy/cleanup/close) 并追踪调用链.
当 wrapper(p) 被调用后, p 在调用点之后直接 free(p) 构成 double-free.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple, Optional

from analysis.dfc_pv_types import FreeSite, AllocSite


class CrossFuncAnalyzer:
    """跨函数 free 分析."""

    def __init__(self, lines: List[str],
                 func_map: Dict[str, Tuple[int, int, List[str]]]):
        self.lines = lines
        self.func_map = func_map
        self.wrappers = self._find_free_wrappers()
        self.call_graph = self._build_call_graph()

    def _find_free_wrappers(self) -> Set[str]:
        """识别含 free 的函数 (无论是否有其他调用)."""
        result: Set[str] = set()
        for name, (s, e, _) in self.func_map.items():
            for i in range(s, min(e + 1, len(self.lines) + 1)):
                text = self.lines[i - 1].strip()
                if text.startswith(('//', '/*')):
                    continue
                if re.search(r'\bfree\s*\(', text):
                    result.add(name)
                    break
        return result

    def _build_call_graph(self) -> Dict[str, List[Tuple[str, int]]]:
        """构建 call graph: caller -> [(callee, call_line)]."""
        cg: Dict[str, List[Tuple[str, int]]] = {}
        for name, (s, e, _) in self.func_map.items():
            for i in range(s, min(e + 1, len(self.lines) + 1)):
                text = self.lines[i - 1].strip()
                if text.startswith('//'):
                    continue
                for m in re.finditer(r'\b(\w+)\s*\(', text):
                    callee = m.group(1)
                    if callee in self.func_map and callee != name:
                        cg.setdefault(name, []).append((callee, i))
        return cg

    def find_transitive_frees(self, func: str,
                               visited: Optional[Set[str]] = None) -> List[str]:
        """返回 func 及其调用链中所有含 free 的函数."""
        if visited is None:
            visited = set()
        if func in visited or func not in self.func_map:
            return []
        visited.add(func)
        result = []
        if func in self.wrappers:
            result.append(func)
        for callee, _ in self.call_graph.get(func, []):
            if callee not in visited:
                result.extend(self.find_transitive_frees(callee, visited))
        return result

    def get_call_lines(self, callee: str) -> List[int]:
        """返回 callee 被调用的所有行号."""
        lines = []
        for name, (_, _, _) in self.func_map.items():
            if name == callee:
                continue
            for i in range(*self.func_map[name][:2]):
                if i - 1 >= len(self.lines):
                    break
                text = self.lines[i - 1].strip()
                if text.startswith('//'):
                    continue
                if re.search(rf'\b{re.escape(callee)}\s*\(', text):
                    lines.append(i)
        return lines

    def find_wrapper_calls_with_args(self) -> List[Tuple[int, str, str]]:
        """返回 (line, func_name, arg_var) — 所有函数调用点.

        调用链中含 free 的函数 (直接或间接 wrapper) 均被纳入.
        无参 wrapper 时 arg_var 为空字符串.
        """
        result = []
        seen = set()
        # 构建"有 free 的函数"集合 (直接或通过调用链)
        free_funcs = set()
        for fn in self.func_map:
            if self.find_transitive_frees(fn):
                free_funcs.add(fn)
        for i, line in enumerate(self.lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*', '#')):
                continue
            for fn in free_funcs:
                if i == self.func_map.get(fn, (0,))[0]:
                    continue
                m = re.search(
                    rf'\b{re.escape(fn)}\s*\(\s*([^)]*)\s*\)', text)
                if m:
                    key = (i, fn)
                    if key not in seen:
                        seen.add(key)
                        arg = m.group(1).strip()
                        result.append((i, fn, arg))
        return result

    def is_global_var(self, var: str) -> bool:
        """var 是否为全局变量 (不在任何函数参数列表中且无局部声明)."""
        for _, (_, _, params) in self.func_map.items():
            if var in params:
                return False
        for _, (s, e, _) in self.func_map.items():
            for i in range(s, min(e + 1, len(self.lines) + 1)):
                text = self.lines[i - 1].strip()
                if re.search(
                    rf'\b(?:char|int|void|long|short|float|double|size_t)\s+'
                    rf'\*?\s*{re.escape(var)}\s*[=;]',
                    text):
                    return False
        return True

    def enclosing(self, line: int) -> Optional[str]:
        best = None
        bs = 0
        for name, (s, e, _) in self.func_map.items():
            if s <= line <= e and s > bs:
                best = name
                bs = s
        return best

    def count_calls(self, fn: str) -> int:
        count = 0
        fn_start = self.func_map.get(fn, (0, 0, []))[0]
        for idx, line in enumerate(self.lines, start=1):
            if idx == fn_start:
                continue
            text = line.strip()
            if text.startswith(('//', '/*')):
                continue
            count += len(re.findall(rf'\b{re.escape(fn)}\s*\(', text))
        return count

    def map_param_through_chain(self, root: str, target: str,
                                param: str) -> str:
        """沿调用链 root→...→target 映射参数名.

        当 root(arg) 调用 intermediate(x) 调用 target(x) 时,
        将 root 的 arg 映射到 target 中的对应参数名.
        """
        if root == target:
            return param
        # BFS: 从 root 出发, 沿 call_graph 搜索到 target
        from collections import deque
        queue = deque([(root, param)])
        visited = {root}
        while queue:
            cur_func, cur_param = queue.popleft()
            for callee, call_line in self.call_graph.get(cur_func, []):
                if callee in visited:
                    continue
                visited.add(callee)
                # 查找调用行, 获取实参列表
                call_args = self._get_call_args(cur_func, callee, call_line)
                callee_params = self.func_map.get(callee, (0, 0, []))[2]
                # 映射 cur_param → callee 中的参数名
                mapped = cur_param
                for i, ca in enumerate(call_args):
                    ca_base = ca.strip().lstrip('*').strip()
                    if ca_base == cur_param or ca_base.lstrip('*') == cur_param:
                        if i < len(callee_params):
                            mapped = callee_params[i]
                            break
                if callee == target:
                    return mapped
                queue.append((callee, mapped))
        return ""

    def _get_call_args(self, caller: str, callee: str,
                       call_line: int) -> List[str]:
        """获取 call_line 处对 callee 的调用参数列表."""
        if call_line - 1 >= len(self.lines):
            return []
        text = self.lines[call_line - 1].strip()
        m = re.search(rf'\b{re.escape(callee)}\s*\(\s*([^)]*)\s*\)', text)
        if not m:
            return []
        args_str = m.group(1).strip()
        if not args_str:
            return []
        return [a.strip() for a in args_str.split(',')]

    def find_cb_arg_in_func(self, func: str, cb_param: str,
                            target_arg: str) -> str:
        """在 func 体内查找回调函数指针 cb_param 的调用, 返回传入的参数名.

        如 process 体内 cb(ptr), target_arg=buf, cb_param=cb,
        则返回 ptr (因为 ptr 接收的实参是 buf).
        """
        s, e, params = self.func_map.get(func, (0, 0, []))
        for i in range(s, min(e + 1, len(self.lines) + 1)):
            text = self.lines[i - 1].strip()
            if text.startswith(('//', '/*', '#')):
                continue
            m = re.search(rf'\b{re.escape(cb_param)}\s*\(\s*([^)]*)\s*\)', text)
            if m:
                cb_args = [a.strip() for a in m.group(1).split(',') if a.strip()]
                for ca in cb_args:
                    cb_base = ca.strip().lstrip('*').strip()
                    return cb_base
        return target_arg

    def find_cb_call_args(self, func: str, cb_fn: str,
                          func_params: List[str]) -> List[str]:
        """在 func 体内查找对函数指针 (类型为 cb_fn 或已知的函数指针参数) 的调用.

        返回调用时传入的实参列表 (来自 func 参数映射).
        """
        s, e, _ = self.func_map.get(func, (0, 0, []))
        for i in range(s, min(e + 1, len(self.lines) + 1)):
            text = self.lines[i - 1].strip()
            if text.startswith(('//', '/*', '#')):
                continue
            # 遍历 func 的每个函数指针参数, 检查是否有调用
            for fp in func_params:
                m = re.search(rf'\b{re.escape(fp)}\s*\(\s*([^)]*)\s*\)', text)
                if m:
                    args_str = m.group(1).strip()
                    if args_str:
                        return [a.strip() for a in args_str.split(',')]
                    return []
        return []
