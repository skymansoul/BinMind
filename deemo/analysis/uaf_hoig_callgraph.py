"""
HOIG Call Graph — 跨函数调用图构建与查询.

从伪代码自动提取调用点, 替代手工 register_call.
解析函数签名获取真实参数名, 替代 arg0/arg1 位置绑定.
支持赋值调用 (result = func(args)) 和裸调用 (func(args);).
"""


import re
from typing import Dict, List, Optional, Tuple


_RE_FUNC_DEF = re.compile(
    r'(?:[\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)'
)
_RE_ASSIGN_CALL = re.compile(
    r'(\w[\w]*)\s*=\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_RE_PLAIN_CALL = re.compile(
    r'(?:^|[;{}])\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_RE_RETURN = re.compile(r'return\s+(\w[\w]*)\s*;?')

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'kmalloc', 'kzalloc',
                'vmalloc', 'kcalloc', 'strdup'}
_FREE_FUNCS = {'free', 'kfree', 'delete'}


class CallSite:
    """单个调用点信息."""
    __slots__ = ('callee', 'line', 'lhs', 'args', 'is_assign')

    def __init__(self, callee: str, line: int, lhs: str,
                 args: List[str], is_assign: bool):
        self.callee = callee
        self.line = line
        self.lhs = lhs
        self.args = args
        self.is_assign = is_assign


class HoigCallGraph:
    """调用图: 自动从伪代码提取调用关系与参数绑定."""

    def __init__(self):
        self.func_bodies: Dict[str, str] = {}
        self.func_params: Dict[str, List[str]] = {}
        self.call_sites: Dict[str, List[CallSite]] = {}
        self.callee_to_callers: Dict[str, List[Tuple[str, CallSite]]] = {}

    def register(self, name: str, pseudocode: str):
        """注册函数并自动提取参数与调用点."""
        self.func_bodies[name] = pseudocode
        self.func_params[name] = self._extract_params(pseudocode)
        sites = self._extract_call_sites(pseudocode)
        self.call_sites[name] = sites
        for cs in sites:
            self.callee_to_callers.setdefault(
                cs.callee, []).append((name, cs))

    def find_call_lines(self, caller: str, callee: str) -> List[int]:
        """查找 caller 中调用 callee 的行号列表."""
        lines = []
        for cs in self.call_sites.get(caller, []):
            if cs.callee == callee:
                lines.append(cs.line)
        return lines

    def get_call_sites(self, caller: str,
                       callee: Optional[str] = None) -> List[CallSite]:
        """获取调用点, 可按 callee 过滤."""
        sites = self.call_sites.get(caller, [])
        if callee:
            return [cs for cs in sites if cs.callee == callee]
        return sites

    def get_callers(self, callee: str) -> List[Tuple[str, CallSite]]:
        """获取所有调用 callee 的 (caller_name, CallSite)."""
        return self.callee_to_callers.get(callee, [])

    def get_params(self, func_name: str) -> List[str]:
        """获取函数参数名列表."""
        return self.func_params.get(func_name, [])

    def bind_params(self, callee: str,
                    call_args: List[str]) -> Dict[str, str]:
        """将调用实参绑定到被调用者形参名.

        返回 {param_name: arg_var} 映射.
        """
        params = self.func_params.get(callee, [])
        bindings: Dict[str, str] = {}
        for i, param in enumerate(params):
            if i < len(call_args):
                bindings[param] = call_args[i]
        return bindings

    def has_returned_ptr(self, func_name: str) -> Optional[str]:
        """检查函数是否 return 了某个变量."""
        body = self.func_bodies.get(func_name, '')
        for line in body.split('\n'):
            m = _RE_RETURN.search(line.strip())
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _extract_params(pseudocode: str) -> List[str]:
        """从伪代码第一行提取函数参数名."""
        first_line = pseudocode.split('\n')[0].strip()
        m = _RE_FUNC_DEF.search(first_line)
        if not m:
            return []
        params_str = m.group(2).strip()
        if not params_str or params_str == 'void':
            return []
        params: List[str] = []
        for raw in params_str.split(','):
            raw = raw.strip()
            parts = raw.split()
            if not parts:
                continue
            param_name = parts[-1].lstrip('*')
            params.append(param_name)
        return params

    @staticmethod
    def _extract_call_sites(pseudocode: str) -> List[CallSite]:
        """从函数体提取所有调用点."""
        sites: List[CallSite] = []
        lines = pseudocode.split('\n')
        seen_lines: set = set()

        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            m = _RE_ASSIGN_CALL.search(line)
            if m:
                lhs, callee, args_str = m.group(1), m.group(2), m.group(3)
                if callee in _ALLOC_FUNCS or callee in _FREE_FUNCS:
                    continue
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                key = (lineno, callee)
                if key not in seen_lines:
                    seen_lines.add(key)
                    sites.append(CallSite(callee, lineno, lhs, args, True))
                continue

            m = _RE_PLAIN_CALL.search(line)
            if m:
                callee, args_str = m.group(1), m.group(2)
                if callee in _ALLOC_FUNCS or callee in _FREE_FUNCS:
                    continue
                if callee in ('if', 'for', 'while', 'switch', 'sizeof',
                              'return', 'else'):
                    continue
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                key = (lineno, callee)
                if key not in seen_lines:
                    seen_lines.add(key)
                    sites.append(CallSite(callee, lineno, '', args, False))

        return sites


__all__ = ['HoigCallGraph', 'CallSite']
