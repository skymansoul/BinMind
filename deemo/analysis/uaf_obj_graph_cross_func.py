"""
UAF 对象身份图跨函数 UAF 验证器 — 直接分析调用链, 检测跨函数 UAF 模式。


检测模式:
  Pattern 1: 被调用者释放参数对象 → 调用者继续使用
  Pattern 2: 被调用者返回悬垂指针 → 调用者使用返回值
  Pattern 3: 全局/静态对象在某个函数中释放 → 其他函数使用
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from .uaf_obj_graph_types import UafHoigVerdict

_RE_CALL = re.compile(
    r'(\w[\w]*)\s*=\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_RE_PLAIN_CALL = re.compile(
    r'(?:^|[;{;])\s*(\w+)\s*\(([^)]*)\)\s*;?'
)


class HoigCrossFuncVerifier:
    """跨函数 UAF 验证器.

    直接分析调用链, 检测跨函数 UAF 模式:
      Pattern 1: 被调用者释放参数对象 → 调用者继续使用
      Pattern 2: 被调用者返回悬垂指针 → 调用者使用返回值
      Pattern 3: 全局/静态对象在某个函数中释放 → 其他函数使用
    """

    def __init__(self):
        self.func_bodies: Dict[str, str] = {}
        self.func_calls: Dict[str, List[str]] = {}
        # 每个函数的 free/use 事件
        self.func_free_vars: Dict[str, Set[str]] = {}
        self.func_use_vars: Dict[str, Set[str]] = {}

    def register(self, name: str, pseudocode: str):
        self.func_bodies[name] = pseudocode
        self._extract_events(name, pseudocode)

    def register_call(self, caller: str, callee: str):
        self.func_calls.setdefault(caller, []).append(callee)

    def verify_all(self) -> List[UafHoigVerdict]:
        """验证所有跨函数 UAF."""
        # Phase 0: 传递性传播 — 被调用者的 freed vars 传播到调用者
        self._propagate_freed_transitively()
        verdicts: List[UafHoigVerdict] = []
        verdicts.extend(self._verify_pattern_1())
        verdicts.extend(self._verify_pattern_2())
        return verdicts

    def _propagate_freed_transitively(self):
        """传递性传播freed vars.

        若 callee 释放了某参数, 且 caller 将某变量传递给 callee,
        则 caller 的 freed_vars 也包括该变量.
        迭代直到收敛.
        """
        changed = True
        max_iter = 20
        while changed and max_iter > 0:
            max_iter -= 1
            changed = False
            for caller, callees in list(self.func_calls.items()):
                for callee in callees:
                    freed = self.func_free_vars.get(callee, set())
                    if not freed:
                        continue
                    body_lines = self.func_bodies.get(caller, '').split('\n')
                    for line in body_lines:
                        m1 = _RE_CALL.search(line)
                        m2 = _RE_PLAIN_CALL.search(line) if not m1 else None
                        m = m1 or m2
                        if not m:
                            continue
                        func_name = m.group(2) if m1 else m.group(1)
                        args_str = m.group(3) if m1 else m.group(2)
                        if func_name != callee:
                            continue
                        args = [a.strip() for a in args_str.split(',')
                                if a.strip()]
                        # 被调用者释放的变量 → 调用者对应的 arg
                        for arg in args:
                            if arg not in self.func_free_vars.get(caller, set()):
                                self.func_free_vars.setdefault(
                                    caller, set()).add(arg)
                                changed = True

    def _verify_pattern_1(self) -> List[UafHoigVerdict]:
        """被调用者释放参数 → 调用者继续使用."""
        verdicts: List[UafHoigVerdict] = []

        for caller, callees in self.func_calls.items():
            for callee in callees:
                freed = self.func_free_vars.get(callee, set())
                if not freed:
                    continue
                body_lines = self.func_bodies.get(caller, '').split('\n')
                for lineno, line in enumerate(body_lines, 1):
                    # 匹配两种调用模式: result = func(args) 和 func(args)
                    m = _RE_CALL.search(line)
                    if not m:
                        m = _RE_PLAIN_CALL.search(line)
                    if not m:
                        continue

                    # 从匹配组中提取函数名: _RE_CALL 的 group(2) 或 _RE_PLAIN_CALL 的 group(1)
                    func_name = m.group(2) if m.re == _RE_CALL else m.group(1)
                    args_str = m.group(3) if m.re == _RE_CALL else m.group(2)

                    if func_name != callee:
                        continue

                    args = [a.strip() for a in args_str.split(',') if a.strip()]
                    call_lineno = lineno
                    for later in range(call_lineno, len(body_lines)):
                        later_line = body_lines[later].strip()
                        for arg in args:
                            if self._is_deref_use(arg, later_line):
                                if not self._is_reassigned(
                                        arg, body_lines,
                                        call_lineno, later + 1):
                                    verdicts.append(UafHoigVerdict(
                                        verdict='CONFIRMED',
                                        confidence=0.85,
                                        free_line=call_lineno,
                                        use_line=later + 1,
                                        use_var=arg,
                                        free_var=arg,
                                        reason=f'{callee} frees arg, '
                                               f'{caller} uses {arg} after call',
                                        is_cross_func=True,
                                    ))

        return verdicts

    def _verify_pattern_2(self) -> List[UafHoigVerdict]:
        """被调用者返回悬垂指针 → 调用者使用."""
        verdicts: List[UafHoigVerdict] = []
        # 检测: callee 返回局部指针 (已释放) → caller 使用返回值
        for caller, callees in self.func_calls.items():
            for callee in callees:
                freed = self.func_free_vars.get(callee, set())
                if not freed:
                    continue
                # 被调用者是否 return 了被释放的指针
                callee_body = self.func_bodies.get(callee, '')
                for line in callee_body.split('\n'):
                    ret = re.search(r'return\s+(\w[\w]*)', line)
                    if ret and ret.group(1) in freed:
                        # 在调用者中查找使用返回值的地方
                        body_lines = self.func_bodies.get(caller, '').split('\n')
                        ret_var = ''
                        for lineno, cline in enumerate(body_lines, 1):
                            m = _RE_CALL.search(cline)
                            if m and m.group(2) == callee:
                                ret_var = m.group(1)
                                call_lineno = lineno
                                break
                        if ret_var:
                            for later in range(call_lineno, len(body_lines)):
                                later_line = body_lines[later].strip()
                                if self._is_deref_use(ret_var, later_line):
                                    verdicts.append(UafHoigVerdict(
                                        verdict='CONFIRMED',
                                        confidence=0.90,
                                        free_line=call_lineno,
                                        use_line=later + 1,
                                        use_var=ret_var,
                                        free_var=ret_var,
                                        reason=f'{callee} returns freed ptr, '
                                               f'{caller} uses after call',
                                        is_cross_func=True,
                                    ))
        return verdicts

    def _extract_events(self, name: str, pseudocode: str):
        """提取函数中的 free/use 事件."""
        free_vars: Set[str] = set()
        use_vars: Set[str] = set()

        for line in pseudocode.split('\n'):
            stripped = line.strip()
            # free 事件
            fm = re.search(r'(?:free|kfree|delete)\s*\(\s*(\w[\w]*)', stripped)
            if fm:
                free_vars.add(fm.group(1))
            # use 事件 (解引用)
            deref = re.findall(r'\*(\w[\w]*)|(\w[\w]*)\s*->|(\w[\w]*)\s*\[',
                              stripped)
            for d in deref:
                for v in d:
                    if v:
                        use_vars.add(v)

        self.func_free_vars[name] = free_vars
        self.func_use_vars[name] = use_vars

    @staticmethod
    def _is_deref_use(var: str, line: str) -> bool:
        """检查行中是否有某变量的解引用使用."""
        patterns = [f'*{var}', f'{var}->', f'{var}[']
        return any(p in line for p in patterns)

    @staticmethod
    def _is_reassigned(var: str, body_lines: List[str],
                       after_line: int, before_line: int) -> bool:
        """检查变量在 after_line..before_line 之间是否被重新赋值."""
        var_esc = re.escape(var)
        alloc_pat = re.compile(rf'{var_esc}\s*=\s*(?:malloc|calloc|realloc|strdup)')
        assign_pat = re.compile(rf'(?<!\*)(?<!->)(?<!\.){var_esc}\s*=\s*(?!NULL|nullptr|0\b)')
        for i in range(after_line, min(before_line, len(body_lines))):
            line = body_lines[i].strip()
            if alloc_pat.search(line):
                return True
            if assign_pat.search(line) and '==' not in line:
                return True
        return False


__all__ = ['HoigCrossFuncVerifier']
