"""
HOIG Propagator — 跨函数堆对象身份传播.

核心创新: 对象身份 (ObjectID) 而非指针名称 跨函数传播.

与现有 InterProcLifetimeAnalyzer 的关键区别:
  现有: KILL/GEN 摘要 — 粗粒度, 无法追踪 realloc 对象延续
  HOIG:  对象身份图传播 — 精确追踪每个 ObjectID 的生命周期状态
         跨调用边界, 包括 realloc 旧指针→新指针的身份延续.

传播算法:
  1. 构建调用图 (HoigCallGraph), 自动提取调用点与参数绑定
  2. 为每个函数构建 FuncObjSummary (通过 HoigBuilder)
  3. 工作列表固定点迭代:
     (a) 被调用者释放参数对象 → 调用者在调用点后该对象 FREED
     (b) 被调用者返回对象 → 调用者获得该对象身份 (LIVE)
     (c) realloc 对象身份延续
  4. 收敛后重建 HOIG, 验证跨函数使用点
"""


import re
from typing import Dict, List, Optional, Set, Tuple

from .uaf_hoig_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from .uaf_hoig_builder import HoigBuilder
from .uaf_hoig_callgraph import HoigCallGraph, CallSite

_RE_CALL = re.compile(
    r'(\w[\w]*)\s*=\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_RE_PLAIN_CALL = re.compile(
    r'(?:^|[;{}])\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_DEREF_PATS = ('*{v}', '{v}->', '{v}[')


def _is_deref_use(var: str, line: str) -> bool:
    """检查行中是否存在对 var 的解引用."""
    for pat in _DEREF_PATS:
        if pat.format(v=var) in line:
            return True
    return False


class HoigPropagator:
    """跨函数 HOIG 传播器.

    追踪 ObjectID 沿调用链的生命周期状态.
    """

    def __init__(self):
        self.call_graph = HoigCallGraph()
        self.func_summaries: Dict[str, FuncObjSummary] = {}
        self.func_hoig: Dict[str, HoigBuilder] = {}
        # 传播状态: func → {ObjectID → ObjState}
        self.propagated: Dict[str, Dict[ObjectID, ObjState]] = {}
        # 跨函数参数绑定: func → {param_name → ObjectID}
        self.param_bindings: Dict[str, Dict[str, ObjectID]] = {}
        self._max_iterations = 50

    def register_function(self, name: str, pseudocode: str):
        """注册函数体并自动提取调用关系."""
        self.call_graph.register(name, pseudocode)

    def register_call(self, caller: str, callee: str):
        """手工补充调用关系 (调用图自动提取的补充)."""
        if callee not in self.call_graph.func_bodies:
            return
        if self.call_graph.find_call_lines(caller, callee):
            return
        site = CallSite(callee=callee, line=0, lhs='', args=[], is_assign=False)
        self.call_graph.call_sites.setdefault(caller, []).append(site)
        self.call_graph.callee_to_callers.setdefault(
            callee, []).append((caller, site))

    def analyze_all(self) -> List[UafHoigVerdict]:
        """全量分析: 构建HOIG → 传播 → 验证."""
        # Phase 0: 为每个函数的参数创建合成 ObjectID
        self._init_param_object_ids()

        # Phase 1: 构建每个函数的 HOIG (带参数 ObjectID 注入)
        for fname, body in self.call_graph.func_bodies.items():
            builder = HoigBuilder()
            entry = self.param_bindings.get(fname)
            _, _, local_verdicts = builder.build(body, fname, entry)
            self.func_hoig[fname] = builder
            self.func_summaries[fname] = builder.get_summary()

        # Phase 2: 跨函数传播
        self._propagate_lifetimes()

        # Phase 3: 收集所有判定
        all_verdicts: List[UafHoigVerdict] = []
        for fname, builder in self.func_hoig.items():
            body = self.call_graph.func_bodies.get(fname, '')
            entry = self.param_bindings.get(fname)
            rebuild = HoigBuilder()
            _, _, verdicts = rebuild.build(body, fname, entry)
            for v in verdicts:
                v.is_cross_func = self._is_cross_function_use(
                    fname, v.use_var, v.use_line)
            all_verdicts.extend(verdicts)

        # Phase 4: 跨函数使用验证
        cross_verdicts = self._verify_cross_function_uses()
        all_verdicts.extend(cross_verdicts)

        return all_verdicts

    def _init_param_object_ids(self):
        """为每个函数的指针参数创建合成 ObjectID.

        被调用者函数的参数 (如 destroy(char *obj)) 在函数内没有 malloc,
        但 free(obj) 仍需关联到一个 ObjectID 才能生成 killed 摘要.
        合成 ObjectID 使用 (line=0, func=callee_name) 作为标识.
        """
        for fname in self.call_graph.func_bodies:
            params = self.call_graph.get_params(fname)
            if not params:
                continue
            bindings: Dict[str, ObjectID] = {}
            for param in params:
                oid = ObjectID(alloc_line=0, alloc_func=fname,
                               context_hash=hash(param) & 0xFFFF)
                bindings[param] = oid
            self.param_bindings[fname] = bindings

    def _propagate_lifetimes(self):
        """固定点迭代传播对象生命周期."""
        for fname in self.call_graph.func_bodies:
            self.propagated[fname] = {}

        worklist = list(self.call_graph.func_bodies.keys())
        iteration = 0

        while worklist and iteration < self._max_iterations:
            iteration += 1
            fname = worklist.pop(0)
            sites = self.call_graph.get_call_sites(fname)
            if not sites:
                continue

            changed = False
            for cs in sites:
                callee = cs.callee
                if callee not in self.func_summaries:
                    continue
                callee_sum = self.func_summaries[callee]
                caller_builder = self.func_hoig[fname]

                # 规则(a): 被调用者释放参数 → 调用者感知 FREED
                for obj_id, kill_line in callee_sum.killed:
                    # 查找传递该 ObjectID 的实参
                    for arg in cs.args:
                        if arg in caller_builder.ptr_to_obj:
                            caller_oid = caller_builder.ptr_to_obj[arg]
                            if caller_oid == obj_id or self._oids_match(
                                    caller_oid, obj_id, fname, callee, cs):
                                prev = self.propagated[fname].get(obj_id)
                                if prev != ObjState.FREED:
                                    self.propagated[fname][obj_id] = ObjState.FREED
                                    changed = True

                # 规则(b): 被调用者返回对象 → 调用者获得 LIVE
                if callee_sum.returned is not None and cs.lhs:
                    ret_oid = callee_sum.returned
                    prev = self.propagated[fname].get(ret_oid)
                    if prev != ObjState.LIVE:
                        self.propagated[fname][ret_oid] = ObjState.LIVE
                        changed = True
                    if cs.lhs in caller_builder.ptr_to_obj:
                        caller_builder.ptr_to_obj[cs.lhs] = ret_oid
                        changed = True

            if changed:
                for callee in set(cs.callee for cs in sites):
                    if callee in self.call_graph.func_bodies:
                        worklist.append(callee)

    def _oids_match(self, caller_oid: ObjectID, callee_oid: ObjectID,
                    caller: str, callee: str, cs: CallSite) -> bool:
        """判断调用者和被调用者的 ObjectID 是否指向同一对象."""
        params = self.call_graph.get_params(callee)
        for i, param in enumerate(params):
            if i < len(cs.args) and cs.args[i] in self.func_hoig[caller].ptr_to_obj:
                arg_oid = self.func_hoig[caller].ptr_to_obj[cs.args[i]]
                param_oid = self.func_hoig[callee].ptr_to_obj.get(param)
                if param_oid and arg_oid == caller_oid and param_oid == callee_oid:
                    return True
        return False

    def _is_cross_function_use(self, func_name: str, var: str,
                               line: int) -> bool:
        """检查 use 是否涉及跨函数传播的对象."""
        if func_name not in self.func_hoig:
            return False
        builder = self.func_hoig[func_name]
        oid = builder.ptr_to_obj.get(var)
        if oid is None:
            return False
        return oid.alloc_func != func_name

    def _verify_cross_function_uses(self) -> List[UafHoigVerdict]:
        """验证跨函数使用: 被调用者释放参数 → 调用者继续使用."""
        from .uaf_hoig_interproc_verifier import verify_cross_function_uses
        return verify_cross_function_uses(
            self.call_graph, self.func_summaries, self.func_hoig)

    @staticmethod
    def _find_call_lines(func_body: str, callee: str) -> List[int]:
        """在函数体文本中查找调用 callee 的行号."""
        lines: List[int] = []
        for lineno, raw in enumerate(func_body.split('\n'), 1):
            line = raw.strip()
            m = _RE_CALL.search(line)
            if m and m.group(2) == callee:
                lines.append(lineno - 1)
                continue
            m2 = _RE_PLAIN_CALL.search(line)
            if m2 and m2.group(1) == callee:
                lines.append(lineno - 1)
        return lines

    @staticmethod
    def _extract_call_lhs(line: str) -> str:
        m = _RE_CALL.search(line)
        return m.group(1) if m else ''

    @staticmethod
    def _extract_call_args(line: str) -> List[str]:
        m = _RE_CALL.search(line)
        if not m:
            return []
        args_str = m.group(3)
        return [a.strip() for a in args_str.split(',') if a.strip()]


# 延迟导入 HoigCrossFuncVerifier 避免循环依赖
def _get_cross_verifier():
    from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier
    return HoigCrossFuncVerifier


__all__ = ['HoigPropagator']
