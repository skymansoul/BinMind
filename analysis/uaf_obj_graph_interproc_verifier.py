"""
UAF 对象身份图跨过程验证器 — 跨函数 UAF 验证逻辑.

独立于传播算法, 专注于 use-site 验证.
"""


import re
from typing import Dict, List, Set, TYPE_CHECKING

from .uaf_obj_graph_types import ObjState, ObjectID, UafHoigVerdict

if TYPE_CHECKING:
    from .uaf_obj_graph_callgraph import HoigCallGraph, CallSite
    from .uaf_obj_graph_builder import HoigBuilder
    from .uaf_obj_graph_types import FuncObjSummary

_DEREF_PATS = ('*{v}', '{v}->', '{v}[')


def _is_deref_use(var: str, line: str) -> bool:
    """检查行中是否存在对 var 的解引用."""
    for pat in _DEREF_PATS:
        if pat.format(v=var) in line:
            return True
    return False


def verify_cross_function_uses(
    call_graph: 'HoigCallGraph',
    func_summaries: Dict[str, 'FuncObjSummary'],
    func_hoig: Dict[str, 'HoigBuilder'],
) -> List[UafHoigVerdict]:
    """验证跨函数使用: 被调用者释放参数 → 调用者继续使用.

    支持两种释放模式:
    - 直接: free(param) → 检查调用者是否 use(arg)
    - 字段: free(param->field) → 检查调用者是否 use(arg->field)
    """
    verdicts: List[UafHoigVerdict] = []

    for caller, sites in call_graph.call_sites.items():
        if caller not in call_graph.func_bodies:
            continue
        body_lines = call_graph.func_bodies[caller].split('\n')

        for cs in sites:
            callee = cs.callee
            if callee not in func_summaries:
                continue
            freed_params = _get_freed_params(
                callee, func_summaries, func_hoig, call_graph)
            params = call_graph.get_params(callee)

            for param_name in freed_params:
                # 确定参数位置和字段后缀
                field_suffix = ''
                base_param = param_name
                for param in params:
                    if param_name == param:
                        base_param = param
                        break
                    if param_name.startswith(f'{param}->'):
                        base_param = param
                        field_suffix = param_name[len(param):]
                        break
                    if param_name.startswith(f'{param}.'):
                        base_param = param
                        field_suffix = param_name[len(param):]
                        break
                else:
                    continue

                param_idx = params.index(base_param)
                if param_idx >= len(cs.args):
                    continue
                arg_var = cs.args[param_idx]
                use_target = f'{arg_var}{field_suffix}' if field_suffix else arg_var

                for later_idx in range(cs.line, len(body_lines)):
                    later_text = body_lines[later_idx].strip()
                    if _is_deref_use(use_target, later_text):
                        reassigned = _is_reassigned_after(
                            use_target.split('->')[0].split('.')[0],
                            body_lines, cs.line, later_idx + 1)
                        if not reassigned:
                            verdicts.append(UafHoigVerdict(
                                verdict='CONFIRMED',
                                confidence=0.85,
                                free_line=cs.line,
                                use_line=later_idx + 1,
                                use_var=use_target,
                                free_var=use_target,
                                reason=f'{callee} frees "{param_name}" '
                                       f'(arg="{use_target}"), '
                                       f'{caller} uses at L{later_idx+1}',
                                is_cross_func=True,
                            ))

    return verdicts


def _get_freed_params(
    callee: str,
    func_summaries: Dict[str, 'FuncObjSummary'],
    func_hoig: Dict[str, 'HoigBuilder'],
    call_graph: 'HoigCallGraph',
) -> Set[str]:
    """获取被调用者释放的参数名.

    支持两种释放模式:
    1. 直接释放参数: free(param)
    2. 字段释放: free(param->field) — 参数是结构体, 释放其字段
    """
    freed: Set[str] = set()
    if callee not in func_summaries:
        return freed
    callee_sum = func_summaries[callee]
    builder = func_hoig.get(callee)
    if not builder:
        return freed
    params = call_graph.get_params(callee)
    # 模式1: 直接参数释放
    for obj_id, _ in callee_sum.killed:
        for ptr_name, oid in builder.ptr_to_obj.items():
            if oid == obj_id and ptr_name in params:
                freed.add(ptr_name)
    # 模式2: 字段释放 (free(param->field))
    for ptr, _ in builder.free_events:
        for param in params:
            if ptr.startswith(f'{param}->') or ptr.startswith(f'{param}.'):
                freed.add(ptr)
    return freed


def _is_reassigned_after(var: str, body_lines: List[str],
                         after_line: int, before_line: int) -> bool:
    """检查变量在 after_line..before_line 之间是否被重新赋值."""
    for i in range(after_line, min(before_line, len(body_lines))):
        line = body_lines[i].strip()
        m = re.search(
            rf'{re.escape(var)}\s*=\s*(?!NULL|nullptr|0\b)', line)
        if m and '==' not in line:
            return True
        if re.search(
            rf'{re.escape(var)}\s*=\s*(malloc|calloc|realloc)', line):
            return True
    return False


__all__ = ['verify_cross_function_uses']
