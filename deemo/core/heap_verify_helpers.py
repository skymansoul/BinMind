"""

verify_candidate: 单候选精判逻辑，不依赖实例状态
split_args: 括号感知参数分割
"""


from typing import TYPE_CHECKING, Any, Dict, List

from core.abstract_engine import AbstractState

if TYPE_CHECKING:
    from core.heap_verify import VerifyResult


def verify_candidate(
    cand: Dict[str, Any],
    states: Dict[int, AbstractState],
    pseudocode: str,
) -> "VerifyResult":
    """对单个候选做精判。pseudocode 当前未使用，保留参数以兼容调用签名。"""
    # 延迟导入避免与 heap_verify 循环依赖
    from core.heap_verify import VerifyResult

    ptr = cand.get("ptr", "")
    req = cand.get("requested", 0)
    eff = cand.get("effective", 0)
    ws = cand.get("write_size")
    line_no = cand.get("write_line", cand.get("line", -1))
    code = cand.get("write_code", cand.get("code", ""))

    result = VerifyResult(
        original_type="heap-overflow",
        pointer=ptr, line_no=line_no, code_line=code,
        alloc_size=req, effective_size=eff,
    )

    # 查询抽象解释结果
    state = states.get(line_no)
    if state is None or not state.reachable:
        result.verdict = "FILTER"
        result.reason = "path unreachable per abstract interpretation"
        result.confidence = 0.05
        return result

    obj = state.heap.get_object(ptr)
    if obj is None:
        result.verdict = "UNCERTAIN"
        result.reason = "pointer not tracked in heap abstract domain"
        result.confidence = 0.50
        return result

    max_off = obj.offset_range.high
    result.max_write = max_off if max_off is not None else -1

    # 判定逻辑
    if max_off is None:
        result.verdict = "UNCERTAIN"
        result.reason = "write offset unbounded — cannot exclude overflow"
        result.confidence = 0.55
        return result

    if eff > 0 and max_off < eff:
        result.verdict = "FILTER"
        result.reason = (
            f"max_offset({max_off}) < effective_size({eff}) "
            f"[requested={req}B, {obj.alloc_func}]"
        )
        result.confidence = 0.10
        return result

    if ws is not None and eff > 0 and ws <= eff:
        result.verdict = "FILTER"
        result.reason = (
            f"write_size({ws}) <= effective_size({eff}) "
            f"[allocator alignment absorbed the gap]"
        )
        result.confidence = 0.12
        return result

    if max_off >= eff and eff > 0:
        result.verdict = "KEEP"
        result.reason = (
            f"max_offset({max_off}) >= effective_size({eff}) "
            f"— definite overflow of {max_off - eff + 1}B"
        )
        result.confidence = 0.92
        return result

    result.verdict = "UNCERTAIN"
    result.reason = "insufficient information for definitive verdict"
    result.confidence = 0.45
    return result


def split_args(s: str) -> List[str]:
    """括号感知参数分割，逗号仅在顶层深度切分。"""
    if not s.strip():
        return []
    depth, parts, cur = 0, [], []
    for ch in s:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


__all__ = ['verify_candidate', 'split_args']
