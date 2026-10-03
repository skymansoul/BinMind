# 格式化字符串调用点上下文验证
# 技术问题: 格式串经函数参数传递时, 单个调用点无法判定安全 —
#   wrapper 内 printf(fmt) 的 fmt 来自参数槽, 一律报告产生误报,
#   而攻击者可控性取决于调用点实参来源.
# 解决手段: 汇总 callee 的所有调用点实参来源,
#   全为常量字符串/常量 → 格式串不可被外部控制 → 标记可抑制.
# 与堆溢出值流耦合的思想同构: 跨调用点关联而非逐点孤立判定.
from typing import Dict, List, Optional, Tuple


def validate_param_slots(findings: List,
                         call_sites: Dict[str, List[Tuple[int, str]]],
                         enabled: bool = True):
    """对参数槽来源的格式串 finding 做调用点上下文验证.

    findings: FmtStrFinding 列表 (原地标记 is_false_positive)
    call_sites: {callee: [(call_idx, fmt_arg_source)]}
    enabled: 关闭时恢复逐调用点判定 (消融基线)
    """
    if not enabled:
        return
    for f in findings:
        if not f.fmt_source.startswith('param_slot'):
            continue
        sites = call_sites.get(f.function_name)
        if not sites:
            continue
        if all(src in ('constant_string', 'constant')
               for _, src in sites):
            f.is_false_positive = True
            f.false_positive_reason = (
                f"调用点上下文: {len(sites)} 处调用实参均为常量, "
                f"格式串不可被外部控制")
            f.severity = f.severity.__class__.INFO
            f.confidence = min(f.confidence, 0.15)
