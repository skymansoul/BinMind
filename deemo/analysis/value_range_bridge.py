"""
值范围桥接器 — 将 ValueRangeEngine (C源码级区间分析) 连接到
source_scanner 的检测发现, 做轻量 FP 降级。

与现有模块的关系:
  - enhanced_fp_filter.py: 操作 IR 级别候选, 需 IR 提升步骤 (重)
  - 本模块: 直接在 C 源码 + regex-based finding dict 上操作 (轻)
  - 两者互补: enhanced 用于深度分析, 本模块用于快速初筛

桥接逻辑:
  对每个 is_overflow=True 的 finding:
    1. 解析 alloc_size_expr → 找到依赖的变量
    2. 从 ValueRangeEngine 获取该变量的 [min, max]
    3. 如果 min(alloc_size) ≥ write_size → PROVABLY SAFE, 过滤
    4. 如果 max(alloc_size) < write_size → DEFINITELY OVERFLOW, 保留
    5. 否则 → UNCERTAIN, 保守保留

原则: 宁可误报, 不可漏报。只在可证明安全时过滤。
"""

import re
from typing import Any, Dict, List, Optional

from analysis.value_range import Range, INF, ValueRangeEngine
from analysis.expr_evaluator import eval_expr_impl


# 分配大小表达式中的变量引用提取
_VAR_IN_EXPR_RE = re.compile(r'\b([a-zA-Z_]\w*)\b')
# sizeof(type) 不算是变量
_SIZEOF_RE = re.compile(r'sizeof\s*\(')


def _extract_vars_from_expr(expr: str) -> List[str]:
    """从表达式中提取变量名 (排除 sizeof 中的类型名和数字)。"""
    if not expr:
        return []
    # 去掉 sizeof(...) 部分避免类型名被误识别
    cleaned = _SIZEOF_RE.sub('', expr)
    vars_found = []
    for m in _VAR_IN_EXPR_RE.finditer(cleaned):
        name = m.group(1)
        # 排除常见关键字和类型名
        if name in ('if', 'while', 'for', 'return', 'unsigned',
                     'int', 'char', 'long', 'short', 'void',
                     'size_t', 'ssize_t', 'const', 'static'):
            continue
        if name.isdigit():
            continue
        vars_found.append(name)
    return vars_found


def filter_by_value_range(
    findings: List[Dict[str, Any]],
    source: str,
) -> Dict[str, Any]:
    """对 heap overflow findings 应用值范围过滤。

    Args:
        findings: source_scanner._pair_ops 返回的 finding dict 列表
        source: C 源码字符串

    Returns:
        {filtered_count, safe_count_after, detail_parts}
    """
    if not findings:
        return {'filtered_count': 0, 'detail': 'no findings'}

    engine = ValueRangeEngine(source)
    ranges = engine.analyze()

    # 无变量范围 → 无法过滤
    if not ranges:
        return {'filtered_count': 0, 'detail': 'no variable ranges found'}

    external_vars = engine.external_vars
    filtered = 0
    detail_parts: List[str] = []

    for f in findings:
        # 只处理 is_overflow=True 的 heap overflow
        if not f.get('is_overflow', False):
            continue
        # 跳过非堆操作
        if f.get('type') not in ('write', 'array_write'):
            continue

        write_size = f.get('write_size', 0)
        if write_size <= 0:
            continue

        alloc_size_expr = f.get('alloc_size_expr', '')
        if not alloc_size_expr:
            continue

        # 策略1: alloc_size_expr 本身就是一个变量
        alloc_vars = _extract_vars_from_expr(alloc_size_expr)

        # 策略2: 用 eval_expr_impl 对 alloc_size_expr 整体求值
        alloc_range = eval_expr_impl(alloc_size_expr, ranges, external_vars)

        if alloc_range.is_unknown:
            # 无法确定范围 → 保守保留
            continue

        # 检查下界是否足够大以证明安全
        if alloc_range.lo > 0 and alloc_range.lo >= write_size:
            f['_verdict'] = 'SAFE'
            f['_filter_reason'] = (
                f'value_range: alloc_min={alloc_range}, '
                f'write_size={write_size}, provably safe')
            filtered += 1
            detail_parts.append(
                f'filter: {alloc_size_expr}∈{alloc_range}, '
                f'write={write_size}≤{alloc_range.lo}')
            continue

        # 检查上界: 如果必然溢出, 标记为确认 (不过滤)
        if alloc_range.hi < INF and alloc_range.hi < write_size:
            f['_filter_reason'] = (
                f'value_range: alloc_max={alloc_range}, '
                f'write_size={write_size}, confirmed overflow')
            # 不增加 filtered count — 这是真正的漏洞
            detail_parts.append(
                f'confirm: {alloc_size_expr}∈{alloc_range}, '
                f'write={write_size}>{alloc_range.hi}')
            continue

        # 策略3: 逐个变量检查上界约束
        for var in alloc_vars:
            if var in ranges:
                vr = ranges[var]
                # 如果变量上界被约束且写入≤上界 → 安全
                if vr.hi < INF and write_size <= vr.hi:
                    f['_verdict'] = 'SAFE'
                    f['_filter_reason'] = (
                        f'value_range: {var}∈{vr}, '
                        f'write={write_size}≤{vr.hi}')
                    filtered += 1
                    detail_parts.append(
                        f'filter: {var}∈{vr}, write={write_size}')
                    break

    return {
        'filtered_count': filtered,
        'detail': '; '.join(detail_parts) if detail_parts else 'none',
    }


def apply_value_range_quick(
    findings: List[Dict[str, Any]],
    source: str,
) -> List[Dict[str, Any]]:
    """值范围快速过滤: 对 C 源码级 findings 做 SAFE 降级。

    与 filter_by_value_range 相同逻辑, 但直接修改 findings
    并返回过滤后的列表 (SAFE 的从结果中移除)。

    设计决策: 独立函数而非修改原函数 — 允许调用方选择"标记"或"移除"。
    """
    result = filter_by_value_range(findings, source)
    # 移除 _verdict='SAFE' 的 findings
    kept = [f for f in findings if f.get('_verdict') != 'SAFE']
    return kept
