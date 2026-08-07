"""
后处理过滤器 — 对 source_scanner 的 regex-based 检测结果做值范围 FP 降级。

独立于 analysis/value_range_bridge.py:
  - 本模块: 纯 regex 提取约束, 零外部依赖, 在 source_scanner 内内联使用
  - value_range_bridge: 使用 ValueRangeEngine (流敏感变量追踪), 更精确但更重

设计决策: 分离两种实现 — 调用方按需选择"快而粗糙"或"慢而精确"。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def apply_post_filter(paired: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
    """后处理: 值范围传播过滤 (C源码级, 轻量).

    仅对 is_overflow=True 的候选做 SAFE 降级, 不改变确认漏洞.
    策略: 从源码提取变量上界约束 (MIN宏/if guard), 证明 write_size ≤ alloc_size 时降级.

    保守性保证: 只在能证明安全时才过滤. 不确定时保留.
    """
    if not paired or not source:
        return paired

# 提取变量上界约束
    # 模式1: var = MIN(expr, N)
    # 模式2: if (var > N) var = N; (上限钳位)
    var_max: Dict[str, int] = {}
    for m in re.finditer(r'(\w+)\s*=\s*MIN\s*\([^,]+,\s*(\d+)\s*\)', source):
        var_max[m.group(1)] = int(m.group(2))
    for m in re.finditer(
            r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*\1\s*=\s*\1\s*;', source):
        v, n = m.group(1), int(m.group(2))
        var_max[v] = max(var_max.get(v, 0), n)

    # 变量类型推导上界
    type_hi: Dict[str, int] = {}
    for m in re.finditer(r'(?:uint8_t|unsigned\s+char)\s+(\w+)', source):
        type_hi[m.group(1)] = 255
    for m in re.finditer(r'(?:uint16_t|unsigned\s+short)\s+(\w+)', source):
        type_hi[m.group(1)] = 65535
    for m in re.finditer(r'(?:int(?!\d)|size_t|unsigned)\s+(\w+)', source):
        type_hi[m.group(1)] = 2147483647

# 对每个 finding 做保守降级
    for item in paired:
        if not item.get('is_overflow', False):
            continue
        # 跳过非堆操作; array_write 来自循环体, 单次迭代大小不能代表总写入量
        ftype = item.get('type', '')
        if ftype not in ('write', 'heap-overflow', 'heap-buffer-overflow'):
            continue

        # 提取写入大小上界. 优先使用已聚合的 write_size (含循环展开),
        # 否则从 write_size_expr 推导单次写入上界
        w_expr = item.get('write_size_expr', '')
        w_actual = item.get('write_size', 0)
        if w_actual > 0 and (not w_expr or w_actual > _eval_expr_max(w_expr, var_max, type_hi, default=0)):
            write_max = w_actual
        elif w_expr:
            write_max = _eval_expr_max(w_expr, var_max, type_hi)
        else:
            continue
        if write_max is None:
            continue

        # 提取分配大小上界
        a_expr = item.get('alloc_size_expr', '')
        if not a_expr:
            continue
        alloc_max = _eval_expr_max(a_expr, var_max, type_hi)
        if alloc_max is None:
            continue

        # 保守判定: write_max ≤ alloc_max → SAFE (过滤)
        if write_max <= alloc_max:
            item['is_overflow'] = False
            item['filtered_by'] = 'value_range_post'
            item['filter_reason'] = (
                f'write_max({write_max}) <= alloc_max({alloc_max}) '
                f'[{w_expr} vs {a_expr}]')

    return paired


def _eval_expr_max(expr: str, var_max: Dict[str, int],
                   type_hi: Dict[str, int], default: int = None) -> Optional[int]:
    """从表达式推导最大可能值. 返回 default 表示无法推导.

    支持: 纯常量, n*C, C*n, sizeof(T), 单变量.
    """
    expr = expr.strip()
    if not expr:
        return None
    # 纯数字常量
    try:
        return int(expr)
    except ValueError:
        pass
    # sizeof 常见类型
    sizeof_vals = {
        'sizeof(int)': 4, 'sizeof(size_t)': 8, 'sizeof(void*)': 8,
        'sizeof(char)': 1, 'sizeof(short)': 2, 'sizeof(long)': 4,
        'sizeof(long long)': 8, 'sizeof(float)': 4, 'sizeof(double)': 8,
    }
    for pat, sz in sizeof_vals.items():
        if pat in expr:
            remaining = expr.replace(pat, '').strip(' *')
            if remaining and remaining in var_max:
                return var_max[remaining] * sz
            if remaining and remaining in type_hi:
                return type_hi[remaining] * sz
            return sz
    # var * C
    m = re.match(r'(\w+)\s*\*\s*(\d+)', expr)
    if m:
        var, const = m.group(1), int(m.group(2))
        vmax = var_max.get(var, type_hi.get(var))
        return vmax * const if vmax is not None else None
    # C * var
    m = re.match(r'(\d+)\s*\*\s*(\w+)', expr)
    if m:
        const, var = int(m.group(1)), m.group(2)
        vmax = var_max.get(var, type_hi.get(var))
        return const * vmax if vmax is not None else None
    # 单变量
    if expr in var_max:
        return var_max[expr]
    if expr in type_hi:
        return type_hi[expr]
    return default
