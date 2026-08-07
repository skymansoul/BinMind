"""
Copy操作约束验证器 — 对 strcpy/memcpy 类堆溢出候选执行值流约束推理.

核心方法: 追踪 alloc_sz 和 copy_sz 的值来源, 通过以下维度判定:
  1. 来源独立性: alloc_sz 和 copy_sz 是否来自不同的外部输入
  2. 守卫约束: 是否存在 if(cond) 限制 copy_sz 或 alloc_sz 的范围
  3. 常量上界: 即使变量来源未知, 是否有隐式上界 (uint16_t→65535)
  4. 仿射关系: copy_sz = alloc_sz + k 或 copy_sz = alloc_sz * c 等

与传统符号执行的区别: 不符号化内存地址, 仅追踪 size 变量值流;
  无 SMT 求解器, 使用区间代数做保守近似; 确定性可复现.

参考: SUTURE, VYPER, MIRAI tag analysis.
"""

from __future__ import annotations
import re

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate, _UNBOUNDED_COPY,
)
from core.copy_constraint_types import SizeVarOrigin, CopyVerifyResult
from core.copy_value_flow import ValueFlowExtractor, GuardConditionExtractor


def _extract_size_var_from_alloc(alloc: HeapAllocSite,
                                  ir_lines: list[str]) -> str:
    """提取 malloc(size_var) 中的变量名."""
    line = ir_lines[alloc.pc] if alloc.pc < len(ir_lines) else ''
    m = re.search(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*[),]', line)
    if m:
        var = m.group(1)
        try:
            int(var, 0)
            return ''
        except ValueError:
            return var
    return ''


def _extract_copy_size_var(store: HeapStore,
                            ir_lines: list[str]) -> str:
    """提取 memcpy/strncpy 中的大小参数变量名."""
    if store.mnemonic in ('strcpy', 'copy'):
        return ''
    line = ir_lines[store.pc] if store.pc < len(ir_lines) else ''
    m = re.search(
        r'(?:memcpy|memmove|memset|strncpy)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)',
        line)
    if m:
        var = m.group(1)
        try:
            int(var, 0)
            return ''
        except ValueError:
            return var
    return ''


def verify_copy_operation(
    alloc: HeapAllocSite,
    store: HeapStore,
    ir_lines: list[str],
) -> CopyVerifyResult:
    """验证 copy 操作是否可证伪安全或确认溢出.

    核心逻辑:
      若 alloc_sz/copy_sz 来自不同外部输入 → 攻击者可差异化控制 → 置信度提升.
      若同一输入源且有守卫约束 → 可能安全 → 置信度降低.
      若 copy_sz 类型上界 ≤ alloc_sz → 可证明安全 → FILTER.
    """
    result = CopyVerifyResult()
    flow_extractor = ValueFlowExtractor()
    guard_extractor = GuardConditionExtractor()

    alloc_size_var = _extract_size_var_from_alloc(alloc, ir_lines)
    copy_size_var = _extract_copy_size_var(store, ir_lines)

    if alloc_size_var:
        result.alloc_origin = flow_extractor.extract_origin(
            ir_lines, alloc_size_var, alloc.pc)
    else:
        result.alloc_origin = SizeVarOrigin(
            is_constant=True, constant_value=alloc.size_arg)

    if copy_size_var:
        result.copy_origin = flow_extractor.extract_origin(
            ir_lines, copy_size_var, store.pc)
    elif store.mnemonic in ('strcpy', 'strcat'):
        result.copy_origin = SizeVarOrigin(
            is_external_input=True, input_source='unbounded')
    elif store.store_size > 0:
        result.copy_origin = SizeVarOrigin(
            is_constant=True, constant_value=store.store_size)
    else:
        result.copy_origin = SizeVarOrigin()

    ao = result.alloc_origin
    co = result.copy_origin

    # 防御: None → 空 origin
    if ao is None:
        ao = result.alloc_origin = SizeVarOrigin()
    if co is None:
        co = result.copy_origin = SizeVarOrigin()

    # 1. 两者都是常量 → 对比 (考虑 store 偏移)
    if ao.is_constant and co.is_constant and ao.constant_value > 0:
        alias_off = store.offset if store.offset > 0 else 0
        effective_alloc = ao.constant_value - alias_off
        if co.constant_value <= effective_alloc:
            result.verdict = 'SAFE'
            result.confidence_adjust = -0.40
            result.reason = (
                f'常量: copy_sz({co.constant_value}) <= '
                f'effective_alloc({effective_alloc}) → 安全')
            return result
        else:
            result.verdict = 'OVERFLOW'
            result.confidence_adjust = +0.15
            result.reason = (
                f'常量: copy_sz({co.constant_value}) > '
                f'effective_alloc({effective_alloc}) → 溢出'
                + (f' (off={alias_off})' if alias_off else ''))
            return result

    # 2. 固定缓冲区 + 无界strcpy → 确定溢出
    if (ao.is_constant and ao.constant_value > 0
            and store.mnemonic in ('strcpy', 'strcat')):
        result.verdict = 'OVERFLOW'
        result.confidence_adjust = +0.15
        result.reason = (
            f'固定buf({ao.constant_value}B) + 无界strcpy → 可溢出')
        return result

    # 3. 不同外部输入源 → 高危
    if (ao.is_external_input and co.is_external_input
            and ao.input_source != 'unbounded'):
        if ao.input_source != co.input_source:
            result.verdict = 'OVERFLOW'
            result.confidence_adjust = +0.20
            result.reason = (
                f'独立输入: alloc←{ao.input_source}, '
                f'copy←{co.input_source} → 可差异化控制')
            return result

    # 4. 守卫约束检查
    var_set = set()
    if alloc_size_var:
        var_set.add(alloc_size_var)
    if copy_size_var:
        var_set.add(copy_size_var)
    if ao.derived_vars:
        var_set.update(ao.derived_vars)
    if co.derived_vars:
        var_set.update(co.derived_vars)

    guards = guard_extractor.extract(
        ir_lines, var_set, alloc.pc, store.pc)
    if guards:
        result.guard_found = True
        result.guard_detail = str(guards)
        for _g_var, g_list in guards.items():
            for bound, op, gtype in g_list:
                if (gtype == 'upper_bound' and ao.is_constant
                        and bound <= ao.constant_value):
                    result.verdict = 'SAFE'
                    result.confidence_adjust = -0.35
                    result.reason = (
                        f'守卫: ≤{bound} ≤ alloc({ao.constant_value}) → 安全')
                    return result

    # 5. 类型上界保护
    if (co.has_upper_bound and ao.is_constant
            and co.upper_bound <= ao.constant_value):
        result.verdict = 'SAFE'
        result.confidence_adjust = -0.25
        result.reason = (
            f'类型上界: copy上限({co.upper_bound}) ≤ '
            f'alloc({ao.constant_value}) → 安全')
        return result

    # 6. 无法确定
    result.verdict = 'UNCERTAIN'
    result.reason = '值流关联不足以判定, 保留候选'
    return result


def filter_by_copy_constraint(
    candidates: list[HeapOverflowCandidate],
    ir_lines: list[str],
) -> tuple[list[HeapOverflowCandidate], dict]:
    """对候选列表执行 copy 约束验证, 返回 (filtered, stats).

    仅处理 copy 操作候选 (strcpy/memcpy/strncpy/memset/copy).
    """
    stats = {
        'input': len(candidates), 'verified': 0,
        'safe_proved': 0, 'overflow_confirmed': 0, 'uncertain': 0,
        'confidence_adjustments': 0, 'skip_non_copy': 0,
    }
    kept = []
    for c in candidates:
        store = getattr(c, 'overflow_store', None)
        if store is None or store.mnemonic not in (
                'strcpy', 'memcpy', 'strncpy', 'memset',
                'strcat', 'strncat', 'copy'):
            kept.append(c)
            stats['skip_non_copy'] += 1
            continue
        stats['verified'] += 1
        result = verify_copy_operation(
            c.alloc_site, c.overflow_store, ir_lines)
        if result.verdict == 'SAFE':
            stats['safe_proved'] += 1
            continue
        elif result.verdict == 'OVERFLOW':
            stats['overflow_confirmed'] += 1
            c.confidence = min(0.95, c.confidence + result.confidence_adjust)
            kept.append(c)
        else:
            stats['uncertain'] += 1
            kept.append(c)
    stats['output'] = len(kept)
    return kept, stats


__all__ = [
    'SizeVarOrigin', 'CopyVerifyResult',
    'ValueFlowExtractor', 'GuardConditionExtractor',
    'verify_copy_operation', 'filter_by_copy_constraint',
]
