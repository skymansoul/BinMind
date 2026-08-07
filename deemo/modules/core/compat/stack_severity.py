# coding: utf-8
"""栈溢出严重度分级 — canary 感知 + 溢出距离 + 写入目标加权.

stack_overflow_analyzer 做二元检测. 本模块做严重度分级:
  - canary 存在 → 降权 (绕过需要信息泄露)
  - 溢出距离大 (>2x 缓冲区) → 升权 (更可能是攻击而非巧合)
  - 写入目标是返回地址区域 → 极高危 (直接控制 EIP/RIP)
  - 写入目标是局部变量区域 → 中危 (可能篡改相邻变量)

分级: CRITICAL (可直接劫持控制流) / HIGH (需信息泄露绕过canary) /
       MEDIUM (溢出但利用条件苛刻) / LOW (微小溢出或不影响控制流)
"""

from typing import Any, Dict, List


def grade_severity(
    buffer_size: int,
    write_size: int,
    has_canary: bool = False,
    overflow_distance: int = 0,
    write_target_type: str = 'local_vars',  # 'return_addr' | 'local_vars' | 'saved_regs'
    is_user_controlled: bool = False,
) -> Dict[str, Any]:
    """对单个栈溢出候选做严重度分级.

    buffer_size: 栈缓冲区声明大小
    write_size: 实际写入大小
    has_canary: 函数是否有栈保护
    overflow_distance: 溢出量 = write_size - buffer_size
    write_target_type: 写入目标区域类型
    is_user_controlled: 写入数据是否来自外部输入
    """
    overflow_dist = max(0, write_size - buffer_size) if overflow_distance == 0 else overflow_distance
    base_score = 0.0

    # 因子 1: 溢出距离
    if overflow_dist <= 0:
        return {'severity': 'NONE', 'score': 0.0, 'verdict': 'no overflow'}
    if overflow_dist >= buffer_size * 2:
        base_score += 0.40  # 严重溢出
    elif overflow_dist >= buffer_size:
        base_score += 0.25
    elif overflow_dist >= 16:
        base_score += 0.15
    else:
        base_score += 0.05  # 微小溢出

    # 因子 2: 写入目标
    target_weights = {
        'return_addr': 0.40,   # 直接覆盖返回地址 → 控制流劫持
        'saved_regs': 0.30,    # 覆盖保存的寄存器 → 间接控制流
        'local_vars': 0.15,    # 覆盖相邻局部变量 → 数据篡改
        'padding': 0.05,       # 仅填充区域 → 低影响
    }
    base_score += target_weights.get(write_target_type, 0.10)

    # 因子 3: 外部可控
    if is_user_controlled:
        base_score += 0.15

    # 因子 4: canary 降权
    if has_canary:
        base_score *= 0.60  # canary 使利用难度显著上升
        if base_score >= 0.40:
            # 即使有 canary, 若溢出足够大仍可能通过信息泄露绕过
            pass

    score = min(1.0, base_score)

    if score >= 0.60:
        severity = 'CRITICAL'
    elif score >= 0.35:
        severity = 'HIGH'
    elif score >= 0.15:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    return {
        'severity': severity,
        'score': round(score, 2),
        'overflow_distance': overflow_dist,
        'buffer_size': buffer_size,
        'write_size': write_size,
        'has_canary': has_canary,
        'target_type': write_target_type,
        'user_controlled': is_user_controlled,
        'verdict': (f'栈溢出 {overflow_dist}B (缓冲区{buffer_size}B), '
                   f'{"有" if has_canary else "无"}canary, '
                   f'{"外部可控" if is_user_controlled else "内部数据"}, '
                   f'严重度:{severity}'),
    }


def batch_grade(candidates: List) -> List[Dict]:
    """对 stack_overflow_analyzer 的输出批量分级."""
    results = []
    for c in candidates:
        bs = getattr(c, 'buffer_size', 0)
        ws = getattr(c, 'write_size', 0)
        canary = getattr(c, 'has_canary', False)
        ctrl = getattr(c, 'is_user_controlled', False)
        r = grade_severity(bs, ws, canary,
                          overflow_distance=ws - bs if ws > bs else 0,
                          is_user_controlled=ctrl)
        r['func_addr'] = getattr(c, 'func_addr', 0)
        r['write_site'] = getattr(c, 'write_site', 0)
        results.append(r)
    results.sort(key=lambda r: -r['score'])
    return results


def severity_summary(results: List[Dict]) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {}
    for r in results:
        s = r.get('severity', 'UNKNOWN')
        by_sev[s] = by_sev.get(s, 0) + 1
    return {
        'total': len(results),
        'by_severity': by_sev,
        'critical_high': sum(by_sev.get(s, 0) for s in ('CRITICAL', 'HIGH')),
        'avg_score': round(sum(r['score'] for r in results) / max(1, len(results)), 2),
    }
