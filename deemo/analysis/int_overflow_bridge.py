"""
整数溢出桥接器 — 将 IOSV (值范围传播+守卫检测) 接入 int_overflow_detector 的
regex-based 检测, 做后处理精化.

设计决策:
  1. IOSV 做 VRP (Value Range Propagation) + 守卫检测, 比 regex 更精确
  2. 对每个 finding, 检查 IOSV 是否能证明 SAFE
  3. 对 IOSV VULN 的 finding, 确认并增强理由
  4. 只过滤 IOSV 可证明 SAFE 的, 其余保持原样 (保守)
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from analysis.int_overflow_src_verifier import IntOverflowSrcVerifier
from analysis.int_overflow_types import IovVerdict, IovResult


def refine_int_overflow_findings(
    findings: List[Dict[str, Any]],
    source: str,
) -> Dict[str, Any]:
    """对 int_overflow_detector 的发现做后处理精化.

    对每个 finding:
      1. 提取关联变量和行号
      2. 用 IOSV 验证是否有守卫保护
      3. 用 IOSV 值范围验证是否真可能溢出

    Returns: {filtered_count, confirmed_count, detail}
    """
    if not findings:
        return {'filtered_count': 0, 'confirmed_count': 0, 'detail': 'no findings'}

    # 初始化 IOSV
    verifier = IntOverflowSrcVerifier()
    iov_results: List[IovResult] = []
    try:
        iov_results = verifier.verify(source)
    except Exception:
        pass

    # 构建 {line_no: [IovResult]} 映射
    iov_by_line: Dict[int, List[IovResult]] = {}
    for r in iov_results:
        iov_by_line.setdefault(r.alloc_line, []).append(r)

    filtered = 0
    confirmed = 0
    detail_parts: List[str] = []

    for f in findings:
        line_no = f.get('line_no', 0)
        ftype = f.get('type', '')
        var_name = f.get('var', '')

        # 行级匹配
        # 检查是否有 IOSV 结果覆盖此行
        if line_no not in iov_by_line:
            continue

        for iov in iov_by_line[line_no]:
            # 变量匹配
            # IOSV 的 size_expr 与 finding 的 var 有关联
            var_match = (
                (var_name and var_name in iov.size_expr) or
                (var_name and iov.reason and var_name in iov.reason)
            )

            # 类型相关匹配 (如 mul_overflow ↔ MUL, shift_overflow ↔ SHL)
            kind_match = _kind_matches(ftype, iov)

            if not (var_match or kind_match):
                continue

            # 应用 IOSV 判定
            if iov.verdict == IovVerdict.SAFE:
                f['_iov_verdict'] = 'SAFE'
                f['_iov_reason'] = iov.reason
                if iov.guarded:
                    f['_iov_guarded'] = True
                    f['_iov_guard_line'] = iov.guard_line
                # 只过滤有强证据的 (guarded 或值范围证明不溢出)
                if iov.guarded or 'within safe bounds' in iov.reason:
                    f['_filtered'] = True
                    filtered += 1
                    detail_parts.append(
                        f'filter L{line_no} [{ftype}]: IOSV SAFE — {iov.reason}')
                    break

            elif iov.verdict == IovVerdict.VULN:
                f['_iov_confirmed'] = True
                f['_iov_reason'] = iov.reason
                if iov.value_range:
                    f['_iov_value_range'] = iov.value_range
                confirmed += 1
                detail_parts.append(
                    f'confirm L{line_no} [{ftype}]: IOSV VULN — {iov.reason}')
                break

    return {
        'filtered_count': filtered,
        'confirmed_count': confirmed,
        'detail': '; '.join(detail_parts) if detail_parts else 'none',
    }


def _kind_matches(ftype: str, iov: IovResult) -> bool:
    """检查 finding type 与 IOSV overflow_kind 是否语义匹配."""
    kind_map = {
        'mul_overflow': 'mul',
        'arith_overflow_to_alloc': 'mul',
        'alloc_expr_overflow': 'mul',
        'alloc_with_arith': 'mul',
        'struct_field_mul': 'mul',
        'shift_overflow': 'shl',
        'user_input_to_alloc': 'mul',
        'add_wrap': 'add',
    }
    expected = kind_map.get(ftype, '')
    if not expected:
        return False
    return iov.overflow_kind == expected
