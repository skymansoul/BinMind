# -*- coding: utf-8 -*-
"""格式化字符串漏洞的量化置信度评分 — 替代二值判定, 输出连续风险分数.

原 format_string_detector 做二元 exploitable/not 判断.
本模块增加: (a) 格式符危险度加权, (b) 污点源距离衰减,
(c) FORTIFY_SOURCE 绕过检测, 综合产出 [0,1] 置信度分数.

评分公式: score = base_score × taint_factor × fortify_bypass_bonus
  base_score: 格式符危险度加权平均 (0=无危险符, 1=含%n+位置参数)
  taint_factor: 外部输入=1.0, 内部数据=0.3, 未知=0.5
  fortify_bypass: 含位置参数 %10$n → ×1.3 (绕过 FORTIFY_SOURCE)
"""

from typing import Any, Dict, List

# 格式符危险权重 — 基于利用难度和影响
_SPECIFIER_WEIGHTS = {
    '%n':   1.0,    # 任意地址写
    '%hn':  0.9,    # 半字写 (更精确)
    '%hhn': 0.85,   # 字节写 (最精确, 逐字节覆写GOT)
    '%ln':  0.8,    # 长字写
    '%s':   0.5,    # 栈泄露 (信息泄露)
    '%x':   0.25,   # 栈泄露 (hex dump)
    '%p':   0.35,   # 指针泄露 (ASLR 绕过辅助)
    '%d':   0.05,   # 无害
    '%u':   0.05,
    '%c':   0.05,
}

# 位置参数绕过 FORTIFY 的额外乘数
_FORTIFY_BYPASS_MULTIPLIER = 1.30


def compute_confidence(
    format_string: str,
    taint_source_type: str = 'unknown',
    taint_distance: int = 0,
) -> Dict[str, Any]:
    """计算格式字符串漏洞的连续置信度.

    返回 {'score': float, 'max_danger': str, 'has_n_write': bool,
           'has_leak': bool, 'fortify_bypass': bool, 'verdict': str}
    """
    max_weight = 0.0
    max_spec = ''
    has_n_write = False
    has_leak = False
    fortify_bypass = False
    import re
    weighted_sum = 0.0
    spec_count = 0

    for spec, weight in _SPECIFIER_WEIGHTS.items():
        # 直接匹配: %n, %s 等
        matched = spec in format_string
        # 位置参数匹配: %10$n 中的 %n 不会以字面出现, 需用正则
        if not matched and spec.startswith('%') and len(spec) == 2:
            # spec = '%n' → 匹配 %\d+\$n
            letter = spec[1]  # 'n', 's', 'x', 'p'...
            if re.search(rf'%\d+\${letter}', format_string):
                matched = True
        if matched:
            spec_count += 1
            weighted_sum += weight
            if weight > max_weight:
                max_weight = weight
                max_spec = spec
            if spec in ('%n', '%hn', '%hhn', '%ln', '%lln'):
                has_n_write = True
            if spec in ('%s', '%x', '%p'):
                has_leak = True

    # 检测位置参数 (如 %10$n)
    if re.search(r'%\d+\$', format_string):
        fortify_bypass = True

    # base_score: 加权平均危险度
    base_score = weighted_sum / max(1, spec_count) if spec_count > 0 else 0.0
    # 若同时含 %n 和位置参数, 危险度提升
    if has_n_write and fortify_bypass:
        base_score = min(1.0, base_score * _FORTIFY_BYPASS_MULTIPLIER)

    # taint_factor
    taint_map = {'external_input': 1.0, 'file_input': 0.9, 'network': 1.0,
                 'internal_data': 0.3, 'unknown': 0.5, 'register': 0.7}
    taint_factor = taint_map.get(taint_source_type, 0.5)

    # taint 距离衰减: 每远离源1跳, 因子衰减 5%
    distance_factor = max(0.5, 1.0 - taint_distance * 0.05)

    score = base_score * taint_factor * distance_factor

    # 定性判定
    if score >= 0.60:
        verdict = 'CRITICAL'
    elif score >= 0.35:
        verdict = 'HIGH'
    elif score >= 0.15:
        verdict = 'MEDIUM'
    else:
        verdict = 'LOW'

    return {
        'score': round(min(1.0, score), 3),
        'max_danger_spec': max_spec,
        'has_n_write': has_n_write,
        'has_leak': has_leak,
        'fortify_bypass': fortify_bypass,
        'taint_factor': round(taint_factor, 2),
        'verdict': verdict,
    }


def batch_score(findings: List, taint_map: Dict[int, Dict] = None) -> List[Dict]:
    """对 format_string_detector 的输出列表做批量评分."""
    taint_map = taint_map or {}
    results = []
    for f in findings:
        call_site = getattr(f, 'call_site', 0)
        fmt = getattr(f, 'format_string_value', '')
        taint = taint_map.get(call_site, {})
        source = taint.get('source_type', getattr(f, 'taint_source', 'unknown'))
        conf = compute_confidence(fmt, source)
        conf['call_site'] = call_site
        conf['format_string'] = fmt[:40]
        results.append(conf)
    results.sort(key=lambda r: -r['score'])
    return results
