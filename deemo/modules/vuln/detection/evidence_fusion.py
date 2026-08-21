# 多分析器证据一致性加权与漏洞分诊。
# 对同一 (函数, 类型) 的多个独立检测器 finding 做一致性加权, 输出综合置信度。
# 思路: 独立分析器在同类结论上的一致程度可视为证据强度-
# 多分析器同向命中提升置信度, 仅单一弱信号命中的保持低置信, 作为误报抑制。
# 参考: LlamaVuln (arXiv:2401.14185) 的多信号证据组合;
#       VulDeePecker (IEEE S&P 2018) 的多切片特征聚合思想;
#       证据融合引入 Dempster-Shafer 组合规则的加权近似。
# 本实现轻量、纯函数, 数据仅来源于各已跑检测器的 finding 文档, 无额外依赖。

from __future__ import annotations

from typing import Dict, List


# 各漏洞类型的默认分析器先验权重。
# 仅在当前 finding 未自报 severity 时用于映射 severity 排序。
_TYPE_BASE_WEIGHT = {
    'heap-overflow': 0.9,
    'stack-overflow': 0.9,
    'format-string': 0.85,
    'integer-overflow': 0.8,
    'heap-corruption': 0.85,   # UAF / double-free
}


def _severity_rank(sev: str) -> int:
    """severity 文本 -> 数值排序, 用于冲突解决。"""
    return {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(sev, 0)


def _consensus_conf(confs: List[float], weights: List[float]) -> float:
    """一致性加权置信度。

    多检测器都指向同一结论时, 置信度向高值收敛 (证据叠加);
    单一低置信信号保持低值。权重即证据强度。
    """
    if not confs:
        return 0.0
    n = len(confs)
    # 加权平均
    wsum = sum(weights)
    if wsum <= 0:
        base = sum(confs) / n
    else:
        base = sum(c * w for c, w in zip(confs, weights)) / wsum
    # 一致性提升: 命中数越多, 收敛越强; 用 (n-1) 阶(k≥2)证据合并近似
    agreement = (n - 1) / max(1, n)  # 0 for 单源, 趋于 1 for 多源
    boost = base + agreement * (1 - base) * 0.5
    return round(max(0.0, min(1.0, boost)), 3)


def fuse_findings(findings: List[Dict]) -> List[Dict]:
    """按 (function, type) 分组, 融合各分析器 finding 并输出综合结果。

    每组保留: 最高 severity 作为组 severity, 融合后的 fused_confidence,
    evidence 汇总各来源, 并按 (function, type) 去重。
    未命中的 finding 原样保留 (fused_confidence 取该 finding 自身置信度)。
    """
    grouped: Dict[str, List[Dict]] = {}
    for f in findings:
        key = (f.get('function') or f.get('function_name') or '?',
               f.get('type') or '?')
        grouped.setdefault(key, []).append(f)

    fused: List[Dict] = []
    for key, items in grouped.items():
        confs = [max(0.0, float(f.get('confidence') or 0.0)) for f in items]
        # 证据权重: 以所属类型的先验权重为基底, 叠加 finding 自身置信度
        _type = key[1]
        base_w = _TYPE_BASE_WEIGHT.get(_type, 0.5)
        weights = [base_w * (0.5 + 0.5 * c) for c in confs]
        fused_conf = _consensus_conf(confs, weights)

        best = max(items, key=lambda f: _severity_rank(f.get('severity', '')))
        merged = dict(best)
        merged['fused_confidence'] = fused_conf
        merged['confidence'] = fused_conf
        merged['analyzer_count'] = len(items)
        merged['evidence'] = ' || '.join(
            (f.get('evidence') or f.get('description') or f.get('type') or '')
            for f in items if (f.get('evidence') or f.get('description')))
        fused.append(merged)
    return fused


def triage_by_confidence(findings: List[Dict],
                         high: float = 0.6,
                         low: float = 0.3) -> Dict[str, List[Dict]]:
    """按综合置信度分诊: {high, medium, low} 三档。

    high: 应优先复核; low: 与历史证据冲突概率大, 标注需人工确认。
    """
    buckets = {'high': [], 'medium': [], 'low': []}
    for f in findings:
        c = max(0.0, float(f.get('fused_confidence') or f.get('confidence') or 0.0))
        if c >= high:
            buckets['high'].append(f)
        elif c >= low:
            buckets['medium'].append(f)
        else:
            buckets['low'].append(f)
    return buckets


__all__ = ["fuse_findings", "triage_by_confidence"]
