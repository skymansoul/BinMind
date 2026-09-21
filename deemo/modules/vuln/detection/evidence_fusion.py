# 多分析器证据一致性加权与漏洞分诊。
# 对同一 (函数, 类型) 的多个独立检测器 finding 做一致性加权, 输出综合置信度。
# 思路: 独立分析器在同类结论上的一致程度可视为证据强度-
# 多分析器同向命中提升置信度, 仅单一弱信号命中的保持低置信, 作为误报抑制。
# 同时消费 RW 创新管线注入的 fp_votes/fp_sources (安全证据反向投票),
# 对高票 finding 做负向置信度偏移, 保证降权信息进入最终输出而非仅审计统计。
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


def _fp_penalty(f: Dict) -> float:
    """安全证据反向投票衰减系数。

    RW 创新管线通过 fp_votes 累积"该 finding 为误报"的安全证据票数,
    每票按 0.85 衰减 (与 _rw_apply_fp_vote 的 conf*0.85 温和降权对齐),
    避免与融合阶段的一致性抬升互相抵消。无票时返回 1.0 不影响。
    """
    votes = int(f.get('fp_votes', 0) or 0)
    if votes <= 0:
        return 1.0
    return round(0.85 ** votes, 3)


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
        # RW 弱告警 (rw_weak=True) 不参与一致性提升, 避免弱启发式
        # 与基础检测器同组融合时抬高置信度. 仍参与 evidence 汇总与 fp_votes 累积.
        core_items = [f for f in items if not f.get('rw_weak')]
        rw_items = [f for f in items if f.get('rw_weak')]
        if core_items:
            confs = [max(0.0, float(f.get('confidence') or 0.0))
                     for f in core_items]
            _type = key[1]
            base_w = _TYPE_BASE_WEIGHT.get(_type, 0.5)
            weights = [base_w * (0.5 + 0.5 * c) for c in confs]
            fused_conf = _consensus_conf(confs, weights)
        else:
            # 全组均为 RW 弱告警 (无基础检测器命中): 取加权平均不做提升
            confs = [max(0.0, float(f.get('confidence') or 0.0))
                     for f in rw_items]
            _type = key[1]
            base_w = _TYPE_BASE_WEIGHT.get(_type, 0.5)
            weights = [base_w * (0.5 + 0.5 * c) for c in confs]
            wsum = sum(weights)
            if wsum <= 0:
                fused_conf = sum(confs) / len(confs) if confs else 0.0
            else:
                fused_conf = sum(c * w for c, w in zip(confs, weights)) / wsum
        # 安全证据反向投票: 组内任一 finding 累积的 fp_votes 对整体置信度做负向偏移.
        # RW 模块的降权票若在融合阶段被忽略, 会与一致性抬升互相抵消, 降权失效.
        fp_votes = sum(int(f.get('fp_votes', 0) or 0) for f in items)
        fused_conf = round(fused_conf * _fp_penalty({'fp_votes': fp_votes}), 3)

        best = max(items, key=lambda f: _severity_rank(f.get('severity', '')))
        merged = dict(best)
        merged['fused_confidence'] = fused_conf
        merged['confidence'] = fused_conf
        merged['analyzer_count'] = len(items)
        merged['fp_votes'] = fp_votes
        merged['evidence'] = ' || '.join(
            (f.get('evidence') or f.get('description') or f.get('type') or '')
            for f in items if (f.get('evidence') or f.get('description')))
        if fp_votes:
            merged['evidence'] = (merged['evidence']
                                  + f' [FP votes: {fp_votes}]')
        fused.append(merged)
    return fused


def triage_by_confidence(findings: List[Dict],
                         high: float = 0.6,
                         low: float = 0.3) -> Dict[str, List[Dict]]:
    """按综合置信度分诊: {high, medium, low} 三档。

    high: 应优先复核; low: 与历史证据冲突概率大, 标注需人工确认。
    高 fp_votes (安全证据反向投票≥3) 的 finding 即使置信度达标也强制降档,
    防止多票误报占据 high 复核队列。
    """
    buckets = {'high': [], 'medium': [], 'low': []}
    for f in findings:
        c = max(0.0, float(f.get('fused_confidence') or f.get('confidence') or 0.0))
        votes = int(f.get('fp_votes', 0) or 0)
        if votes >= 3 and c >= high:
            # 安全证据多票否决: 降入 medium 而非直接清除, 保留人工复核入口
            buckets['medium'].append(f)
        elif c >= high:
            buckets['high'].append(f)
        elif c >= low:
            buckets['medium'].append(f)
        else:
            buckets['low'].append(f)
    return buckets


__all__ = ["fuse_findings", "triage_by_confidence"]
