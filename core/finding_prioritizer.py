# core/finding_prioritizer.py - 发现优先级评分器
#
# 用静态可得信号(严重度/置信度/污点证据/CWE)计算 0-10 加权分,
# 作为 LLM 分诊(依赖 API key)的确定性基线。评分只附加
# priority_score 字段并降序重排, 不改变检测结论。
#
# 评分思路: CVSS v3.1 严重度分级 (NVD) × 漏洞优先级矩阵。
# 启用方式: ENABLE_FINDING_PRIORITIZER=1, 管线在报告生成后调用。
from typing import Any, Dict, List

_SEVERITY_WEIGHT = {
    'critical': 4.0,
    'high': 3.0,
    'medium': 2.0,
    'low': 1.0,
}


def score_finding(v: Dict[str, Any]) -> float:
    """计算单条告警的加权分。范围约 0-10。"""
    sev = str(v.get('severity', 'unknown')).lower()
    base = _SEVERITY_WEIGHT.get(sev, 0.5)

    try:
        conf = float(v.get('confidence', 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))

    exploit = 0.0
    if v.get('taint_verified'):
        exploit += 1.5
    if v.get('llm_exploitable'):
        exploit += 1.5
    if v.get('cwe'):
        exploit += 0.5

    return round(base + conf * 3.0 + min(exploit, 3.0), 2)


def prioritize_findings(findings: List[Dict]) -> List[Dict]:
    """评分并降序重排。空列表原样返回。"""
    if not findings:
        return findings
    for v in findings:
        v['priority_score'] = score_finding(v)
    findings.sort(key=lambda v: v.get('priority_score', 0.0), reverse=True)
    return findings


def apply_composite_sort(findings: List[Dict]) -> List[Dict]:
    """复合排序 — LLM 分诊与评分器同时启用时消除先后覆盖的不确定性。

    规则: 带 llm_priority 标注的告警(LLM 判定)排前并按优先级降序;
    未标注的告警回退 priority_score 降序排后。两段内各自有序,
    与两个排序器的启用组合无关。
    """
    if not findings:
        return findings

    def _key(v: Dict) -> tuple:
        if v.get('llm_priority') is not None:
            return (0, -float(v['llm_priority']))
        return (1, -float(v.get('priority_score', 0.0)))

    findings.sort(key=_key)
    return findings
