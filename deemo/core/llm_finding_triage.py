# core/llm_finding_triage.py - LLM 告警分诊
#
# 把每条告警的关键字段压缩为结构化提示, 让 LLM 给出 1-5 级
# 优先度与可利用性判定, 写回 llm_priority/llm_exploitable/
# llm_rationale 并按优先度排序。判定不可用(无 API key/解析失败)
# 时原样保留告警, 不改变检测结论; 单次至多分诊 _MAX_FINDINGS 条。
#
# 参照: LLM4Vuln 评测框架 (arXiv:2401.16185) 的 LLM 辅助漏洞
# 排序思路; LLM 只做判定, 静态管线保持权威。
# 启用方式: ENABLE_LLM_TRIAGE=1, 管线在落库后自动调用。
import json
import logging
import re
from typing import Any, Dict, List

from core.ai_backends import query_llm

logger = logging.getLogger(__name__)

_MAX_FINDINGS = 20

_SYSTEM = (
    "你是二进制漏洞复审助手。对每条告警给出可利用性判定。"
    "只输出 JSON: {\"priority\": 1-5, \"exploitable\": true/false, "
    "\"rationale\": \"一句话理由\"}。priority 5 为最优先人工复审。"
)

_JSON_RE = re.compile(r'\{[\s\S]*\}')


def _build_prompt(v: Dict[str, Any]) -> str:
    return (
        f"type={v.get('type', '?')}; severity={v.get('severity', '?')}; "
        f"function={v.get('function_name', v.get('location', '?'))}; "
        f"description={str(v.get('description', ''))[:300]}; "
        f"evidence={str(v.get('evidence', ''))[:200]}"
    )


def _annotate_one(v: Dict[str, Any]) -> bool:
    """对单条告警请求判定, 成功写入标注字段。返回是否成功。"""
    resp = query_llm(
        system=_SYSTEM,
        user=_build_prompt(v),
        model=None,
        temperature=0.1,
        max_tokens=256,
    )
    if not resp:
        return False
    m = _JSON_RE.search(resp)
    if not m:
        return False
    try:
        parsed = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return False
    try:
        priority = int(parsed.get('priority', 3))
        priority = max(1, min(5, priority))
    except (TypeError, ValueError):
        return False
    v['llm_priority'] = priority
    v['llm_exploitable'] = bool(parsed.get('exploitable', False))
    v['llm_rationale'] = str(parsed.get('rationale', ''))[:200]
    return True


def triage_findings(findings: List[Dict], binary_info: Dict = None) -> List[Dict]:
    """对告警列表做 LLM 分诊并原地排序。单条失败不影响其余。"""
    if not findings:
        return findings
    annotated = 0
    for v in findings[:_MAX_FINDINGS]:
        try:
            if _annotate_one(v):
                annotated += 1
        except Exception as err:
            logger.debug("llm triage single failed: %s", err)
    findings.sort(
        key=lambda v: v.get('llm_priority', 0),
        reverse=True,
    )
    logger.info("LLM triage: %d/%d annotated", annotated, len(findings))
    return findings
