"""LLM 深度崩溃分析: 对模糊测试/符号执行的崩溃结果做语义级根因分析。
补充 crash_analysis.py 的关键词匹配: 该模块做快速分类 (SIGSEGV判栈/堆判可利用), 本模块做深度推理 (反编译代码+寄存器+栈回溯);
输入支持原始崩溃文本 (ASAN/GDB/coredump)、结构化崩溃数据或带反编译上下文的增强模式, 输出含漏洞类型、触发链、利用方向与置信度的结构化报告。
参考: Xu et al., 2024, USENIX Security "VulnRepair"; Pearce et al., 2022, IEEE S&P "Asleep at the Keyboard?"。"""


import json
import logging
import re
from typing import Any, Dict, List, Optional

from core.crash_llm_helpers import (
    _build_crash_context,
    _fallback_heuristic_analysis,
    _infer_severity_from_llm,
)

_log = logging.getLogger(__name__)

# LLM 系统提示: 要求结构化 JSON 输出
_CRASH_ANALYSIS_SYSTEM = """You are a senior binary exploitation researcher.
Analyze the crash information and provide a structured root cause analysis.

Output MUST be valid JSON with these keys:
  - crash_type: one of [stack-overflow, heap-overflow, use-after-free,
                 double-free, format-string, integer-overflow, null-deref,
                 type-confusion, other]
  - root_cause: specific explanation of what went wrong (2-3 sentences)
  - trigger_chain: step-by-step description of how the crash was triggered
  - exploitability: one of [confirmed, likely, possible, unlikely, none]
  - exploit_primitive: what capability the crash gives the attacker
  - recommended_approach: brief suggestion for exploitation direction
  - cwe: the most specific CWE number
  - confidence: 0.0 to 1.0"""


def analyze_crash_with_llm(
    crash_data: Dict[str, Any],
    binary_path: Optional[str] = None,
    decompiled_context: Optional[str] = None,
    binfo: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    调用 LLM 对崩溃进行深度分析。

    与 crash_analysis.py 的 analyze_crash_for_exploit 返回格式兼容,
    额外增加 root_cause/trigger_chain/confidence 字段;
    LLM 不可用时降级为关键词分析结果。
    """
    result: Dict[str, Any] = {
        'crash_type': crash_data.get('crash_type', 'unknown'),
        'severity': crash_data.get('severity', 'Medium'),
        'exploitable': crash_data.get('exploitable', False),
        'root_cause': '',
        'trigger_chain': '',
        'exploitability': 'unknown',
        'exploit_primitive': '',
        'recommended_approach': '',
        'cwe': '',
        'confidence': 0.0,
        'source': 'heuristic',
    }

    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return _fallback_heuristic_analysis(crash_data)
    except ImportError:
        return _fallback_heuristic_analysis(crash_data)

    crash_text = _build_crash_context(crash_data, binary_path, decompiled_context, binfo)

    try:
        from core.ai_backends import query_llm

        response = query_llm(
            system=_CRASH_ANALYSIS_SYSTEM,
            user=crash_text,
            temperature=0.2,
            max_tokens=1024,
        )

        llm_result = _parse_llm_crash_response(response)
        if llm_result:
            result.update(llm_result)
            result['source'] = 'llm'

            if result['exploitability'] in ('confirmed', 'likely'):
                result['exploitable'] = True
            elif result['exploitability'] == 'none':
                result['exploitable'] = False

            result['severity'] = _infer_severity_from_llm(result)

    except Exception as e:
        _log.debug("LLM crash analysis failed, using heuristic: %s", e)
        fallback = _fallback_heuristic_analysis(crash_data)
        result.update(fallback)

    return result


def _parse_llm_crash_response(response: str) -> Optional[Dict[str, Any]]:
    """从 LLM 响应解析 JSON: 依次尝试直接解析、代码块提取与回退模式。"""
    if not response:
        return None

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    json_match = re.search(r'```(?:json)?\s*\n?(\{[\s\S]*?\})\n?```', response)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    json_match = re.search(r'\{[\s\S]*?"crash_type"[\s\S]*?\}', response)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def batch_analyze_crashes(
    crashes: List[Dict[str, Any]],
    binary_path: str,
    parallel: bool = False,
) -> List[Dict[str, Any]]:
    """
    批量分析多个崩溃, 按严重级别排序 (最严重在前);
    parallel=True 且崩溃数 >1 时用 ThreadPoolExecutor 并发。
    """
    results = []

    if parallel and len(crashes) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(4, len(crashes))) as pool:
            futures = {
                pool.submit(analyze_crash_with_llm, c, binary_path): i
                for i, c in enumerate(crashes)
            }
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    _log.warning("Parallel crash analysis task failed: %s", e)
    else:
        for crash in crashes:
            try:
                result = analyze_crash_with_llm(crash, binary_path)
                results.append(result)
            except Exception as e:
                _log.warning("Crash analysis failed: %s", e)

    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    results.sort(key=lambda r: sev_order.get(r.get('severity', 'Low'), 99))

    return results
