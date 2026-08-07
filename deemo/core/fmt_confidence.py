"""
格式化字符串检测置信度融合与 LLM 增强。
"""


import logging
from typing import Any, Dict, List

_log = logging.getLogger(__name__)


def llm_enhance_findings(
    findings: List[Dict[str, Any]],
    binary_path: str,
) -> List[Dict[str, Any]]:
    """
    调用 LLM 对静态检测结果进行深度分析。

    将反编译代码和检测到的模式发送给 LLM，
    获取利用可行性评估和详细的利用步骤建议。
    """
    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return findings

        from core.ai_backends import query_llm

        for finding in findings[:3]:
            system_prompt = (
                "You are an expert binary exploitation analyst specializing in "
                "format string vulnerabilities. Evaluate the exploitability of "
                "the given finding concisely."
            )
            user_prompt = (
                f"Format string finding:\n"
                f"Function: {finding['function']}\n"
                f"Dangerous call: {finding['format_func']}({finding['format_arg']})\n"
                f"Estimated offset: {finding.get('offset', -1)}\n\n"
                f"Provide: 1) Is this exploitable? 2) What is the most likely "
                f"attack vector? 3) Key constraints. Keep it under 200 words."
            )
            try:
                response = query_llm(
                    system=system_prompt,
                    user=user_prompt,
                    temperature=0.2,
                    max_tokens=256,
                )
                finding['llm_analysis'] = response.strip()
                finding['confidence'] = min(1.0, finding['confidence'] + 0.15)
            except Exception as e:
                _log.debug("LLM format string analysis failed: %s", e)

    except (ImportError, Exception) as e:
        _log.debug("LLM enhancement unavailable: %s", e)

    findings = fuse_confidence(findings)
    return findings


def fuse_confidence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """贝叶斯加权融合多层检测置信度。

    各层视为独立证据源, 用对数似然比(log-odds)累加而非直接加减置信度。
    log-odds = log(p/(1-p)), 融合后 p = 1/(1+exp(-sum log-odds))。

    各层权重基于历史准确率估计:
      L0(汇编): 0.6, L1(静态): 0.5, L1.5(污点): 0.7,
      L1.7(def-use): 0.65, L2(符号): 0.8
    """
    import math
    weights = {'asm': 0.6, 'static': 0.5, 'taint': 0.7,
               'defuse': 0.65, 'symbolic': 0.8}

    for f in findings:
        log_odds = 0.0
        count = 0
        base_conf = f.get('confidence', 0.5)
        if base_conf > 0 and base_conf < 1:
            log_odds += math.log(base_conf / (1.0 - base_conf))
            count += 1

        if f.get('taint_source', '').startswith('safe'):
            log_odds -= 1.5
        elif f.get('taint_source'):
            log_odds += weights['taint']
        if f.get('def_use_trace', '').startswith('safe'):
            log_odds -= 1.0
        elif f.get('def_use_trace'):
            log_odds += weights['defuse']
        if f.get('offset', -1) >= 0:
            log_odds += weights['symbolic']

        if count > 0:
            fused = 1.0 / (1.0 + math.exp(-log_odds))
            f['confidence'] = round(max(0.05, min(0.98, fused)), 3)
            f['fused'] = True
    return findings


def format_offset_to_arg_position(offset: int, arch_bits: int = 64) -> str:
    """
    将格式化字符串栈偏移转换为人类可读的参数位置描述。

    Args:
        offset: 格式化字符串在栈上的偏移（以指针为单位）
        arch_bits: 架构位数

    Returns:
        例如 "第 6 个参数 (printf 的第 1 个栈参数)"
    """
    if offset <= 0:
        return "unknown"

    if arch_bits == 32:
        return f"argument #{offset} (stack position {offset})"

    if offset <= 6:
        reg_names = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        return f"argument #{offset} (register {reg_names[offset-1]} -> format string itself)"

    stack_pos = offset - 5
    return f"argument #{offset} ({stack_pos}{_ordinal(stack_pos)} stack argument after r9)"


def _ordinal(n: int) -> str:
    """返回英文序数后缀。"""
    if 11 <= (n % 100) <= 13:
        return 'th'
    return {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
