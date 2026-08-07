"""

独立模块化以避免主环文件超长；两者通过函数导入复用。
"""


import json
import logging
import re
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# LLM 系统提示
_ITERATION_SYSTEM_PROMPT = """You are an expert binary exploitation engineer.
Analyze the failed exploit attempt, identify the root cause, and provide
a corrected pwntools exploit script.

Output as JSON with these keys:
  - failure_analysis: brief root cause diagnosis
  - changes_made: specific changes from the original script
  - optimized_script: complete corrected pwntools Python script"""


def _llm_correct_script(
    current_script: str,
    exec_result: Dict[str, Any],
    binfo: Optional[Dict[str, Any]],
    libc_info: Optional[Dict[str, Any]],
    checksec: Optional[Dict[str, Any]],
) -> str:
    """调用 LLM 分析失败原因并生成修正脚本。"""
    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            _log.debug("No API key configured, skipping LLM correction")
            return ''

        from core.ai_backends import query_llm

        # 构建上下文
        context_parts = []
        if binfo:
            context_parts.append(
                f"Arch: {binfo.get('arch', '?')} {binfo.get('bits', 64)}-bit"
            )
        if checksec:
            from core.checksec import checksec_summary
            context_parts.append(f"Protections: {checksec_summary(checksec)}")
        if libc_info:
            from core.libc_identifier import get_libc_context_for_llm
            ctx = get_libc_context_for_llm(libc_info)
            if ctx:
                context_parts.append(ctx)

        user_prompt = (
            f"Binary context:\n" + '\n'.join(f"  {p}" for p in context_parts) +
            f"\n\nOriginal exploit script:\n```python\n{current_script}\n```\n"
            f"\nExecution failure:\n"
            f"  exit_code: {exec_result.get('exit_code')}\n"
            f"  signal: {exec_result.get('signal', 'none')}\n"
            f"  stderr: {exec_result.get('stderr', '')[:500]}\n"
            f"  stdout: {exec_result.get('stdout', '')[:500]}\n"
            f"\nAnalyze the failure and provide a corrected exploit script."
        )

        response = query_llm(
            system=_ITERATION_SYSTEM_PROMPT,
            user=user_prompt,
            temperature=0.3,
            max_tokens=4096,
        )
        return response.strip()
    except Exception as e:
        _log.debug("LLM correction failed: %s", e)
        return ''


def _extract_script_from_llm_response(response: str) -> str:
    """从 LLM 响应中提取 Python 脚本。"""
    if not response:
        return ''

    # 尝试从 JSON 中提取
    try:
        data = json.loads(response)
        if 'optimized_script' in data:
            return data['optimized_script']
    except json.JSONDecodeError:
        pass

    # 从 Markdown 代码块中提取
    code_match = re.search(r'```(?:python)?\s*\n(.*?)```', response, re.DOTALL)
    if code_match:
        return code_match.group(1).strip()

    if response.strip().startswith(('#!/usr', 'from pwn', 'import pwn')):
        return response.strip()

    return ''
