"""
漏洞利用反馈迭代环 —— 分析→生成→执行→反馈 闭环实现。

当 exploit 执行失败时，收集执行日志并调用 LLM 进行根因分析和修正建议，
然后重新生成 exploit 脚本并执行。最多迭代 MAX_ITERATIONS 次。

迭代策略:
  1. 收集失败信息（exit code, stdout, stderr, crash signal, registers）
  2. 调用 LLM chain-of-thought 分析失败原因
  3. LLM 输出修正后的 exploit 脚本
  4. 重新执行 → 成功则记录，失败则继续迭代
  5. 若连续 3 次相同错误则提前终止（防死循环）

创新点: 链式推理驱动的自适应 exploit 修正。与传统自动化工具
（如 pwnpasi 的固定模板）不同，LLM 根据实际执行反馈动态调整
payload 结构、偏移值和绕过策略，模拟人工调试的"试错-修正"循环。

参考:
  - Peng et al., 2025, ACL, "PwnGPT: Automatic Exploit Generation Based on LLMs"
  - Zeng et al., 2026, NDSS, "ropbot: Reimaging Code Reuse Attack Synthesis"
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 最大迭代轮数
MAX_ITERATIONS = 5
# 连续相同错误的最大容忍次数
MAX_REPEATED_ERRORS = 3

# LLM 系统提示
_ITERATION_SYSTEM_PROMPT = """You are an expert binary exploitation engineer.
Analyze the failed exploit attempt, identify the root cause, and provide
a corrected pwntools exploit script.

Output as JSON with these keys:
  - failure_analysis: brief root cause diagnosis
  - changes_made: specific changes from the original script
  - optimized_script: complete corrected pwntools Python script"""


def run_feedback_loop(
    binary_path: str,
    initial_script: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
    checksec: Optional[Dict[str, Any]] = None,
    max_iterations: int = MAX_ITERATIONS,
    timeout: int = 30,
    sandbox: str = 'subprocess',
) -> Dict[str, Any]:
    """
    执行 exploit 反馈迭代环。

    从初始 exploit 脚本开始，执行并迭代修正直到成功或耗尽轮次。

    Args:
        binary_path:    目标二进制文件路径
        initial_script: 初始 pwntools exploit 脚本内容
        binfo:          get_binary_info() 的结果
        libc_info:      identify_libc() 的结果
        checksec:       detect_checksec() 的结果
        max_iterations: 最大迭代轮数
        timeout:        单次执行超时
        sandbox:        执行模式

    Returns:
        {
            'success': bool,
            'final_script': str,          # 最终/最佳 exploit 脚本
            'iterations': int,             # 实际迭代轮数
            'history': list,               # 每轮迭代的完整记录
            'best_result': dict,           # 最佳执行结果
            'root_cause': str,             # 若失败，LLM 分析的根因
        }
    """
    result: Dict[str, Any] = {
        'success': False,
        'final_script': initial_script,
        'iterations': 0,
        'history': [],
        'best_result': {},
        'root_cause': '',
    }

    current_script = initial_script
    prev_errors: List[str] = []

    for iteration in range(1, max_iterations + 1):
        _log.info("Feedback loop iteration %d/%d", iteration, max_iterations)
        result['iterations'] = iteration

        # 写入临时脚本
        script_path = _write_temp_script(current_script, iteration)

        # 执行
        from core.exploit_executor import execute_exploit, is_exploit_successful
        exec_result = execute_exploit(
            script_path,
            binary_path,
            timeout=timeout,
            sandbox=sandbox,
        )

        # 记录本轮
        round_record = {
            'iteration': iteration,
            'script': current_script,
            'script_path': script_path,
            'exec_result': exec_result,
            'llm_feedback': '',
        }
        result['history'].append(round_record)

        # 检查是否成功
        if is_exploit_successful(exec_result):
            result['success'] = True
            result['final_script'] = current_script
            result['best_result'] = exec_result
            _log.info("Exploit succeeded at iteration %d", iteration)
            break

        # 更新最佳结果
        if _score_result(exec_result) > _score_result(result['best_result']):
            result['best_result'] = exec_result
            result['final_script'] = current_script

        # 检测重复错误
        error_sig = _error_signature(exec_result)
        prev_errors.append(error_sig)
        if (_count_recent_same_error(prev_errors) >= MAX_REPEATED_ERRORS):
            result['root_cause'] = (
                f"Same error repeated {MAX_REPEATED_ERRORS} times: {error_sig}. "
                "Likely requires manual analysis."
            )
            _log.warning("Feedback loop aborted: repeated error '%s'", error_sig)
            break

        # 调用 LLM 修正
        if iteration < max_iterations:
            llm_feedback = _llm_correct_script(
                current_script, exec_result, binfo, libc_info, checksec,
            )
            round_record['llm_feedback'] = llm_feedback

            if llm_feedback:
                corrected = _extract_script_from_llm_response(llm_feedback)
                if corrected and corrected != current_script:
                    current_script = corrected
                    continue

            # LLM 未返回有效修正，提前终止
            result['root_cause'] = "LLM failed to produce a valid corrected script"
            break

        # 清理临时文件
        _cleanup_temp_script(script_path)

    if not result['success']:
        _log.warning("Feedback loop exhausted after %d iterations", iteration)

    return result


def _write_temp_script(script: str, iteration: int) -> str:
    """将 exploit 脚本写入临时文件。"""
    tmpdir = tempfile.mkdtemp(prefix='binmind_exploit_')
    script_path = os.path.join(tmpdir, f'exploit_iter{iteration}.py')
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write(script)
    os.chmod(script_path, 0o755)
    return script_path

import tempfile


def _cleanup_temp_script(script_path: str) -> None:
    """清理临时 exploit 脚本。"""
    try:
        tmpdir = os.path.dirname(script_path)
        if os.path.exists(tmpdir) and 'binmind_exploit_' in tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


def _score_result(exec_result: Dict[str, Any]) -> float:
    """对执行结果打分，用于选择最佳迭代。"""
    if not exec_result:
        return 0.0

    score = 0.0
    if exec_result.get('shell_obtained'):
        score += 100.0
    if exec_result.get('exit_code') == 0:
        score += 50.0
    stdout = exec_result.get('stdout', '')
    if 'flag' in stdout.lower():
        score += 30.0
    if exec_result.get('signal'):
        score -= 20.0
    return score


def _error_signature(exec_result: Dict[str, Any]) -> str:
    """生成错误的简短签名，用于去重检测。"""
    parts = []
    if exec_result.get('signal'):
        parts.append(exec_result['signal'])
    if exec_result.get('exit_code', 0) != 0:
        parts.append(f'exit={exec_result["exit_code"]}')
    if exec_result.get('error'):
        # 取错误信息的前 60 个字符
        err = exec_result['error'][:60]
        parts.append(err)
    return '|'.join(parts) if parts else 'unknown'


def _count_recent_same_error(errors: List[str]) -> int:
    """计算最近连续相同错误的数量。"""
    if not errors:
        return 0
    last = errors[-1]
    count = 0
    for e in reversed(errors):
        if e == last:
            count += 1
        else:
            break
    return count


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
    import re
    code_match = re.search(r'```(?:python)?\s*\n(.*?)```', response, re.DOTALL)
    if code_match:
        return code_match.group(1).strip()

    # 检查响应是否本身就是完整的 Python 脚本
    if response.strip().startswith(('#!/usr', 'from pwn', 'import pwn')):
        return response.strip()

    return ''
