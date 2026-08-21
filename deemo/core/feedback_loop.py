"""Exploit 反馈迭代环: 分析、生成、执行、反馈。
执行失败时收集日志 (退出码/stdout/stderr/信号/寄存器) 并调用 LLM 做根因分析与修正建议,
再生成并重执行, 上限 MAX_ITERATIONS; LLM 依据实际执行反馈动态调整载荷结构、偏移与绕过策略,
模拟人工试错调试; 连续 3 次相同错误提前终止。
参考: Peng et al., 2025, ACL "PwnGPT"; Zeng et al., 2026, NDSS "ropbot"。"""


import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from core.feedback_llm_helpers import (
    _llm_correct_script,
    _extract_script_from_llm_response,
)

_log = logging.getLogger(__name__)

# 最大迭代轮数
MAX_ITERATIONS = 5
# 连续相同错误的最大容忍次数
MAX_REPEATED_ERRORS = 3


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

    从初始 exploit 脚本开始, 执行并迭代修正直到成功或耗尽轮次。
    binfo/libc_info/checksec 供 LLM 修正时参考;
    返回 {success, final_script, iterations, history, best_result, root_cause}。
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

        script_path = _write_temp_script(current_script, iteration)

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

