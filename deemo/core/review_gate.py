"""
人工审查门控: 在利用反馈迭代循环中插入结构化人工决策节点。
每轮迭代后写入 pending 状态文件, 人工编辑为 approved/rejected/modify, 下一轮读取;
无状态文件时跳过门控 (向后兼容)。基于文件系统(TOML), 无 HTTP/gRPC 依赖。
"""

from __future__ import annotations

import logging
import os
import time
from enum import Enum
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 门控文件路径 (相对实验输出目录)
_DEFAULT_GATE_FILENAME = "review_gate.toml"

# 人工等待超时 (秒); 非交互模式自动跳过
_DEFAULT_TIMEOUT = 3600


class GateStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFY = "modify"


def _gate_path(output_dir: str) -> str:
    return os.path.join(output_dir, _DEFAULT_GATE_FILENAME)


def write_gate(
    output_dir: str,
    iteration: int,
    script_content: str,
    exec_result: Dict[str, Any],
    llm_feedback: str = "",
) -> str:
    """
    写入待人工审查的门控文件。

    在每轮反馈循环迭代后调用 (含初始脚本生成), 自动创建 output_dir。

    Args:
        output_dir:    实验输出目录
        iteration:     当前迭代轮次
        script_content: 当前 exploit 脚本内容
        exec_result:   exploit_executor 返回的执行结果
        llm_feedback:  LLM 的修正建议（若已调用）

    Returns:
        门控文件的绝对路径
    """
    os.makedirs(output_dir, exist_ok=True)
    path = _gate_path(output_dir)

    exit_code = exec_result.get("exit_code", -1)
    signal_name = exec_result.get("signal", "")
    stdout_tail = (exec_result.get("stdout", "") or "")[-2048:]
    stderr_tail = (exec_result.get("stderr", "") or "")[-1024:]

    # TOML格式: 人工可编辑, 无需JSON转义
    content = (
        f'# BinMind Review Gate\n'
        f'# Set status to approved / rejected / modify, then save.\n'
        f'# The pipeline reads on next poll. If still pending after timeout, auto-skip.\n'
        f'\n'
        f'status = "pending"\n'
        f'iteration = {iteration}\n'
        f'timestamp = "{time.strftime("%Y-%m-%dT%H:%M:%S")}"\n'
        f'\n'
        f'[exec_result]\n'
        f'exit_code = {exit_code}\n'
        f'signal = "{signal_name}"\n'
        f'\n'
        f'[human_input]\n'
        f'# If status = "modify", write correction instructions here for LLM reference\n'
        f'instruction = ""\n'
        f'\n'
        f'[llm_feedback]\n'
        f'summary = """{llm_feedback[:500] if llm_feedback else "(not yet invoked)"}"""\n'
        f'\n'
        f'# --- stdout ---\n'
        f'# {stdout_tail}\n'
        f'# --- stderr (last 1024 chars) ---\n'
        f'# {stderr_tail}\n'
        f'# --- script (first 40 lines) ---\n'
    )

    # 脚本内容按行嵌入为注释 (人工可读, 合法TOML)
    for i, line in enumerate(script_content.splitlines()[:40]):
        content += f"# L{i+1:04d}: {line}\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    _log.info("Review gate written: %s (iteration=%d)", path, iteration)
    return path


def read_gate(output_dir: str, timeout: float = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    读取门控状态。

    门控文件不存在时返回 {"status": "skip", "reason": "no_gate_file"}, 调用方全自动继续;
    pending 未超时返回 pending (调用方等待重试), 超时返回 skip 继续自动迭代。

    Args:
        output_dir: 实验输出目录
        timeout:    pending 状态的超时秒数

    Returns:
        {"status": "approved"|"rejected"|"modify"|"skip",
         "instruction": str (仅 modify 时有效),
         "reason": str}
    """
    path = _gate_path(output_dir)
    if not os.path.isfile(path):
        return {"status": "skip", "reason": "no_gate_file", "instruction": ""}

    # 读取 TOML——不引入 tomli 依赖，用简单行解析
    status = "pending"
    instruction = ""
    timestamp_str = ""

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("status = "):
                    status = line.split('"')[1] if '"' in line else "pending"
                elif line.startswith("instruction = "):
                    # TOML 基本字符串: instruction = "value"
                    if '"""' in line:
                        # 多行字符串暂不深度解析——人工可在下一行继续写
                        instruction = line.split('"""')[1] if '"""' in line else ""
                    elif '"' in line:
                        parts = line.split('"')
                        instruction = parts[1] if len(parts) > 1 else ""
                elif line.startswith("timestamp = "):
                    timestamp_str = line.split('"')[1] if '"' in line else ""
    except (OSError, UnicodeDecodeError) as e:
        _log.warning("Gate file read error: %s", e)
        return {"status": "skip", "reason": f"read_error: {e}", "instruction": ""}

    # 超时检查
    if status == "pending":
        if timestamp_str:
            try:
                gate_time = time.mktime(
                    time.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                )
                if time.time() - gate_time > timeout:
                    _log.info("Gate timeout after %.0fs, auto-skipping", timeout)
                    return {"status": "skip", "reason": "timeout", "instruction": ""}
            except ValueError:
                pass
        return {"status": "pending", "reason": "awaiting_human", "instruction": ""}

    # 映射状态字符串到 GateStatus
    if status in ("approved", "rejected", "modify"):
        return {"status": status, "instruction": instruction, "reason": ""}

    # 未知状态视为 skip
    return {"status": "skip", "reason": f"unknown_status: {status}", "instruction": ""}


def clear_gate(output_dir: str) -> None:
    """实验完成后删除门控文件。"""
    path = _gate_path(output_dir)
    if os.path.isfile(path):
        try:
            os.unlink(path)
            _log.debug("Gate file cleared: %s", path)
        except OSError as e:
            _log.warning("Failed to clear gate file: %s", e)


def gate_in_feedback_loop(
    output_dir: str,
    iteration: int,
    current_script: str,
    exec_result: Dict[str, Any],
    llm_feedback: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
    poll_interval: float = 5.0,
) -> Dict[str, Any]:
    """
    反馈循环中嵌入门控检查的便捷封装。

    写入门控文件并轮询人工决策。

    Returns:
        {"action": "continue"|"accept"|"reject"|"modify"|"skip",
         "instruction": str (valid when modify)}
    """
    write_gate(output_dir, iteration, current_script, exec_result, llm_feedback)

    waited = 0.0
    while waited < timeout:
        gate = read_gate(output_dir, timeout=timeout)

        if gate["status"] == "approved":
            return {"action": "accept", "instruction": ""}
        if gate["status"] == "rejected":
            return {"action": "reject", "instruction": ""}
        if gate["status"] == "modify":
            return {"action": "modify", "instruction": gate["instruction"]}
        if gate["status"] == "skip":
            return {"action": "skip", "instruction": ""}

        # pending — 等待并重试
        time.sleep(poll_interval)
        waited += poll_interval

    _log.info("Gate wait timeout after %.0fs", timeout)
    return {"action": "skip", "instruction": ""}
