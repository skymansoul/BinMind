"""
Human review gate: inserts structured human decision nodes into the exploit
feedback iteration loop.

After each feedback-loop iteration, a pending status file is written. The human
edits it to set status to approved/rejected/modify, and the pipeline reads it
on the next cycle. Absent a status file, the gate is skipped (backward compatible).

State machine: pending -> approved | rejected | modify
  - approved: accept current exploit, terminate iteration
  - rejected: discard current path, mark experiment needs_manual_analysis
  - modify: human supplies correction instructions for LLM re-generation

Design: filesystem-based gate (TOML), no HTTP/gRPC dependency. Fits CTF and
classroom single-machine workflows. TOML avoids JSON quoting noise.

References:
  - Amershi et al., 2019, CHI, "Guidelines for Human-AI Interaction"
  - Xin et al., 2024, USENIX Security, "Understanding the Challenges of
    Human-in-the-Loop Binary Exploitation"
"""

from __future__ import annotations

import logging
import os
import time
from enum import Enum
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# Gate file path relative to experiment output directory
_DEFAULT_GATE_FILENAME = "review_gate.toml"

# Human wait timeout (seconds); auto-skip in non-interactive mode
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
    Write a pending gate file for human review.

    Called after each feedback loop iteration (including initial script generation).
    Auto-creates output_dir if it does not exist.

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

    # TOML format: human-editable, no JSON escaping needed
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
        f'# --- stdout (last 2048 chars) ---\n'
        f'# {stdout_tail}\n'
        f'# --- stderr (last 1024 chars) ---\n'
        f'# {stderr_tail}\n'
        f'# --- script (first 40 lines) ---\n'
    )

    # Embed script content as line-by-line comments (human-readable, valid TOML)
    for i, line in enumerate(script_content.splitlines()[:40]):
        content += f"# L{i+1:04d}: {line}\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    _log.info("Review gate written: %s (iteration=%d)", path, iteration)
    return path


def read_gate(output_dir: str, timeout: float = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Read gate status.

    If gate file does not exist, returns {"status": "skip", "reason": "no_gate_file"}，
    Caller proceeds in fully automatic mode. This is by design: the gate is an optional layer.

    If pending and not timed out, returns pending; caller should wait and retry.
    If pending and timed out, returns skip; caller continues automatic iteration.

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
    """Delete the gate file after experiment completion."""
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
    Convenience wrapper for embedding gate checks in the feedback loop.

    Writes a gate file and polls for human decision.

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

        # pending - wait and retry
        time.sleep(poll_interval)
        waited += poll_interval

    _log.info("Gate wait timeout after %.0fs", timeout)
    return {"action": "skip", "instruction": ""}
