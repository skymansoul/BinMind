"""
人工复核门控 —— 在 exploit 反馈迭代环中插入结构化的人工决策节点。

反馈环每轮迭代后写入待审状态文件，人工编辑该文件将 status 设为
approved / rejected / modify 后，管线下一轮读取状态决定后续路径。
不阻断自动迭代——无状态文件时默认跳过门控，保持向后兼容。

状态机: pending → approved | rejected | modify
  - approved: 接受当前 exploit，终止迭代
  - rejected: 放弃当前路径，不消耗剩余迭代轮次，标记实验为 needs_manual_analysis
  - modify:   人工在文件中提供修正指令，LLM 据此重新生成（比纯自动迭代多一次人工引导的机会）

设计权衡:
  采用文件系统而非 HTTP/gRPC 作为门控接口——降低部署依赖，适配 CTF 和教学场景
  中单机运行的常见模式。状态文件为人类可编辑的 TOML，避免 JSON 的引号噪音。

参考:
  - Amershi et al., 2019, CHI, "Guidelines for Human-AI Interaction" — 第 5/11 条:
    人工应在 AI 不确定时能够介入，且介入成本应最小化
  - Xin et al., 2024, USENIX Security, "Understanding the Challenges of
    Human-in-the-Loop Binary Exploitation" — 结构化的人工介入点比自由形式的
    日志审查更有效，人工倾向于修改而非从零编写
"""

from __future__ import annotations

import logging
import os
import time
from enum import Enum
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 门控状态文件相对于实验输出目录的路径
_DEFAULT_GATE_FILENAME = "review_gate.toml"

# 人工等待超时（秒）——非交互模式下超过此时间自动 skip
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
    写入待审门控文件。

    在反馈环每轮迭代（包括第 1 轮初始脚本生成后）调用。
    若 output_dir 不存在则自动创建。

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

    # TOML 格式——人类可直接编辑，不需要处理 JSON 转义
    content = (
        f'# BinMind Review Gate — 人工复核门控\n'
        f'# 将 status 改为 approved / rejected / modify 后保存，\n'
        f'# 管线下次轮询时读取。若保持 pending，管线等待 timeout 后自动 skip。\n'
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
        f'# 若 status = "modify"，在此填写修正指令供 LLM 参考\n'
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

    # 脚本内容按行注释嵌入——人类可读且不破坏 TOML 语法
    for i, line in enumerate(script_content.splitlines()[:40]):
        content += f"# L{i+1:04d}: {line}\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    _log.info("Review gate written: %s (iteration=%d)", path, iteration)
    return path


def read_gate(output_dir: str, timeout: float = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    读取门控状态。

    若状态文件不存在——返回 {"status": "skip", "reason": "no_gate_file"}，
    由调用方按纯自动模式继续。这是设计意图：门控是可选的增强层。

    若状态为 pending 且未超时——返回 pending，调用方应等待后重试。
    若状态为 pending 且已超时——返回 skip，调用方继续自动迭代。

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
    """删除门控文件——实验完成后清理。"""
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
    反馈环中嵌入门控检查的便捷封装。

    写入门控文件后轮询等待人工决策。

    Returns:
        {"action": "continue"|"accept"|"reject"|"modify"|"skip",
         "instruction": str (modify 时有效)}
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

        # pending——等待后重试
        time.sleep(poll_interval)
        waited += poll_interval

    _log.info("Gate wait timeout after %.0fs", timeout)
    return {"action": "skip", "instruction": ""}
