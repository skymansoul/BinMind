"""多模态崩溃分析: 融合反编译代码+汇编+执行轨迹三通道，供LLM联合推理，
三通道交叉验证构建输入到崩溃的因果链。单模态各自有盲区（反编译漏编译器
优化UB、汇编难推高层语义、轨迹缺代码级因果）；此处不做显式模态对齐，
由LLM注意力隐式对齐，复杂度低。"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 三通道 LLM 系统提示
_MULTIMODAL_SYSTEM_PROMPT = """You are a senior binary exploitation researcher performing
multi-modal crash root cause analysis. You receive three information channels:

[CHANNEL A — Decompiled C code]: High-level program semantics
[CHANNEL B — Assembly at crash point]: Instruction-level precision
[CHANNEL C — Execution trace / dynamic context]: Runtime behavior

Cross-reference all three channels to build a causal chain from input to crash.
Output MUST be valid JSON with:
  - crash_type: stack-overflow | heap-overflow | use-after-free | ...
  - root_cause: specific chain-of-events leading to crash
  - cross_channel_findings: what each channel contributes independently
  - contradiction: any disagreement between channels (e.g., decompiled ≠ asm)
  - exploitability: confirmed | likely | possible | unlikely | none
  - cwe: most specific CWE
  - confidence: 0.0-1.0"""


def analyze_crash_multimodal(
    crash_data: Dict[str, Any],
    binary_path: str,
    crash_func_name: str = "",
    trace_log: str = "",
) -> Dict[str, Any]:
    """
    三通道联合崩溃分析。

    比单模态 crash_analyzer_llm 多两个信息通道（汇编 + 执行轨迹），
    但 API key 未配置时降级为单模态分析。

    Args:
        crash_data:       崩溃数据 (registers, stack_trace, signal, addresses)
        binary_path:      崩溃来源二进制
        crash_func_name:  崩溃所在的函数名（空字符串则从 stack_trace 自动提取）
        trace_log:        执行轨迹文本（strace / QEMU log / fuzzer trace）

    Returns:
        与 crash_analyzer_llm.analyze_crash_with_llm 兼容的增强分析 dict
    """
    result: Dict[str, Any] = {
        "crash_type": crash_data.get("crash_type", "unknown"),
        "severity": crash_data.get("severity", "Medium"),
        "exploitable": False,
        "root_cause": "",
        "cross_channel_findings": {},
        "contradiction": "",
        "cwe": "",
        "confidence": 0.0,
        "source": "multi-modal-heuristic",
    }

    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            _log.debug("No API key — falling back to single-modal heuristic")
            from core.crash_analyzer_llm import _fallback_heuristic_analysis
            return _fallback_heuristic_analysis(crash_data)
    except ImportError:
        from core.crash_analyzer_llm import _fallback_heuristic_analysis
        return _fallback_heuristic_analysis(crash_data)

# Channel A: 反编译代码
    channel_a = _extract_decompiled_context(binary_path, crash_func_name, crash_data)

# Channel B: 汇编
    channel_b = _extract_asm_context(binary_path, crash_data)

# Channel C: 执行轨迹
    channel_c = trace_log[:3000] if trace_log else _extract_trace_from_crash(crash_data)

    # 若三通道都为空，未获得足够上下文
    if not channel_a and not channel_b and not channel_c:
        _log.debug("All three channels empty — falling back to heuristic")
        from core.crash_analyzer_llm import _fallback_heuristic_analysis
        return _fallback_heuristic_analysis(crash_data)

    # 构建多模态 prompt
    user_prompt = (
        "[CHANNEL A — Decompiled Code]\n"
        f"{channel_a or '(not available)'}\n\n"
        "[CHANNEL B — Assembly]\n"
        f"{channel_b or '(not available)'}\n\n"
        "[CHANNEL C — Execution Trace]\n"
        f"{channel_c or '(not available)'}\n\n"
        f"Crash signal: {crash_data.get('crash_type', 'unknown')}\n"
        f"Registers: {crash_data.get('registers', {})}\n\n"
        "Cross-reference all three channels and provide root cause analysis."
    )

    try:
        from core.ai_backends import query_llm

        response = query_llm(
            system=_MULTIMODAL_SYSTEM_PROMPT,
            user=user_prompt,
            temperature=0.2,
            max_tokens=1536,
        )

        import json, re
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            parsed = json.loads(json_match.group(0))
            result.update(parsed)
            result["source"] = "multi-modal-llm"

            if result.get("exploitability") in ("confirmed", "likely"):
                result["exploitable"] = True

    except Exception as e:
        _log.debug("Multi-modal LLM analysis failed: %s", e)
        from core.crash_analyzer_llm import _fallback_heuristic_analysis
        fallback = _fallback_heuristic_analysis(crash_data)
        result.update(fallback)

    return result


def _extract_decompiled_context(
    binary_path: str,
    func_name: str,
    crash_data: Dict[str, Any],
) -> str:
    """从二进制提取崩溃函数的反编译代码 (Channel A)。"""
    # 先推断崩溃函数名
    if not func_name:
        stack_trace = crash_data.get("stack_trace", [])
        if isinstance(stack_trace, list) and stack_trace:
            # GDB backtrace 格式: "#0  0xADDR in func_name ()"
            import re
            m = re.search(r'in\s+(\S+)', str(stack_trace[0]))
            if m:
                func_name = m.group(1)

    if not func_name:
        return ""

    try:
        from core.decompiler import decompile_function
        decomp = decompile_function(binary_path, func_name)
        return decomp.get("pseudocode", "")[:3000]
    except Exception:
        return ""


def _extract_asm_context(
    binary_path: str,
    crash_data: Dict[str, Any],
) -> str:
    """提取崩溃点附近的汇编指令 (Channel B)。"""
    # 从 crash_data 获取故障地址
    addresses = crash_data.get("addresses", [])
    fault_addr = addresses[0] if addresses else crash_data.get("fault_instruction", "")

    if not fault_addr or "0x" not in str(fault_addr):
        return ""

    import re
    m = re.search(r'(0x[0-9a-fA-F]+)', str(fault_addr))
    if not m:
        return ""
    addr = m.group(1)

    try:
        import subprocess
        from config import R2_PATH
        proc = subprocess.run(
            [R2_PATH, "-q", "-e", "io.color=false",
             "-c", f"s {addr}", "-c", "pd 20", binary_path],
            capture_output=True, text=True, timeout=15,
        )
        if proc.stdout.strip():
            return proc.stdout[:2000]
    except Exception:
        pass

    return ""


def _extract_trace_from_crash(crash_data: Dict[str, Any]) -> str:
    """从崩溃数据中提取执行轨迹片段 (Channel C 后备)。"""
    parts = []

    stack_trace = crash_data.get("stack_trace", [])
    if isinstance(stack_trace, list) and stack_trace:
        parts.append("Stack trace:\n" + "\n".join(
            str(s) for s in stack_trace[:15]
        ))

    registers = crash_data.get("registers", {})
    if registers:
        parts.append("Key registers:\n" + "\n".join(
            f"  {k}: {v}" for k, v in list(registers.items())[:8]
        ))

    raw = crash_data.get("raw", "")
    if raw:
        parts.append(f"Raw output (truncated):\n{raw[:1500]}")

    return "\n\n".join(parts)
