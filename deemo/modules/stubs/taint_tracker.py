# taint_tracker.py — 动态污点追踪
# 跟踪用户输入在二进制执行中的传播路径，检测注入点和信息泄露。
# 参考: LLM-Powered Static Binary Taint Analysis (2024) — LLM 增强的静态污点 &
#   Dynamic Taint Analysis for Automatic Detection of Exploits (Newsome & Song, 2005) &
#   Scalable Language Agnostic Taint Tracking (SOAP 2025)
import struct as _pack
from collections import defaultdict as _defdict

# 污点源 API 映射 — 从外部获取数据的函数
_TAINT_SOURCES = {
    'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
    'scanf', 'fscanf', 'gets', 'fgets',
    'ReadFile', 'RegQueryValueEx',
    'getenv', 'getenv_s',
}

# 污点传播操作 — 数据从源寄存器流向目标寄存器
_TAINT_PROPAGATION_OPS = {
    'mov', 'lea', 'add', 'sub', 'xor', 'and', 'or', 'shl', 'shr',
    'movzx', 'movsx', 'push', 'pop', 'xchg',
}

def mark_taint_sources(instructions: list[dict]) -> dict[int, set[str]]:
    """标记污点源。返回 {insn_index: {taint_labels}}。"""
    taint_map = {}
    for idx, insn in enumerate(instructions):
        mnemonic = insn.get('mnemonic', '').lower()
        if mnemonic == 'call':
            target = insn.get('operands', '').lower()
            for src in _TAINT_SOURCES:
                if src in target:
                    taint_map[idx] = {f'taint_{src}'}
    return taint_map

def propagate_taint(instructions: list[dict],
                     taint_map: dict[int, set[str]]) -> dict[int, set[str]]:
    """沿数据流传播污点标记。固定点迭代直至收敛。
    参考 LLM-Powered Static Binary Taint Analysis 的
    LLM 辅助别名分析 — 此处用简化版寄存器别名追踪。"""
    changed = True
    max_iter = len(instructions) * 3  # 防止不收敛

    while changed and max_iter > 0:
        max_iter -= 1; changed = False
        for idx, insn in enumerate(instructions):
            mnem = insn.get('mnemonic', '').lower()
            if mnem not in _TAINT_PROPAGATION_OPS:
                continue
            # 检查前一条指令是否带污点（简化：线性传播）
            if idx > 0 and (idx - 1) in taint_map:
                prev_taint = taint_map[idx - 1]
                if idx not in taint_map or not prev_taint.issubset(taint_map.get(idx, set())):
                    taint_map.setdefault(idx, set()).update(prev_taint)
                    changed = True
    return taint_map

def detect_taint_sinks(instructions: list[dict],
                        taint_map: dict[int, set[str]]) -> list[dict]:
    """检测污点汇 — 带污点的数据到达危险操作（如 system, exec, memcpy size 参数）。
    返回 [{'insn_idx': int, 'sink_type': str, 'taint_labels': [...]}]。"""
    # 污点汇 API
    sinks = {
        'system': 'command_injection',
        'execve': 'command_injection',
        'memcpy': 'memory_corruption',
        'strcpy': 'buffer_overflow',
        'sprintf': 'format_string',
        'CreateProcess': 'process_creation',
    }
    findings = []
    for idx, insn in enumerate(instructions):
        if insn.get('mnemonic', '').lower() != 'call':
            continue
        ops = insn.get('operands', '').lower()
        for sink_api, sink_type in sinks.items():
            if sink_api.lower() in ops and idx in taint_map:
                findings.append({
                    'insn_idx': idx,
                    'sink_type': sink_type,
                    'taint_labels': list(taint_map[idx]),
                })
    return findings
