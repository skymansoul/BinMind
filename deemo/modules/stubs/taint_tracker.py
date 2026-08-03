# 动态污点追踪 — 输入数据在二进制执行中的传播路径分析
# 标记污点源，沿指令传播，检测注入点和信息泄露。
# 参考: 语言模型辅助静态污点分析 (2024) 的别名解析策略 &
#   Dynamic Taint Analysis for Automatic Detection of Exploits (Newsome & Song, 2005) &
#   Scalable Language Agnostic Taint Tracking (SOAP 2025)
import struct as _pack
from collections import defaultdict as _defdict

# 污点源映射表 — 从外部获取数据的函数调用
_TAINT_SOURCES = {
    'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
    'scanf', 'fscanf', 'gets', 'fgets',
    'ReadFile', 'RegQueryExValue',
    'getenv', 'getenv_s',
}

# 传播类操作码 — 数据在寄存器间迁移的指令集合
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
    """沿数据流传播污点标记，固定点迭代至收敛。
    简化寄存器别名追踪 — 线性传播近似替代完整别名分析。"""
    changed = True
    max_iter = len(instructions) * 3  # 迭代上限，防止发散

    while changed and max_iter > 0:
        max_iter -= 1; changed = False
        for idx, insn in enumerate(instructions):
            mnem = insn.get('mnemonic', '').lower()
            if mnem not in _TAINT_PROPAGATION_OPS:
                continue
            # 前序指令携带污点时传播（线性近似）
            if idx > 0 and (idx - 1) in taint_map:
                prev_taint = taint_map[idx - 1]
                if idx not in taint_map or not prev_taint.issubset(taint_map.get(idx, set())):
                    taint_map.setdefault(idx, set()).update(prev_taint)
                    changed = True
    return taint_map

def detect_taint_sinks(instructions: list[dict],
                        taint_map: dict[int, set[str]]) -> list[dict]:
    """检测污点汇 — 带污点数据到达危险调用点。
    返回 [{'insn_idx': int, 'sink_type': str, 'taint_labels': [...]}]。"""
    # 危险汇点分类表
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
