# coding: utf-8
"""
栈溢出检测 — 基于 IR 级帧分析 + 污点约束.

方法:
  1. 识别函数的栈帧: sub rsp, N → 帧大小 = N
  2. 检测栈缓冲区写入: 识别 [rbp-offset] 或 [rsp+offset] 的 store 操作
  3. 写入大小 vs 缓冲区大小比对: 若 write_size > buffer_size → 溢出候选
  4. 污点过滤: 反向追踪写入数据源 — 仅外部可控数据标记为可利用
  5. Canary 检测: 若函数包含 __stack_chk_fail 调用 → 有栈保护 (降低置信度)

关键洞察:
  仅靠帧大小和写入大小比对产生大量误报 (memcpy 到栈上的正常操作).
  必须结合污点源过滤 + canary 感知 + 写入模式分析 (连续 vs 离散).
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class StackFrame:
    """函数的栈帧分析结果."""
    func_addr: int
    frame_size: int          # sub rsp, N 的值
    buffers: List[Dict]      # [{offset, size, name}, ...] 栈上的缓冲区
    has_canary: bool         # 是否有栈保护
    canary_check_addr: int = 0


@dataclass
class StackOverflowCandidate:
    """栈溢出候选."""
    func_addr: int
    write_site: int          # 写入指令地址
    buffer_offset: int       # 缓冲区在栈上的偏移
    buffer_size: int         # 声明的缓冲区大小
    write_size: int          # 实际写入大小 (0 = 未知/动态)
    is_user_controlled: bool
    has_canary: bool
    exploitable: bool
    confidence: float
    detail: str = ''


# 栈帧探测: sub rsp, imm / push rbp; mov rbp, rsp; sub rsp, imm
_FRAME_PROLOG_PATTERNS = [
    re.compile(r'sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)', re.I),
    re.compile(r'push\s+rbp.*?sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)', re.I | re.DOTALL),
]

# 栈缓冲区写入: mov [rbp-N], src 或 lea rdi, [rbp-N]; call memcpy
_STACK_STORE_PATTERN = re.compile(
    r'(?:mov|lea|store).*?(?:rbp|rsp|ebp|esp)\s*[-+]\s*(0x[0-9a-fA-F]+|\d+)', re.I)

# canary 检测: __stack_chk_fail 或 fs:0x28 访问
_CANARY_PATTERNS = [
    re.compile(r'__stack_chk_fail', re.I),
    re.compile(r'fs:\s*0x28', re.I),
    re.compile(r'security_cookie', re.I),
]


def analyze_stack_frame(
    func_addr: int,
    disasm_lines: List[str],
    ir_ops: Optional[Dict[int, Dict]] = None,
) -> StackFrame:
    """分析单个函数的栈帧.

    disasm_lines: 反汇编文本行列表.
    ir_ops: 可选的 IR 操作映射 (用于更精确的帧大小推断).
    """
    frame_size = 0
    has_canary = False
    canary_addr = 0
    buffers: List[Dict] = []

    disasm_text = '\n'.join(disasm_lines[:30])  # 只看前30行 (序言+局部变量)

    # 帧大小检测
    for pattern in _FRAME_PROLOG_PATTERNS:
        m = pattern.search(disasm_text)
        if m:
            val = m.group(2)
            if val.startswith('0x'):
                frame_size = int(val, 16)
            else:
                frame_size = int(val)
            break

    # canary 检测
    for pattern in _CANARY_PATTERNS:
        if pattern.search(disasm_text):
            has_canary = True
            break

    # 缓冲区识别: 在 [rbp-N] 处的 store + 对 memcpy 的调用暗示了缓冲区
    for i, line in enumerate(disasm_lines):
        m = _STACK_STORE_PATTERN.search(line)
        if m:
            offset_str = m.group(1)
            offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
            # 估算缓冲区大小: 找相邻的 store, 差值即缓冲区大小
            buffers.append({'offset': offset, 'size': 0, 'name': f'buf_{offset:x}',
                           'line': i})

    # 合并相邻偏移量的缓冲区 (间距 < 64B 视为同一缓冲区)
    if buffers:
        buffers.sort(key=lambda b: b['offset'])
        merged = [buffers[0]]
        for b in buffers[1:]:
            prev = merged[-1]
            gap = abs(b['offset'] - prev['offset'])
            if gap < 64:
                prev['size'] = max(prev['size'], gap + b.get('size', 8))
                prev['name'] = f'{prev["name"]}_{b["name"]}'
            else:
                merged.append(b)
        buffers = merged

    # 为没有推断出大小的缓冲区赋默认值
    for b in buffers:
        if b['size'] == 0:
            b['size'] = 16  # 保守假设

    return StackFrame(
        func_addr=func_addr, frame_size=frame_size,
        buffers=buffers, has_canary=has_canary,
        canary_check_addr=canary_addr,
    )


def detect_stack_overflow(
    frames: List[StackFrame],
    write_ops: Dict[int, Dict],      # addr → {size, target, source, ...}
    taint_map: Dict[int, Dict],      # addr → {source_type, source_desc}
    instructions: Optional[List[Dict]] = None,
) -> List[StackOverflowCandidate]:
    """检测栈溢出候选.

    frames: analyze_stack_frame 的输出列表.
    write_ops: 所有写入操作的映射 (地址 → 操作详情).
    taint_map: 污点映射.
    """
    candidates = []
    frame_by_addr = {f.func_addr: f for f in frames}

    for addr, op in write_ops.items():
        write_size = op.get('write_size', op.get('size', 0))
        target = op.get('target', '')
        source = op.get('source', '')

        # 定位所属函数
        func_addr = op.get('func_addr', 0)
        frame = frame_by_addr.get(func_addr)
        if frame is None:
            continue

        # 匹配到栈缓冲区
        for buf in frame.buffers:
            buf_off = buf['offset']
            buf_sz = buf['size']
            if buf_sz <= 0:
                continue

            # 检查写入是否超出缓冲区
            if write_size > buf_sz:
                taint = taint_map.get(addr, {})
                is_ctrl = taint.get('source_type', '') in (
                    'external_input', 'file_input', 'network')

                conf = 0.5
                if is_ctrl:
                    conf += 0.25
                if write_size > buf_sz * 2:
                    conf += 0.15  # 显著超出 → 更像是漏洞而非巧合
                if frame.has_canary:
                    conf *= 0.7   # canary 增加了利用难度
                else:
                    conf += 0.10  # 无保护 → 更容易利用

                detail = (f'写入 {write_size}B 到 {buf_sz}B 缓冲区 '
                         f'(rbp-{buf_off:#x}), '
                         f'超出 {write_size - buf_sz}B')
                if frame.has_canary:
                    detail += ', 有 canary 保护'
                if is_ctrl:
                    detail += f', 数据来自 {taint.get("source_desc", "外部输入")}'

                candidates.append(StackOverflowCandidate(
                    func_addr=func_addr, write_site=addr,
                    buffer_offset=buf_off, buffer_size=buf_sz,
                    write_size=write_size, is_user_controlled=is_ctrl,
                    has_canary=frame.has_canary,
                    exploitable=(is_ctrl and write_size > buf_sz),
                    confidence=min(1.0, conf),
                    detail=detail,
                ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates


def summarize_stack_findings(candidates: List[StackOverflowCandidate]) -> Dict[str, Any]:
    exploitable = [c for c in candidates if c.exploitable]
    with_canary = [c for c in candidates if c.has_canary]
    return {
        'total_candidates': len(candidates),
        'exploitable': len(exploitable),
        'with_canary': len(with_canary),
        'avg_overflow_bytes': round(
            sum(c.write_size - c.buffer_size for c in candidates) / max(1, len(candidates)), 1),
        'avg_confidence': round(sum(c.confidence for c in candidates) / max(1, len(candidates)), 2),
    }
