# rop_gadget_scanner.py — ROP 指令片段扫描与利用链评估
# 在代码段中定位以 ret 结尾的指令序列，分类并量化其在 ROP 链中的可用性。
# 参考: ropbot (2024) — 自动化 gadget 发现与链组装 &
#   ARG: Automatic ROP Chains Generation (CODASPY 2017) &
#   Stitching the Gadgets (2014) — 粗粒度 CFI 绕过分析
import os as _os, struct as _pack, re as _re
from collections import defaultdict as _defdict

# x86-64 RET 操作码集合 — 每条 gadget 以此类指令结束
_RET_OPCODES = {0xC3, 0xC2, 0xCB, 0xCA}  # ret, ret imm16, far ret, far ret imm16
_GADGET_MAX_LEN = 32  # 单条 gadget 所允许的最大指令字节跨度

def find_gadgets(code_section: bytes, base_addr: int = 0) -> list[dict]:
    """在代码段中扫描以 ret 结尾的指令序列。
    返回 [{'addr': int, 'bytes': str, 'len': int, 'category': str}]。
    线性扫描，O(n)，n 为代码段长度。"""
    gadgets = []
    # 标记所有 ret 指令在段内的偏移位置
    ret_positions = [i for i, b in enumerate(code_section) if b in _RET_OPCODES]

    for ret_pos in ret_positions:
        # 从 ret 位置向前回溯，截取最长不超过 GADGET_MAX_LEN 的窗口
        start = max(0, ret_pos - _GADGET_MAX_LEN)
        chunk = code_section[start:ret_pos + 1]
        # 对窗口内每个偏移切出一条候选片段
        for offset in range(len(chunk)):
            candidate = chunk[offset:]
            if len(candidate) < 1 or candidate[-1] not in _RET_OPCODES:
                continue
            if len(candidate) > _GADGET_MAX_LEN:
                continue
            addr = base_addr + start + offset
            # 按操作码特征归类
            cat = _classify_gadget(candidate)
            gadgets.append({
                'addr': addr,
                'bytes': candidate.hex(),
                'len': len(candidate),
                'category': cat,
            })
            break  # 每个 ret 指令仅保留最近一条候选
    return gadgets

def _classify_gadget(gadget_bytes: bytes) -> str:
    """基于字节模式对 gadget 做语义归类。
    ropbot 定义了 6 类语义 gadget；此处使用操作码的启发式模式匹配。"""
    hex_str = gadget_bytes.hex()
    if '58' in hex_str or '5f' in hex_str or '5e' in hex_str or '5d' in hex_str or '5b' in hex_str or '59' in hex_str:
        return 'pop_register'
    if '8b' in hex_str or '89' in hex_str:
        return 'mov_load_store'
    if '01' in hex_str or '29' in hex_str or '31' in hex_str:
        return 'arithmetic'
    if 'ff' in hex_str or 'e8' in hex_str:
        return 'call_indirect'
    return 'other'


def score_gadget_utility(gadget: dict) -> float:
    """评估 gadget 在 ROP 链中的利用价值（ropbot 评分启发式）。
    高分: pop 类指令可写寄存器、无副作用。
    低分: 间接调用、复杂内存操作导致链不稳定。"""
    cat_weights = {'pop_register': 0.9, 'mov_load_store': 0.7,
                   'arithmetic': 0.5, 'call_indirect': 0.2, 'other': 0.3}
    base = cat_weights.get(gadget.get('category', 'other'), 0.3)
    # 长度惩罚 — 过长片段增加链构造的约束复杂度
    length_penalty = 1.0 - (gadget.get('len', 0) / (_GADGET_MAX_LEN * 2))
    return base * max(0.3, min(1.0, length_penalty))
