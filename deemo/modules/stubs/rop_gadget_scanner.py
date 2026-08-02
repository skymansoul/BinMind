# rop_gadget_scanner.py — ROP Gadget 扫描器
# 在二进制中搜索、分类和评估 ROP gadget，生成利用链候选。
# 参考: ropbot (2024) — 代码重用攻击合成，自动化 gadget 发现与链组装 &
#   ARG: Automatic ROP Chains Generation (CODASPY 2017) &
#   Stitching the Gadgets (2014) — 粗粒度 CFI 的绕过分析
import os as _os, struct as _pack, re as _re
from collections import defaultdict as _defdict

# x86-64 RET 指令操作码 — gadget 的基本终结符
_RET_OPCODES = {0xC3, 0xC2, 0xCB, 0xCA}  # ret, ret imm16, far ret, far ret imm16
_GADGET_MAX_LEN = 32  # gadget 最大指令字节数

def find_gadgets(code_section: bytes, base_addr: int = 0) -> list[dict]:
    """在代码段中扫描以 ret 结尾的 gadget。
    返回 [{'addr': int, 'bytes': bytes, 'len': int, 'category': str}]。
    单次线性扫描，O(n)，n 为代码段字节数。"""
    gadgets = []
    # 构建 ret 指令位置索引
    ret_positions = [i for i, b in enumerate(code_section) if b in _RET_OPCODES]

    for ret_pos in ret_positions:
        # 从 ret 位置向前搜索至多 GADGET_MAX_LEN 字节
        start = max(0, ret_pos - _GADGET_MAX_LEN)
        chunk = code_section[start:ret_pos + 1]
        # 从 chunk 的每个偏移尝试反汇编（简化：按字节偏移枚举）
        for offset in range(len(chunk)):
            candidate = chunk[offset:]
            if len(candidate) < 1 or candidate[-1] not in _RET_OPCODES:
                continue
            if len(candidate) > _GADGET_MAX_LEN:
                continue
            addr = base_addr + start + offset
            # 分类 — 基于指令字节特征
            cat = _classify_gadget(candidate)
            gadgets.append({
                'addr': addr,
                'bytes': candidate.hex(),
                'len': len(candidate),
                'category': cat,
            })
            break  # 每个 ret 只取最近的候选
    return gadgets

def _classify_gadget(gadget_bytes: bytes) -> str:
    """基于字节特征对 gadget 分类。ropbot 定义了 6 类语义 gadget；
    此处使用简化的操作码模式匹配。"""
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
    """评估 gadget 在 ROP 链中的可用性（ropbot 评分启发式）。
    高评分: pop 类 gadget（设置寄存器）、无副作用指令。
    低评分: 间接调用、复杂内存操作。"""
    cat_weights = {'pop_register': 0.9, 'mov_load_store': 0.7,
                   'arithmetic': 0.5, 'call_indirect': 0.2, 'other': 0.3}
    base = cat_weights.get(gadget.get('category', 'other'), 0.3)
    # 长度惩罚 — 过长 gadget 导致 ROP 链不稳定
    length_penalty = 1.0 - (gadget.get('len', 0) / (_GADGET_MAX_LEN * 2))
    return base * max(0.3, min(1.0, length_penalty))
