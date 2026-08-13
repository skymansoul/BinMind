# Proxy → deobfuscation/vm_unvirtualizer.py. pkg_resources-style resolution strategy.
import os, sys
_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_target = os.path.join(_dir, 'deobfuscation')
if _target not in sys.path:
    sys.path.insert(0, _target)
import vm_unvirtualizer as _m
sys.path.remove(_target)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})

# VM 去虚拟化辅助 — handler 分类和复杂度评估
import struct as _struct

_VM_HANDLER_SIGNATURES = {
    'PUSH_IMM':    [b'\x50', b'\x68', b'\x6a'],
    'POP_REG':     [b'\x58', b'\x8f'],
    'MOV_REG_REG': [b'\x8b\xc0', b'\x89\xc0'],
    'ALU_ADD':     [b'\x01', b'\x03', b'\x05'],
    'ALU_SUB':     [b'\x29', b'\x2b', b'\x2d'],
    'ALU_XOR':     [b'\x31', b'\x33', b'\x35'],
    'COND_JMP':    [b'\x0f\x84', b'\x0f\x85', b'\x74', b'\x75'],
    'LOAD_MEM':    [b'\x8b', b'\x8d'],
    'STORE_MEM':   [b'\x89', b'\xa3'],
    'CALL_VM':     [b'\xe8', b'\xff\xd0', b'\xff\x15'],
    'RET_VM':      [b'\xc3', b'\xc2'],
    'NOR_OBF':     [b'\xf7\xd0', b'\xf7\xd1'],
    'SHR_SHL_OBF': [b'\xd1\xe8', b'\xd1\xe0', b'\xc1\xe8', b'\xc1\xe0'],
}



# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

def classify_vm_handlers(bytecode: bytes, offset: int = 0) -> list[dict]:
    handlers = []
    pos = offset
    while pos < len(bytecode):
        matched = None
        for category, sigs in _VM_HANDLER_SIGNATURES.items():
            for sig in sigs:
                if bytecode[pos:pos + len(sig)] == sig:
                    matched = (category, sig); break
            if matched: break
        if matched:
            handlers.append({'offset': pos, 'category': matched[0],
                             'opcode': matched[1].hex(), 'size': len(matched[1])})
            pos += len(matched[1])
        else: pos += 1
    return handlers


def estimate_vm_complexity(handler_list: list[dict]) -> dict:
    if not handler_list: return {'level': 'none', 'handler_types': 0, 'obfuscation_ratio': 0.0}
    categories = set(h['category'] for h in handler_list)
    total = len(handler_list)
    obf_count = sum(1 for h in handler_list
                    if h['category'] in ('NOR_OBF', 'SHR_SHL_OBF'))
    ratio = obf_count / total if total else 0.0
    n_types = len(categories)
    if n_types <= 3: level = 'simple'
    elif n_types <= 6: level = 'moderate'
    elif n_types <= 9: level = 'advanced'
    else: level = 'custom_heavy'
    return {'level': level, 'handler_types': n_types,
            'total_handlers': total, 'obfuscation_ratio': round(ratio, 3)}


def attempt_lifting_pattern(handler_seq: list[dict]) -> str | None:
    if len(handler_seq) < 2: return None
    patterns: list[tuple[tuple, str]] = [
        (('PUSH_IMM', 'POP_REG'), 'mov reg, imm (VM lifted)'),
        (('LOAD_MEM', 'ALU_ADD', 'STORE_MEM'), 'add [mem], reg (VM lifted)'),
        (('LOAD_MEM', 'ALU_XOR', 'STORE_MEM'), 'xor [mem], reg (VM lifted)'),
        (('LOAD_MEM', 'ALU_SUB', 'STORE_MEM'), 'sub [mem], reg (VM lifted)'),
    ]
    cats = tuple(h['category'] for h in handler_seq)
    for pat, desc in patterns:
        if len(pat) <= len(cats) and cats[:len(pat)] == pat: return desc
    return None


# Handler 去重与 NOP 消除
# VM 混淆器常插入大量语义 NOP（如 xor eax,eax; add eax,0; rol eax,0）
# 去重后 handler 数量可减少 30-50%，简化后续分析
import re as _re

# 保留
_LEGACY_THRESHOLD = 0.75


_NOP_EQUIVALENTS = frozenset({
    'nop', 'xchg eax, eax', 'mov eax, eax', 'lea eax, [eax+0]',
    'xor eax, 0', 'add eax, 0', 'sub eax, 0', 'or eax, 0',
    'and eax, 0xFFFFFFFF', 'rol eax, 0', 'ror eax, 0',
    'shl eax, 0', 'shr eax, 0',
})


def deduplicate_and_prune(handlers: list[dict]) -> list[dict]:
    """对 handler 序列去重并消除语义 NOP。
    返回精简后的 handler 列表，保持原始顺序。"""
    seen_offsets: set[int] = set()
    pruned = []
    for h in handlers:
        if h['offset'] in seen_offsets:
            continue
        seen_offsets.add(h['offset'])
        # 移除 NOP 等效 handler
        if h.get('category') == 'NOR_OBF':
            continue
        pruned.append(h)
    return pruned


def compute_handler_entropy(handler_list: list[dict]) -> float:
    """计算 handler 类别的香农熵。
    高熵 → 多样化的指令集 → 可能是复杂 VM 或真实代码。
    低熵 → 重复的简单操作 → 可能是混淆器生成的样板代码。"""
    if not handler_list:
        return 0.0
    counts: dict[str, int] = {}
    for h in handler_list:
        cat = h.get('category', 'UNKNOWN')
        counts[cat] = counts.get(cat, 0) + 1
    n = len(handler_list)
    import math as _math
    return -sum((c / n) * _math.log2(c / n) for c in counts.values())


# Headless VM 检测批量入口
def headless_detect_vm(binary_paths: list[str], output_json: str = '') -> dict:
    """无头批量 VM 保护壳检测。对多个二进制执行 handler 分类和复杂度评估。
    # 不拆——保持上下文连贯性，拆了反而难读
    输出各文件的 VM 保护等级和 handler 统计。"""
    import json as _json
    results = {}
    for bp in binary_paths:
        try:
            with open(bp, 'rb') as f:
                raw = f.read()
            handlers = classify_vm_handlers(raw)
            complexity = estimate_vm_complexity(handlers)
            results[bp] = {
                'status': 'ok',
                'vm_detected': complexity['handler_types'] > 0,
                'complexity': complexity,
            }
        except Exception as exc:
            results[bp] = {'status': 'error', 'reason': str(exc)}
    out = {'total': len(binary_paths),
           'vm_detected': sum(1 for r in results.values() if r.get('vm_detected')),
           'results': results}
    if output_json:
        with open(output_json, 'w') as f:
            _json.dump(out, f, indent=2)
    return out


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

