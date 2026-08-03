# ROP/JOP/SYS 指令片段扫描器 — 自动发现可利用的代码片段
# 参考: "War on JITs" (Ducasse et al. ACM Computing Surveys 2025) —
#       JIT-ROP 的 gadget 发现与分类框架
# 参考: "Jump-oriented programming: a new class of code-reuse attack"
#       (Bletsch et al. AsiaCCS 2011) — JOP dispatcher gadget 的识别模式
# 参考: "Control-Flow Bending" (Carlini et al. USENIX 2015) —
#       非控制数据攻击的 gadget 利用

import re as _re, struct as _struct
from collections import defaultdict

# ===== ROP gadget 匹配 =====
# x86-64 ROP gadget 以 ret (0xC3) 或间接跳转 (0xFF 0xE0-0xE7) 结尾
# gadget 最长 32 字节 — 覆盖典型 ROP 链的单个片段（实际利用中通常 < 20B）

_GADGET_MAX_LEN = 32
_GADGET_MIN_LEN = 2

# ROP 结尾操作码
_ROP_TERMINATORS = frozenset({
    0xC3,          # ret
    0xC2,          # ret imm16
    0xCB,          # far ret
    0xCA,          # far ret imm16
})

# JOP 结尾操作码 (jmp reg / call reg)
_JOP_TERMINATORS = frozenset({
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,  # jmp rax..rdi
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,  # call rax..rdi
})


def scan_rop_gadgets(code_bytes: bytes, base_addr: int = 0) -> list[dict]:
    """扫描二进制代码段中的 ROP gadget。
    对每个 ret 指令（及其前导的 FF /4 jmp），反向搜索最多 32 字节作为 gadget 体。

    返回的每个 gadget 包含:
    - address: 在二进制中的虚拟地址
    - bytes: gadget 的字节码 (hex)
    - disasm: 助记符序列
    - category: 'stack_pivot'|'load_reg'|'store_mem'|'syscall'|'arithmetic'|'other'
    - usefulness: 'high'|'medium'|'low' (基于后续可利用性)"""
    gadgets = []

    for i in range(len(code_bytes)):
        byte_val = code_bytes[i]
        # ROP terminator check
        if byte_val in _ROP_TERMINATORS:
            start = max(0, i - _GADGET_MAX_LEN)
            # 反向搜索更短的 gadget 变体（从同一 ret 出发的不同前缀）
            for j in range(start, i - _GADGET_MIN_LEN + 1):
                gbytes = code_bytes[j:i + 1]
                # 过滤含非指令前缀的片段 — 在真实引擎中通过反汇编器验证
                if len(gbytes) < _GADGET_MIN_LEN:
                    continue
                category, useful = _classify_gadget(gbytes)
                gadgets.append({
                    'address': base_addr + j,
                    'size': len(gbytes),
                    'bytes': gbytes.hex(),
                    'terminator': f'ret (0x{byte_val:02x})',
                    'category': category,
                    'usefulness': useful,
                })
            # 每个 ret 只取最多 5 个变体
            gadgets = gadgets[:-max(0, len(gadgets) - (i - start) * 5)] if i > start + 5 else gadgets

        # JOP terminator: jmp [reg] pattern (0xFF 0xE0-0xE7)
        elif byte_val == 0xFF and i + 1 < len(code_bytes):
            next_byte = code_bytes[i + 1]
            if next_byte in _JOP_TERMINATORS:
                start = max(0, i - _GADGET_MAX_LEN)
                for j in range(start, i - _GADGET_MIN_LEN + 1):
                    gbytes = code_bytes[j:i + 2]
                    if len(gbytes) < _GADGET_MIN_LEN:
                        continue
                    category, useful = _classify_gadget(gbytes)
                    gadgets.append({
                        'address': base_addr + j,
                        'size': len(gbytes),
                        'bytes': gbytes.hex(),
                        'terminator': 'jmp/call reg',
                        'category': f'JOP_{category}',
                        'usefulness': useful,
                    })

    return gadgets


# ===== Gadget 分类 =====
def _classify_gadget(gbytes: bytes) -> tuple[str, str]:
    # 操作码模式分类 → 自动化 ROP 链合成
    hex_str = gbytes.hex()

    # 栈 pivot: xchg eax,esp; ret / mov esp, eax; ret / leave; ret
    if any(pat in hex_str for pat in ('94c3', '89c4c3', 'c9c3', '8724c3',
                                       '87244c3', '89e0c3')):
        return ('stack_pivot', 'high')

    # pop reg; ret → 加载寄存器
    pop_pattern = _re.match(rb'([\x41\x58-\x5f])' + b'[\xc3\xc2]', gbytes[-2:])
    if pop_pattern:
        return ('load_reg', 'high')

    # mov [reg], reg; ret → 写内存
    if _re.search(rb'[\x89\x88\x89]\x03', gbytes):
        return ('store_mem', 'high')

    # syscall / sysenter / int 0x80
    if any(pat in gbytes for pat in (b'\x0f\x05', b'\x0f\x34', b'\xcd\x80')):
        return ('syscall', 'high')

    # 算术: add/sub/xor + ret
    if any(op in gbytes[:-1] for op in (b'\x01', b'\x29', b'\x31', b'\x09', b'\x21')):
        return ('arithmetic', 'medium')

    # xor reg, reg; ret → 清零 (常见于 ROP 链初始化)
    if _re.search(rb'\x31[\xc0-\xff]|\x33[\xc0-\xff]', gbytes):
        if gbytes[-1] in _ROP_TERMINATORS:
            return ('zero_reg', 'medium')

    return ('other', 'low')


# ===== Gadget 去重 =====
# 同一 gadget 可能被多个 ret 找到（共享字节前缀）— 去重保留地址最低/最短的版本
def deduplicate_gadgets(gadgets: list[dict]) -> list[dict]:
    # 去重: 相同(bytes, category)仅保留地址最小者
    seen: dict[tuple[str, str], dict] = {}
    for g in gadgets:
        key = (g['bytes'], g['category'])
        if key not in seen or g['address'] < seen[key]['address']:
            seen[key] = g
    return sorted(seen.values(), key=lambda g: g['address'])


# ===== SYS gadget 扫描 =====
# syscall (0F 05) 和 sysenter (0F 34) 在 x64 上为特权指令
# 在 gadget 上下文中，syscall 前的指令决定系统调用号和参数
# 参考: "Sigreturn-Oriented Programming" (Bosman & Bos 2014) —
#       SROP 利用信号帧构造任意系统调用序列

def scan_syscall_gadgets(code_bytes: bytes, base_addr: int = 0) -> list[dict]:
    """扫描代码段中系统调用相关的 gadget。
    识别 syscall; ret 和 syscall 前有 rax 设置的 gadget 模式。"""
    gadgets = []
    syscall_ops = {b'\x0f\x05': 'syscall', b'\x0f\x34': 'sysenter', b'\xcd\x80': 'int80'}

    for i in range(len(code_bytes) - 1):
        window = code_bytes[i:i + 2]
        if window in syscall_ops:
            # 向前搜索: 看 rax/eax 是否被设置
            rax_set = False
            rax_value = None
            for j in range(max(0, i - 16), i):
                b = code_bytes[j]
                if b in (0xB8,):  # mov eax, imm32
                    rax_value = _struct.unpack_from('<I', code_bytes, j + 1)[0]
                    rax_set = True
                    break
                if b in (0x48, 0x49) and j + 2 < i:  # REX.W mov rax, imm32
                    if code_bytes[j + 1] in (0xB8, 0xC7):
                        rax_value = _struct.unpack_from('<I', code_bytes, j + 2)[0]
                        rax_set = True
                        break

            # 向后搜索 ret
            has_ret = any(code_bytes[k] in _ROP_TERMINATORS
                         for k in range(i + 2, min(len(code_bytes), i + 10)))

            if has_ret:
                gadgets.append({
                    'address': base_addr + i,
                    'type': syscall_ops[window],
                    'syscall_number': rax_value if rax_set else 'unknown',
                    'has_ret': True,
                    'preceding_bytes': code_bytes[max(0, i - 8):i].hex(),
                })

    return gadgets


# ===== 按用途索引 Gadgets =====
# 构建分类索引 — 加速 ROP 链自动合成
# 参考: ROPgadget / ropper 的 gadget 分类体系

def build_gadget_index(gadgets: list[dict]) -> dict[str, list[dict]]:
    """按操作类型对 gadget 建索引。
    索引键: 'pop_*', 'mov_*', 'add_*', 'xor_*', 'syscall', 'stack_pivot', 'call_*'

    此索引为 ROP 链自动合成提供 O(1) 查找 — 编译器根据所需操作快速定位候选。"""
    idx: dict[str, list[dict]] = defaultdict(list)

    for g in gadgets:
        cat = g.get('category', 'other')
        idx[cat].append(g)

        # 细化子类: pop rdi vs pop rsi
        gbytes = bytes.fromhex(g['bytes'])
        if gbytes and gbytes[0] in (0x41,):  # REX prefix
            reg_idx = gbytes[1] - 0x58 if len(gbytes) > 1 and 0x58 <= gbytes[1] <= 0x5F else -1
            if 0 <= reg_idx < 8:
                idx[f'pop_r{reg_idx}'].append(g)
        elif gbytes and 0x58 <= gbytes[0] <= 0x5F:
            reg_idx = gbytes[0] - 0x58
            idx[f'pop_r{reg_idx}'].append(g)

    return dict(idx)


# --- Headless 批量 Gadget 扫描 ---
def headless_scan_gadgets(binary_paths: list[str], output_json: str = '') -> dict:
    """批量扫描多个二进制文件的 ROP/JOP/SYS gadget。
    对每个文件输出 gadget 统计和分类分布。"""
    import json as _json
    results = {}
    for bp in binary_paths:
        try:
            with open(bp, 'rb') as f:
                data = f.read()
            rop = scan_rop_gadgets(data)
            rop_dedup = deduplicate_gadgets(rop)
            syscall = scan_syscall_gadgets(data)
            idx = build_gadget_index(rop_dedup)
            results[bp] = {
                'status': 'ok',
                'rop_gadgets': len(rop_dedup),
                'syscall_gadgets': len(syscall),
                'categories': {k: len(v) for k, v in idx.items()},
                'high_usefulness': sum(1 for g in rop_dedup if g.get('usefulness') == 'high'),
            }
        except Exception as exc:
            results[bp] = {'status': 'error', 'reason': str(exc)}
    out = {'total_binaries': len(binary_paths), 'results': results}
    if output_json:
        with open(output_json, 'w') as f:
            _json.dump(out, f, indent=2)
    return out
