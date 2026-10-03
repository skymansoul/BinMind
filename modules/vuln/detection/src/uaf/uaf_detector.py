"""UAF 检测器 — 指令级扫描 + 时序路径验证.

创建: 2024-09-02
目的: 整合 UAFTemporalVerifier 的四态时序分析到检测管线中.
      替代 uaf_regression_runner.py 中的骨架 detect_uaf().

管线:
  1. 解析 objdump 指令 → (mnemonic, op_str, addr) 三元组
  2. 扫描 free 调用点, 追踪被释放的指针寄存器
  3. 在 free 后的指令中检测通过该寄存器的解引用
  4. 对每个 free→use 候选, 调用 UAFTemporalVerifier.verify()
  5. 输出带时序判定的结构化 findings

决策:
  - 同时支持 MS x64 (rcx=arg1) 和 System V (rdi=arg1) ABI
  - mov 链追踪: mov rbx, rax; call free; ... mov rcx, rbx; call free → 别名
  - 跨函数边界不做追踪 — 仅在同一函数内的指令流中分析
"""

from typing import Dict, List, Optional, Set, Tuple

try:
    from .uaf_temporal_verifier import (
        UAFTemporalVerifier, TemporalVerdict, SafetyProof,
    )
except ImportError:
    from uaf_temporal_verifier import (  # type: ignore[no-redef]
        UAFTemporalVerifier, TemporalVerdict, SafetyProof,
    )

# free-family 函数名子串
_FREE_FUNCTIONS = {'free', '_Zdl', '_Zda', 'HeapFree', 'free@plt',
                   'realloc', 'realloc@plt'}

# 参数传递寄存器 — 第一参数 (指针)
_ARG1_REGS = {'rcx', 'ecx', 'rdi', 'edi', 'cx', 'di'}

# x86-64 通用寄存器 (用于 mov 链追踪)
_GPRS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9',
         'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
         'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'}

# 安全信号 — 清零/置空
_NULLIFY_MNEMS = {'xor', 'mov', 'lea', 'and'}


def parse_instruction(instr: str) -> Tuple[str, str]:
    """解析一行 objdump 输出 → (mnemonic, op_str)."""
    parts = instr.split(maxsplit=1)
    if len(parts) == 0:
        return ('', '')
    if len(parts) == 1:
        return (parts[0].lower(), '')
    return (parts[0].lower(), parts[1])


def _is_free_call(mnem: str, ops: str) -> bool:
    """判断是否为 free/realloc 调用."""
    if mnem != 'call':
        return False
    target = ops.lower().strip('<>@')
    return any(fn in target for fn in _FREE_FUNCTIONS)


def _extract_ptr_reg(instrs: List[Tuple[str, str, int]],
                     call_idx: int) -> Optional[str]:
    """从 free 调用前的指令中提取被释放的指针寄存器.

    回溯最多5条指令, 找 mov arg1_reg, ptr_reg 模式.
    """
    for j in range(max(0, call_idx - 5), call_idx):
        mnem, ops, _ = instrs[j]
        if mnem not in ('mov', 'movabs', 'lea'):
            continue
        parts = [p.strip() for p in ops.split(',')]
        if len(parts) < 2:
            continue
        dst = parts[0].lower()
        src = parts[1].lower()
        if dst in _ARG1_REGS and src in _GPRS:
            return src
        # 直接传地址: lea rcx, [rip+...] 或 mov rcx, [rbp-...]
        if dst in _ARG1_REGS:
            return dst
    return None


def _find_reg_deref(instrs: List[Tuple[str, str, int]],
                    from_idx: int, reg: str,
                    window: int = 80) -> List[int]:
    """在 [from_idx, from_idx+window] 范围内找 reg 的解引用.

    返回 use 地址列表.
    """
    uses = []
    reg_variants = {reg.lower(), reg.upper()}
    # 64↔32bit 变体: rax↔eax, rbx↔ebx 等
    _32to64 = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
               'esi': 'rsi', 'edi': 'rdi', 'r8d': 'r8', 'r9d': 'r9'}
    _64to32 = {v: k for k, v in _32to64.items()}
    for r in list(reg_variants):
        r_lower = r.lower()
        if r_lower in _32to64:
            reg_variants.add(_32to64[r_lower])
        if r_lower in _64to32:
            reg_variants.add(_64to32[r_lower])

    for i in range(from_idx, min(from_idx + window, len(instrs))):
        mnem, ops, addr = instrs[i]
        # 检测清零: xor reg, reg 或 mov reg, 0
        if mnem == 'xor':
            parts = [p.strip().lower() for p in ops.split(',')]
            if len(parts) == 2 and parts[0] == parts[1] and parts[0] in reg_variants:
                break  # reg 清零 → 后续不再有 UAF
        if mnem == 'mov':
            parts = [p.strip().lower() for p in ops.split(',')]
            if len(parts) == 2 and parts[0] in reg_variants and parts[1] in ('0', '0x0'):
                break

        # 检测通过 reg 的解引用: [reg], [reg+...], qword [reg] 等
        if any(f'[{v}]' in ops.lower() or f'[{v}+' in ops.lower()
               or f'[{v}-' in ops.lower() for v in reg_variants):
            uses.append(addr)

        # 检测 mov 到其他寄存器 → 扩展追踪 (但不去重追踪)
        if mnem == 'mov':
            parts = [p.strip().lower() for p in ops.split(',')]
            if len(parts) == 2 and parts[1] in reg_variants and parts[0] in _GPRS:
                new_reg = parts[0]
                reg_variants.update({new_reg, new_reg.lower(), new_reg.upper()})

    return uses


def detect_uaf(insns: List[str], addrs: List[int]) -> dict:
    """对指令序列执行集成 UAF 检测.

    管线:
      1. 解析指令 → (mnem, op_str, addr)
      2. 定位 free 调用 + 追踪被释放的指针寄存器
      3. 扫描 free 后的解引用
      4. UAFTemporalVerifier 做四态时序安全证明
      5. 输出带 verdict 的 findings
    """
    findings: List[dict] = []
    instrs: List[Tuple[str, str, int]] = []

    for insn_text, addr in zip(insns, addrs):
        mnem, ops = parse_instruction(insn_text)
        instrs.append((mnem, ops, addr))

    verifier = UAFTemporalVerifier()
    verifier.load_instructions(instrs)

    # 找所有 free/realloc 调用
    free_calls: List[Tuple[int, str, bool]] = []  # [(idx, ptr_reg, is_realloc)]
    for i, (mnem, ops, addr) in enumerate(instrs):
        if _is_free_call(mnem, ops):
            ptr_reg = _extract_ptr_reg(instrs, i)
            if ptr_reg:
                is_realloc = 'realloc' in ops.lower()
                free_calls.append((i, ptr_reg, is_realloc))

    if not free_calls:
        return {'findings': [], 'n_findings': 0, 'detected': False}

    # 对每个 free/realloc, 找后续 use
    for free_idx, ptr_reg, is_realloc in free_calls:
        free_addr = instrs[free_idx][2]
        use_addrs = _find_reg_deref(instrs, free_idx + 1, ptr_reg)

        for use_addr in use_addrs:
            # realloc 返回值 (rax/eax) 是有效的 — 跳过通过新指针的访问
            if is_realloc:
                _, use_ops, _ = instrs[
                    next((j for j in range(free_idx + 1, len(instrs))
                         if instrs[j][2] == use_addr), free_idx + 1)]
                # 若解引用通过 rax/eax (realloc 返回值) → 安全, 跳过
                if any(r in use_ops.lower()
                       for r in ('[rax]', '[rax+', '[rax-',
                                 '[eax]', '[eax+', '[eax-')):
                    continue
            # 调用时序验证器
            proof = verifier.verify(ptr_reg, free_addr, use_addr)

            # 映射 TemporalVerdict → finding 数据
            verdict_map = {
                TemporalVerdict.DEFINITELY_UAF: ('DEFINITELY_UAF', 0.90),
                TemporalVerdict.POTENTIAL_UAF: ('POTENTIAL_UAF', 0.50),
                TemporalVerdict.LIKELY_SAFE: ('LIKELY_SAFE', 0.25),
                TemporalVerdict.DEFINITELY_SAFE: ('DEFINITELY_SAFE', 0.05),
            }
            verdict_label, base_conf = verdict_map.get(
                proof.verdict, ('POTENTIAL_UAF', 0.50))

            findings.append({
                'type': 'UAF',
                'free_addr': free_addr,
                'use_addr': use_addr,
                'ptr_reg': ptr_reg,
                'verdict': verdict_label,
                'confidence': proof.confidence,
                'has_null_after_free': proof.has_null_after_free,
                'has_guard_before_use': proof.has_guard_before_use,
                'has_mutex_protection': proof.has_mutex_protection,
                'free_after_use': proof.free_after_use,
                'proof_trace': proof.proof_trace,
            })

    # 汇总: detected = 至少有一个非 SAFE 的 finding
    real_findings = [f for f in findings
                     if f['verdict'] not in ('DEFINITELY_SAFE',)]
    return {
        'findings': findings,
        'n_findings': len(findings),
        'n_real_findings': len(real_findings),
        'detected': len(real_findings) > 0,
        'verifier_stats': verifier.stats(),
    }
