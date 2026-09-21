"""ImmPropAbsorb - 立即数传播吸收 (stage 80).

mov reg,imm 序列的常量通过 push/pop/栈槽传播后的吸收追踪,
写大小=纯常量链 -> 精确判定. 与 co_source 不同: 栈槽常量吸收链.

设计决策:
  - 追踪 mov reg, imm 常量
  - push reg / pop reg 经栈槽传播
  - mov [mem], reg 写点大小=追踪到的常量 -> 精确判定
"""

import re
from typing import Dict, List, Optional


def _trace_constants(pseudocode: str) -> Dict[str, int]:
    """追踪 {寄存器: 常量值}, 包含 push/pop/栈槽传播吸收链.

    吸收链: mov reg,imm -> push reg -> 栈槽 -> pop reg2 -> reg2 继承常量.
    """
    consts: Dict[str, int] = {}
    # 栈槽常量表: slot_idx -> const_val
    stack_slots: Dict[int, int] = {}
    # 模拟栈指针偏移 (push 减小, pop 增大)
    sp_offset = 0

    for line in pseudocode.splitlines():
        line_stripped = line.strip()

        # mov reg, imm — 直接常量赋值
        m_mov_imm = re.search(
            r"\bmov\s+(r\w+|eax|ebx|ecx|edx|esi|edi)\s*,\s*"
            r"(0[xX][0-9a-fA-F]+|\d+)",
            line_stripped,
        )
        if m_mov_imm:
            consts[m_mov_imm.group(1)] = int(m_mov_imm.group(2), 0)

        # mov [rbp-N], imm — 栈槽直接赋常量
        m_slot_imm = re.search(
            r"\bmov\s+\[\s*(?:rbp|rbp|r13|r5)\s*-\s*(\d+)\s*\]\s*,\s*"
            r"(0[xX][0-9a-fA-F]+|\d+)",
            line_stripped,
        )
        if m_slot_imm:
            slot_idx = int(m_slot_imm.group(1))
            stack_slots[slot_idx] = int(m_slot_imm.group(2), 0)

        # mov [rbp-N], reg — 栈槽间接赋值 (reg 已知常量时记录)
        m_slot_reg = re.search(
            r"\bmov\s+\[\s*(?:rbp|r5|r13)\s*-\s*(\d+)\s*\]\s*,\s*"
            r"(r\w+|eax|ebx|ecx|edx|esi|edi)",
            line_stripped,
        )
        if m_slot_reg:
            slot_idx = int(m_slot_reg.group(1))
            src_reg = m_slot_reg.group(2)
            if src_reg in consts:
                stack_slots[slot_idx] = consts[src_reg]

        # mov reg, [rbp-N] — 从栈槽恢复常量到 reg
        m_restore = re.search(
            r"\bmov\s+(r\w+|eax|ebx|ecx|edx|esi|edi)\s*,\s*"
            r"\[\s*(?:rbp|r5|r13)\s*-\s*(\d+)\s*\]",
            line_stripped,
        )
        if m_restore:
            dst_reg = m_restore.group(1)
            slot_idx = int(m_restore.group(2))
            if slot_idx in stack_slots:
                consts[dst_reg] = stack_slots[slot_idx]
            else:
                # 栈槽无记录, 传播链中断
                if dst_reg in consts:
                    del consts[dst_reg]

        # push reg — 将 reg 的常量值压入栈槽
        m_push = re.search(r"\bpush\s+(r\w+|eax|ebx|ecx|edx|esi|edi)", line_stripped)
        if m_push:
            src_reg = m_push.group(1)
            if src_reg in consts:
                stack_slots[sp_offset] = consts[src_reg]
            else:
                # 传播链中断: 栈槽标记为未知
                if sp_offset in stack_slots:
                    del stack_slots[sp_offset]
            sp_offset += 8

        # pop reg — 从栈槽恢复常量到 reg
        m_pop = re.search(r"\bpop\s+(r\w+|eax|ebx|ecx|edx|esi|edi)", line_stripped)
        if m_pop:
            sp_offset -= 8
            dst_reg = m_pop.group(1)
            if sp_offset in stack_slots:
                # 吸收链完成: 栈槽有记录, reg 继承常量
                consts[dst_reg] = stack_slots[sp_offset]
            else:
                # 传播链中断: reg 常量未知
                if dst_reg in consts:
                    del consts[dst_reg]

    return consts


def run_imm_prop_absorb(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """立即数传播吸收. 返回 findings."""
    findings: List[dict] = []
    # 含 push/pop/栈槽传播的完整吸收链追踪
    consts = _trace_constants(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\d+)?\]\s*(?:,|=)\s*(r\w+|eax|ebx|ecx|edx|esi|edi)", line)
        if not m:
            continue
        reg = m.group(3)
        if reg in consts:
            verdict, conf = "const_exact", 0.95
            desc = f"line{ln} reg={reg} write_size={consts[reg]} exact"
        else:
            # 传播链中断, 写大小无法静态确定
            verdict, conf = "unknown_size", 0.5
            desc = f"line{ln} reg={reg} not_const"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": desc,
            "verdict": verdict,
            "source": "imm_prop_absorb",
        })

    # C 风格伪代码: malloc 常量容量 vs memcpy/memmove 常量长度
    alloc_caps: Dict[str, int] = {}
    for line in pseudocode.splitlines():
        m_alloc = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)",
            line,
        )
        if m_alloc:
            alloc_caps[m_alloc.group(1)] = int(m_alloc.group(2))

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_copy = re.search(
            r"\b(?:memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*\)",
            line,
        )
        if not m_copy:
            continue
        dst_var = m_copy.group(1)
        len_tok = m_copy.group(2)
        # 仅处理立即数长度, 变量长度不属立即数范畴
        if not len_tok.isdigit():
            continue
        if dst_var not in alloc_caps:
            continue
        copy_len = int(len_tok)
        cap = alloc_caps[dst_var]
        if copy_len > cap:
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "high",
                "cwe": "CWE-122",
                "confidence": 0.9,
                "description": f"line{ln} memcpy len={copy_len} exceeds malloc cap={cap}",
                "verdict": "const_too_large",
                "source": "imm_prop_absorb",
            })
        elif copy_len == cap:
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "low",
                "cwe": "CWE-122",
                "confidence": 0.85,
                "description": f"line{ln} memcpy len={copy_len} equals malloc cap={cap}",
                "verdict": "const_exact",
                "source": "imm_prop_absorb",
            })

    return findings


if __name__ == "__main__":
    demo = """\
mov rax, 16;
push rax;
pop rbx;
mov [rbx], rbx;
"""
    out = run_imm_prop_absorb(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])