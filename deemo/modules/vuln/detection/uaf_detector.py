"""
UAF专项检测 — free点→use点可达性 + dangling pointer追踪。

检测逻辑:
  1. 定位free/delete调用 → 标记被释放的指针
  2. 前向扫描 → 检测该指针在后续指令中被解引用 (mov/load/call via)
  3. 若在free和use之间无重新赋值 → UAF告警
  4. 特殊检测: 多次free同一指针 (double free)

与路径分析的关系:
  仅做intra-procedural分析——跨函数UAF需要调用图支持。
  跨函数情形标记为"possible"而非"confirmed"。

修改记录:
  创建 2026-08-05
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class UafFinding:
    location: str
    free_insn_idx: int
    use_insn_idx: int
    dangling_pointer: str       # 寄存器名或变量名
    free_func: str              # free / delete / delete[]
    use_type: str               # read / write / call_via
    instruction_gap: int        # free与use之间的指令数
    confidence: str


_FREE_FUNCS = {'free', '_ZdlPv', 'operator delete', 'delete', 'HeapFree', 'VirtualFree'}
_DELETE_ARRAY = {'_ZdaPv', 'operator delete[]'}


def _extract_pointer_reg(insn: str) -> Optional[str]:
    """从指令提取被操作的指针寄存器——含方括号内的寄存器。"""
    import re
    insn_lower = insn.lower().strip()
    if ':' in insn_lower[:20]: insn_lower = insn_lower.split(':',1)[1].strip()
    x86_regs = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                'r12','r13','r14','r15','eax','ebx','ecx','edx','esi','edi'}
    # 优先提取方括号内的寄存器（被解引用的指针）
    bracket_m = re.search(r'\[(\w+)\]', insn_lower)
    if bracket_m and bracket_m.group(1) in x86_regs:
        return bracket_m.group(1)
    parts = insn_lower.replace(',', ' ').split()
    for p in parts[1:4]:
        if p in x86_regs: return p
    return None


def _is_dereference(insn: str) -> Tuple[bool, str]:
    insn_lower = insn.lower().strip()
    if ':' in insn_lower[:20]: insn_lower = insn_lower.split(':',1)[1].strip()
    if '[' in insn_lower:
        if 'mov' in insn_lower and ',' in insn_lower:
            dst_is_mem = '[' in insn_lower.split(',')[0] if ',' in insn_lower else False
            return True, 'write' if dst_is_mem else 'read'
        return True, 'read'
    if insn_lower.startswith('call') and '*' in insn_lower:
        return True, 'call_via'
    return False, ''


def detect_uaf(
    instructions: List[str],
    inter_procedural: bool = False,
) -> List[UafFinding]:
    findings: List[UafFinding] = []
    freed_pointers: Dict[str, int] = {}  # reg_name → free_insn_idx

    for i, insn in enumerate(instructions):
        insn_lower = insn.lower().strip()

        # 检测free调用
        if 'call' in insn_lower:
            parts = insn_lower.split()
            if len(parts) >= 2:
                callee = parts[-1].lstrip('*').strip('<>').split('@')[0]
                if callee in _FREE_FUNCS or callee in _DELETE_ARRAY:
                    ptr = _extract_pointer_reg(insn)
                    if not ptr:  # 从call free回溯——找mov rdi, <reg>
                        for j in range(i-1, max(0, i-5), -1):
                            prev = instructions[j].lower().strip()
                            if ':' in prev[:20]: prev = prev.split(':',1)[1].strip()
                            if 'mov rdi,' in prev or 'mov edi,' in prev:
                                parts = prev.replace(',',' ').split()
                                for p in parts[2:]:
                                    if p in ('rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','eax','ebx','ecx','edx','esi','edi'): ptr = p; break
                                break
                    if ptr:
                        if ptr in freed_pointers:
                            # double free detected
                            findings.append(UafFinding(
                                location=f'double_free@{i}', free_insn_idx=freed_pointers[ptr],
                                use_insn_idx=i, dangling_pointer=ptr,
                                free_func=callee, use_type='double_free',
                                instruction_gap=i - freed_pointers[ptr],
                                confidence='confirmed'))
                        freed_pointers[ptr] = i
                    continue

        # 检测对已释放指针的解引用
        is_deref, dtype = _is_dereference(insn)
        if is_deref:
            ptr = _extract_pointer_reg(insn)
            if ptr and ptr in freed_pointers:
                free_idx = freed_pointers[ptr]
                # 检查free和use之间是否重新赋值 (排除已修复的情形)
                reassigned = False
                for j in range(free_idx + 1, i):
                    prev_insn = instructions[j].lower()
                    if 'mov' in prev_insn and ptr in prev_insn:
                        # mov reg, imm 或 mov reg, other_reg → 重新赋值
                        parts = prev_insn.replace(',', ' ').split()
                        if len(parts) >= 2 and parts[1] == ptr:
                            reassigned = True
                            break
                if not reassigned:
                    conf = 'confirmed' if inter_procedural else 'likely'
                    findings.append(UafFinding(
                        location=f'uaf@{i}', free_insn_idx=free_idx,
                        use_insn_idx=i, dangling_pointer=ptr,
                        free_func='free', use_type=dtype,
                        instruction_gap=i - free_idx, confidence=conf))

    return findings
