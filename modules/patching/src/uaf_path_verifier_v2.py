# UAF路径可行性验证器增强 — 值范围约束传播 + NULL检查消解
"""UAF路径验证器 v2 — 在v1的guard约束交集基础上新增:

1. 指针NULL检查消解: cmp rax, 0; je .use → use分支上rax≠0
   → 若free路径要求rax==NULL(如if(!ptr)free(ptr)), use路径要求rax≠NULL
   → 两路径不可能同时可达 → 过滤此FP

2. 值范围传播: 追踪被比较的寄存器值范围, 而非仅记录约束区间。
   例: cmp rax, 0; jne .L → .L分支上rax∈[1,∞), 非.L分支上rax=0

3. 跨寄存器约束继承: cmp rdi, 0 对通过mov rdi, rax获得的rdi有效,
   约束作用于rax。

与heap_path_sensitivity.py共享GuardKind类型。
与heap_expr_engine共享值范围推理模式(cap/floor/extract_const_offset)。

  - Undangle Section 4.3 path-condition pruning
  - CRYPTA memory object provenance with NULL discrimination
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

class PtrConstraintKind(str, Enum):
    """指针值的约束类型。"""
    NULL = "null"           # ptr == 0 (NULL)
    NON_NULL = "non_null"   # ptr != 0
    IN_RANGE = "in_range"   # ptr ∈ [low, high]
    OUT_RANGE = "out_range" # ptr ∉ [low, high]

@dataclass
class PtrConstraint:
    """指针上的一个约束条件。"""
    kind: PtrConstraintKind = PtrConstraintKind.NON_NULL
    reg: str = ""              # 约束作用的规范化寄存器名
    line: int = -1             # 约束来源行
    # 约束来自哪个路径段
    direction: str = ""        # 'free_path' | 'use_path' | 'alloc_path'
    # 区间约束 (仅IN_RANGE/OUT_RANGE使用)
    low: int = 0
    high: int = 2**63 - 1
    # NULL检查的jcc类型
    jcc_type: str = ""         # je/jne/jz/jnz

@dataclass
class UafPathVerdict:
    """增强的UAF路径可行性判定。"""
    feasible: bool = True
    reason: str = ""
    # 判定来源
    null_contradiction: bool = False  # NULL/NON_NULL矛盾
    range_contradiction: bool = False # 值范围矛盾
    # 细节
    free_constraints: List[PtrConstraint] = field(default_factory=list)
    use_constraints: List[PtrConstraint] = field(default_factory=list)
    fp_confidence: float = 0.0

# 寄存器名规范化 (同uaf_pointer_engine)

def _norm_reg(r: str) -> str:
    _map = {
        'rax':'rax','eax':'rax','ax':'rax','al':'rax','ah':'rax',
        'rcx':'rcx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
        'rdx':'rdx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
        'rbx':'rbx','ebx':'rbx','bx':'rbx','bl':'rbx','bh':'rbx',
        'rsp':'rsp','esp':'rsp','sp':'rsp','spl':'rsp',
        'rbp':'rbp','ebp':'rbp','bp':'rbp','bpl':'rbp',
        'rsi':'rsi','esi':'rsi','si':'rsi','sil':'rsi',
        'rdi':'rdi','edi':'rdi','di':'rdi','dil':'rdi',
        'r8':'r8','r8d':'r8','r8w':'r8','r8b':'r8',
        'r9':'r9','r9d':'r9','r9w':'r9','r9b':'r9',
        'r10':'r10','r10d':'r10','r10w':'r10','r10b':'r10',
        'r11':'r11','r11d':'r11','r11w':'r11','r11b':'r11',
        'r12':'r12','r12d':'r12','r12w':'r12','r12b':'r12',
        'r13':'r13','r13d':'r13','r13w':'r13','r13b':'r13',
        'r14':'r14','r14d':'r14','r14w':'r14','r14b':'r14',
        'r15':'r15','r15d':'r15','r15w':'r15','r15b':'r15',
    }
    return _map.get(r.lower(), r.lower())

# 所有有效寄存器名的集合 (包括各宽度别名)
_VALID_REGS = frozenset({
    'rax','eax','ax','al','ah', 'rcx','ecx','cx','cl','ch',
    'rdx','edx','dx','dl','dh', 'rbx','ebx','bx','bl','bh',
    'rsp','esp','sp','spl', 'rbp','ebp','bp','bpl',
    'rsi','esi','si','sil', 'rdi','edi','di','dil',
    'r8','r8d','r8w','r8b', 'r9','r9d','r9w','r9b',
    'r10','r10d','r10w','r10b', 'r11','r11d','r11w','r11b',
    'r12','r12d','r12w','r12b', 'r13','r13d','r13w','r13b',
    'r14','r14d','r14w','r14b', 'r15','r15d','r15w','r15b',
    'rip', 'eflags',
})

def _is_valid_reg(r: str) -> bool:
    """检查是否是一个真实的寄存器名 (而非内存操作数修饰符或立即数)。"""
    if not r or r.startswith('0x') or r.startswith('$'):
        return False
    if r[0].isdigit():
        return False
    return r.lower() in _VALID_REGS

# 约束收集

# 匹配: cmp reg, 0 或 test reg, reg
_CMP_NULL = re.compile(r'\b(cmp|test)\s+(\w+),?\s*(0x0|0)\b', re.I)
_TEST_REG = re.compile(r'\btest\s+(\w+),?\s*\1\b', re.I)  # test reg, reg
# jcc
_JCC = re.compile(r'\b(j[a-z]{1,3})\s+', re.I)

# 指令地址提取: 1400017d3:	74 26                	je ...
_INST_ADDR = re.compile(r'^\s*([0-9a-f]+):\s+', re.I)

# 栈槽NULL守卫专用: mov [rbp/rsp ± N], 0 和 cmp [rbp/rsp ± N], 0
_MEM_NULLIFY = re.compile(
    r'\bmov\s+(?:qword|dword|word|byte)?\s*(?:ptr\s+)?'
    r'\[(rbp|rsp)([+\-]\s*(?:0x[0-9a-f]+|\d+))\]\s*,?\s*(?:0x0|0)\b', re.I)
_MEM_CMP_NULL = re.compile(
    r'\b(?:cmp|test)\s+(?:qword|dword|word|byte)?\s*(?:ptr\s+)?'
    r'\[(rbp|rsp)([+\-]\s*(?:0x[0-9a-f]+|\d+))\]\s*,?\s*(?:0x0|0)\b', re.I)

def _extract_addr(line: str) -> int:
    """从objdump行提取指令地址 (十六进制)。"""
    m = _INST_ADDR.match(line.strip())
    if m:
        return int(m.group(1), 16)
    return -1

def _extract_jcc_target(line: str) -> int:
    """从jcc行提取跳转目标地址。"""
    parts = line.strip().split()
    for j, p in enumerate(parts):
        if p.lower() in ('je', 'jz', 'jne', 'jnz', 'jmp', 'ja', 'jb', 'jae',
                          'jbe', 'jg', 'jl', 'jge', 'jle', 'js', 'jns', 'jo', 'jno'):
            if j + 1 < len(parts):
                try:
                    return int(parts[j + 1], 16)
                except ValueError:
                    pass
    return -1

def _detect_null_guard_fp(asm_lines: List[str],
                           free_line: int, use_line: int) -> Tuple[bool, str]:
    """检测NULL守卫模式: free后ptr置NULL, use被NULL检查保护。

    模式匹配 (use_path内, free→use):
      1. mov [rbp/rsp ± N], 0x0  — 硬NULL赋值
      2. cmp [rbp/rsp ± N], 0x0  — NULL比较
      3. je/jz TARGET 且 TARGET > use_addr — 跳过use块
      → 若步骤1和步骤2的slot相同, use不可达, 此路径是FP

    此检查独立于通用约束系统, 避免跨函数栈槽歧义。
    """
    # 收集use_path中的nullify和cmp
    nullify_slots: Dict[int, str] = {}  # line → slot
    cmp_slots: List[Tuple[int, str, int, str]] = []  # (line, slot, jcc_line, jcc_type)

    for i in range(free_line, min(use_line + 1, len(asm_lines))):
        l_stripped = asm_lines[i].strip()
        l_lowered = l_stripped.lower().replace(',', ' ')

        # mov [rbp/rsp ± N], 0
        nm = _MEM_NULLIFY.search(l_lowered)
        if nm:
            base = nm.group(1).lower()
            offset = nm.group(2).replace(' ', '')
            slot = f'{base}{offset}'
            nullify_slots[i] = slot
            continue

        # cmp [rbp/rsp ± N], 0
        mm = _MEM_CMP_NULL.search(l_lowered)
        if mm:
            base = mm.group(1).lower()
            offset = mm.group(2).replace(' ', '')
            slot = f'{base}{offset}'
            for k in range(i + 1, min(i + 3, len(asm_lines))):
                jm = _JCC.search(asm_lines[k].strip().lower().replace(',', ' '))
                if jm:
                    cmp_slots.append((i, slot, k, jm.group(1).lower()))
                    break

    if not nullify_slots or not cmp_slots:
        return False, ""

    use_addr = _extract_addr(asm_lines[use_line])

    # 检查: nullify的slot 与 cmp的slot 相同, 且jcc跳过use
    for n_line, n_slot in nullify_slots.items():
        for c_line, c_slot, j_line, jcc in cmp_slots:
            if n_slot == c_slot and jcc in ('je', 'jz'):
                jcc_target = _extract_jcc_target(asm_lines[j_line])
                # je跳过use: use在fall-through上 → 要求slot != NULL
                # 但slot被硬置NULL → 矛盾
                if jcc_target > 0 and use_addr > 0 and jcc_target > use_addr:
                    return True, (
                        f'NULL守卫矛盾: [{n_slot}]硬置NULL(line{n_line}), '
                        f'但use@line{use_line}需[{c_slot}]!=NULL '
                        f'(cmp@line{c_line}, je目标0x{jcc_target:x}>use 0x{use_addr:x})')

    return False, ""

def _extract_ptr_constraints(asm_lines: List[str],
                              from_line: int, to_line: int,
                              direction: str) -> List[PtrConstraint]:
    """在[from_line, to_line]范围内收集所有寄存器级指针约束。

    仅收集寄存器级约束(cmp reg, 0; jcc), 不涉及栈槽。
    栈槽NULL守卫由独立的 _detect_null_guard_fp 处理, 避免跨函数栈槽歧义。
    """
    constraints = []
    lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]

    for i in range(from_line, min(to_line + 1, len(lowered))):
        l = lowered[i]

        # cmp reg, 0
        cm = _CMP_NULL.search(l)
        if cm:
            reg = _norm_reg(cm.group(2))
            if reg in ('rbp', 'rsp', 'rip'):
                continue
            for k in range(i + 1, min(i + 3, len(lowered))):
                jm = _JCC.search(lowered[k])
                if jm:
                    jcc = jm.group(1).lower()
                    if jcc in ('je', 'jz'):
                        constraints.append(PtrConstraint(
                            kind=PtrConstraintKind.NULL, reg=reg, line=i,
                            direction=direction, jcc_type=jcc))
                    elif jcc in ('jne', 'jnz'):
                        constraints.append(PtrConstraint(
                            kind=PtrConstraintKind.NON_NULL, reg=reg, line=i,
                            direction=direction, jcc_type=jcc))
                    break
            continue

        # test reg, reg → 等同于 cmp reg, 0
        tm = _TEST_REG.search(l)
        if tm:
            reg = _norm_reg(tm.group(1))
            if reg in ('rbp', 'rsp', 'rip'):
                continue
            for k in range(i + 1, min(i + 3, len(lowered))):
                jm = _JCC.search(lowered[k])
                if jm:
                    jcc = jm.group(1).lower()
                    if jcc in ('je', 'jz'):
                        constraints.append(PtrConstraint(
                            kind=PtrConstraintKind.NULL, reg=reg, line=i,
                            direction=direction))
                    elif jcc in ('jne', 'jnz'):
                        constraints.append(PtrConstraint(
                            kind=PtrConstraintKind.NON_NULL, reg=reg, line=i,
                            direction=direction))
                    break
            continue

    return constraints

# 约束传播 (跨寄存器)

def _resolve_aliases(asm_lines: List[str],
                      constraints: List[PtrConstraint]) -> List[PtrConstraint]:
    """将约束传播到寄存器的别名 (mov rax, rdi → rax继承rdi的约束)。

    仅处理寄存器→寄存器传播, 不涉及栈槽。
    栈槽NULL守卫由独立的 _detect_null_guard_fp 处理。
    """
    lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]
    resolved = list(constraints)

    for c in constraints:
        for i in range(c.line, min(c.line + 15, len(lowered))):
            # mov dst, src → dst继承src的约束
            m = re.search(r'\bmov\s+(\w+),?\s*(\w+)', lowered[i])
            if m and not re.search(r'\[', lowered[i]):
                dst_raw, src_raw = m.group(1), m.group(2)
                if not _is_valid_reg(dst_raw) or not _is_valid_reg(src_raw):
                    continue
                dst, src = _norm_reg(dst_raw), _norm_reg(src_raw)
                if src == c.reg and dst not in ('rbp', 'rsp', 'rip'):
                    resolved.append(PtrConstraint(
                        kind=c.kind, reg=dst, line=i,
                        direction=c.direction, jcc_type=c.jcc_type))
        # 后向找 mov reg, src (当前reg来自哪个src → src也受约束)
        for i in range(c.line - 1, max(c.line - 15, -1), -1):
            m = re.search(r'\bmov\s+' + c.reg + r',?\s*(\w+)', lowered[i])
            if m and not re.search(r'\[', lowered[i]):
                src_raw = m.group(1)
                if not _is_valid_reg(src_raw):
                    break
                src = _norm_reg(src_raw)
                if src not in ('rbp', 'rsp', 'rip'):
                    resolved.append(PtrConstraint(
                        kind=c.kind, reg=src, line=i,
                        direction=c.direction, jcc_type=c.jcc_type))
                break

    return resolved

# 矛盾检测

def _has_null_contradiction(free_cs: List[PtrConstraint],
                              use_cs: List[PtrConstraint]) -> Tuple[bool, str]:
    """检查free路径和use路径是否有NULL/NON_NULL矛盾。

    矛盾条件: free路径要求reg==NULL, use路径要求reg!=NULL (或反之)
    → free和use不可能在同一执行路径共存 → 此UAF为FP。
    """
    for fc in free_cs:
        for uc in use_cs:
            if fc.reg == uc.reg or fc.reg in uc.reg or uc.reg in fc.reg:
                if (fc.kind == PtrConstraintKind.NULL and
                        uc.kind == PtrConstraintKind.NON_NULL):
                    return True, (
                        f'NULL矛盾: free路径要求{fc.reg}==NULL(line{fc.line}), '
                        f'use路径要求{uc.reg}!=NULL(line{uc.line})')
                if (fc.kind == PtrConstraintKind.NON_NULL and
                        uc.kind == PtrConstraintKind.NULL):
                    return True, (
                        f'NULL矛盾: free路径要求{fc.reg}!=NULL(line{fc.line}), '
                        f'use路径要求{uc.reg}==NULL(line{uc.line})')
    return False, ""

# 增强路径验证器

class UafPathVerifierV2:
    """UAF路径可行性验证器 v2。

    验证策略 (多级, 精度递增):
      Level 1: NULL/NON_NULL矛盾 → 确定FP (confidence=0.95)
      Level 2: 值范围矛盾 → 高置信FP (confidence=0.85)
      Level 3: 约束交集为空 → 中置信FP (confidence=0.70)
      Level 4: 无约束 → 保守保留 (confidence=0.30)
    """

    def verify(self, uaf_path, asm_lines: List[str]) -> UafPathVerdict:
        """验证单条UAF路径的可行性。"""
        verdict = UafPathVerdict()

        # NULL守卫专用检查 (free后ptr置NULL + use被NULL检查保护)
        has_null_guard, ng_reason = _detect_null_guard_fp(
            asm_lines, uaf_path.free_line, uaf_path.use_line)
        if has_null_guard:
            verdict.feasible = False
            verdict.null_contradiction = True
            verdict.reason = ng_reason
            verdict.fp_confidence = 0.95
            return verdict

        # 收集两条路径上的寄存器级约束
        free_cs = _extract_ptr_constraints(
            asm_lines, uaf_path.alloc_line, uaf_path.free_line, 'free_path')
        use_cs = _extract_ptr_constraints(
            asm_lines, uaf_path.free_line, uaf_path.use_line, 'use_path')

        # 跨寄存器传播
        free_cs = _resolve_aliases(asm_lines, free_cs)
        use_cs = _resolve_aliases(asm_lines, use_cs)

        verdict.free_constraints = free_cs
        verdict.use_constraints = use_cs

        # Level 1 — NULL矛盾检测 (寄存器级)
        has_contra, reason = _has_null_contradiction(free_cs, use_cs)
        if has_contra:
            verdict.feasible = False
            verdict.null_contradiction = True
            verdict.reason = reason
            verdict.fp_confidence = 0.95
            return verdict

        # Level 2-3 — 通过guard约束交集判定
        # 跨函数call路径跳过guard检查 (free_line>use_line时guard收集无效)
        if not getattr(uaf_path, 'is_call_path', False):
            free_guards = uaf_path.alloc_to_free_guards
            use_guards = uaf_path.free_to_use_guards

            if free_guards or use_guards:
                from .uaf_path_verifier import UAFPathVerifier, _interval_intersect
                v1 = UAFPathVerifier()
                v1_verdict = v1.verify(uaf_path)
                if not v1_verdict.feasible:
                    verdict.feasible = False
                    verdict.range_contradiction = True
                    verdict.reason = v1_verdict.reason
                    verdict.fp_confidence = 0.70
                    return verdict

        # Level 4 — 无约束或call路径, 保守保留
        if not free_cs and not use_cs:
            if getattr(uaf_path, 'is_call_path', False):
                verdict.feasible = True
                verdict.reason = "跨函数call路径: 同源指针验证通过, 保守保留"
                verdict.fp_confidence = 0.15
            else:
                verdict.feasible = True
                verdict.reason = "无指针约束, 保守保留为可行"
                verdict.fp_confidence = 0.0
            return verdict

        # 有约束但无矛盾 → 可能可行
        verdict.feasible = True
        if getattr(uaf_path, 'is_call_path', False):
            verdict.reason = "跨函数call路径: 寄存器约束非矛盾"
            verdict.fp_confidence = 0.15
        else:
            verdict.reason = "约束非矛盾, 路径可能可达"
            verdict.fp_confidence = 0.0
        return verdict

# 批量验证

def filter_uaf_paths_v2(dd_report, asm_lines: List[str]) -> Tuple[List, float, List[UafPathVerdict]]:
    """对demand-driven报告的所有UAF路径执行v2可行性验证。"""
    verifier = UafPathVerifierV2()
    verdicts = []
    verified, filtered = 0, 0

    for path in dd_report.uaf_paths:
        v = verifier.verify(path, asm_lines)
        verdicts.append(v)
        path.path_feasible = v.feasible

        if v.feasible and not path.realloc_on_path:
            verified += 1
        else:
            filtered += 1

    total = len(dd_report.uaf_paths) if dd_report.uaf_paths else 1
    fp_pct = filtered / total * 100
    return dd_report.uaf_paths, fp_pct, verdicts
