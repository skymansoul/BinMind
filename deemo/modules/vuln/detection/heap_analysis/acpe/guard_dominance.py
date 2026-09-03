"""守卫支配分析 — 判定写入 size 是否被边界检查守卫限定.

用途: ACPE 的路径敏感侧。真实程序大量用 `if (len <= cap) { memcpy(...) }`
      或 `if (len > cap) return;` 保护堆拷贝。这些守卫在二进制层体现为
      cmp + 条件跳转。若能证明所有到达写入点的路径都满足 size ≤ 容量,
      该写入可安全滤除。

设计决策:
  - 为何不用完整 CFG 支配树: 目标二进制规模中等, 线性扫描已覆盖
    两个主导模式(早退守卫/钳位守卫), 且保守——无证据不滤除。
  - 早退守卫(SAFE):  cmp X,C; ja/jg T 且 T 在写入点之后。
    只有 X ≤ C 的路径能到达写入点。
  - 钳位守卫(SAFE):  cmp X,C; jbe/jle T 且 T ≤ 写入点, 且 jcc 与写入点
    之间存在把 X 钳位到 C'≤C 的 mov。两条路径的 X 上界都是 min(C, C')。
  - 反例守卫(证据):  cmp X,C; jbe/jle T 且 T 在写入点之后——写入点仅在
    X>C 时可达, 该守卫实际"放行大尺寸", 记录为溢出证据而非安全证据。
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from modules.vuln.detection.heap_analysis.insn_parser import (
    Instruction, extract_register, extract_constant, extract_mem_offset)

from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
    CapExpr, usable_size)


@dataclass
class GuardRecord:
    """一条 cmp+jcc 守卫."""
    addr: int
    sym: str            # 被比较操作数的规范符号 (如 'A:1')
    bound: int          # 比较的常数上界
    jcc: str            # jbe/jle/ja/jg/...
    target: int         # 跳转目标地址
    taken_le_bound: bool  # 跳转被采取时是否隐含 X <= bound
    operand_key: str = ''  # 被比较操作数定位键 (寄存器名或 'rbp:-8')

    @property
    def is_safety_shape(self) -> bool:
        """jcc 的"取真"分支隐含 X ≤ bound (ja/jg/jae/jge 的取假分支).

        jae/jge 取真时 X ≥ bound, 取假路径 X < bound ≤ bound, 同样安全。
        """
        return self.jcc in ('ja', 'jg', 'jae', 'jge')


@dataclass
class GuardEvidence:
    """守卫分析结果 — 对一次写入的守卫证据."""
    write_addr: int
    size_sym: str
    safe_upper_bound: Optional[int] = None   # 证明的写入 size 上界
    bound_source: str = ''
    overflow_hint: Optional[int] = None      # 反例守卫的 bound
    guards_seen: int = 0


def parse_guard(insn: Instruction,
                jcc: Instruction,
                sym_map: Dict[str, str]) -> Optional[GuardRecord]:
    """从 cmp+jcc 指令对构建 GuardRecord.

    sym_map: 寄存器/栈槽 → 规范符号 ('A:1' 等), 由追踪器提供。
    仅处理 cmp reg/mem, imm 与 cmp reg, reg(符号可解析) 两种形态。
    """
    if insn.mnemonic != 'cmp':
        return None
    op = insn.operands
    left, _, right = op.partition(',')
    left, right = left.strip(), right.strip()

    c = extract_constant(right)
    sym = None
    if c is None:
        # cmp reg, reg: 右侧若可解析为已知常数符号则采用
        right_sym = _operand_sym(right, sym_map)
        if right_sym:
            try:
                c = int(right_sym, 0)
            except ValueError:
                return None
    if c is None:
        return None

    sym, operand_key = _operand_sym_key(left, sym_map)
    if sym is None:
        return None

    jcc_mnem = jcc.mnemonic
    if jcc_mnem not in ('jbe', 'jle', 'jb', 'jl',
                        'ja', 'jg', 'jae', 'jge'):
        return None

    target = _jcc_target(jcc)
    if target is None:
        return None

    # 跳转被采取时是否隐含 X ≤ bound:
    #   jbe/jle/jb/jl: X ≤ C 时跳转 → taken_le_bound=True
    #   jae/jge/ja/jg: X ≥/> C 时跳转 → taken_le_bound=False
    taken_le = jcc_mnem in ('jbe', 'jle', 'jb', 'jl')
    return GuardRecord(
        addr=insn.addr, sym=sym, bound=c, jcc=jcc_mnem,
        target=target, taken_le_bound=taken_le, operand_key=operand_key)


def _operand_sym(operand: str, sym_map: Dict[str, str]) -> Optional[str]:
    sym, _ = _operand_sym_key(operand, sym_map)
    return sym


def _operand_sym_key(operand: str,
                     sym_map: Dict[str, str]) -> Tuple[Optional[str], str]:
    """返回 (符号, 定位键). 定位键用于钳位检测: 'rbp:-8' 或寄存器名."""
    if '[' in operand:
        base, off = extract_mem_offset(operand)
        if base in ('rbp', 'rsp') and off is not None:
            key = f'{base}:{off}'
            return sym_map.get(key), key
        return None, ''
    reg = extract_register(operand)
    if reg:
        return sym_map.get(reg), reg
    return None, ''


def find_clamp(insns: List[Instruction], guard: GuardRecord,
               write_addr: int) -> Optional[int]:
    """在守卫与写入点之间查找对同一操作数的钳位赋值.

    钳位: mov <operand_key>, imm 且 imm ≤ guard.bound。
    找到则说明取假路径(X > bound)也会把 X 压到 ≤ bound, 两条路径
    的写入 size 上界都是 guard.bound。
    """
    if not guard.operand_key:
        return None
    is_slot = ':' in guard.operand_key
    for insn in insns:
        if insn.addr <= guard.addr or insn.addr >= write_addr:
            continue
        if insn.mnemonic not in ('mov', 'movsxd', 'movzx'):
            continue
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip() if ',' in op else ''
        if is_slot:
            base, off = extract_mem_offset(dst)
            if base not in ('rbp', 'rsp') or off is None:
                continue
            if f'{base}:{off}' != guard.operand_key:
                continue
        else:
            if extract_register(dst) != guard.operand_key:
                continue
        c = extract_constant(src)
        if c is not None and c <= guard.bound:
            return c
    return None


def _jcc_target(jcc: Instruction) -> Optional[int]:
    op = jcc.operands.strip()
    hex_part = op.split()[0] if op else ''
    try:
        return int(hex_part, 16)
    except ValueError:
        return None


def analyze_guards_for_write(
    write_addr: int,
    size_sym: str,
    guards: List[GuardRecord],
    insns: Optional[List[Instruction]] = None,
) -> GuardEvidence:
    """对一次写入聚合守卫证据.

    size_sym 为写入 size 的符号。偏移型写入(ARITH)的符号需先由
    调用方折算 base。
    """
    ev = GuardEvidence(write_addr=write_addr, size_sym=size_sym)
    ev.guards_seen = len(guards)

    for g in guards:
        if g.sym != size_sym:
            continue
        if g.bound < 0:
            continue
        if g.is_safety_shape and g.target > write_addr:
            # 早退守卫: 只有 X ≤ bound 可达写入
            if ev.safe_upper_bound is None:
                ev.safe_upper_bound = g.bound
                ev.bound_source = f'early-exit {g.jcc}@{g.addr:x}'
            else:
                ev.safe_upper_bound = min(ev.safe_upper_bound, g.bound)
        elif (g.taken_le_bound and g.target <= write_addr):
            # 钳位守卫候选: 取真分支(X≤bound)到达写入。
            # 取假分支(X>bound)必须被钳位到 ≤bound 才能滤除——
            # 否则写入点在取假路径上可能越界, 不构成安全证据。
            if insns is not None and find_clamp(insns, g, write_addr) is not None:
                if ev.safe_upper_bound is None:
                    ev.safe_upper_bound = g.bound
                    ev.bound_source = f'clamp {g.jcc}@{g.addr:x}'
                else:
                    ev.safe_upper_bound = min(ev.safe_upper_bound, g.bound)
        elif (g.taken_le_bound and g.target > write_addr):
            # 反例守卫: 写入点仅在 X > bound 时可达
            if ev.overflow_hint is None:
                ev.overflow_hint = g.bound
    return ev


def guard_safety_check(ev: GuardEvidence, cap: CapExpr,
                       write_offset: int = 0) -> Tuple[str, str]:
    """守卫证据 → 安全判定.

    返回 (verdict, 说明): 'SAFE' / 'UNSAFE' / 'UNKNOWN'
    """
    if ev.safe_upper_bound is None:
        return 'UNKNOWN', 'no bounding guard found'
    eff = ev.safe_upper_bound + write_offset
    cu = cap.upper_bound()
    if cu is None:
        # 容量为符号: 守卫 bound + offset ≤ 最大可能 slack 区间不足, 保守
        return 'UNKNOWN', f'capacity not constant, guard bound {eff}'
    if eff <= usable_size(cu):
        return 'SAFE', (f'guard proves size <= {eff}B <= usable '
                        f'{usable_size(cu)}B ({ev.bound_source})')
    return 'UNSAFE', f'guard bound {eff}B exceeds usable {usable_size(cu)}B'


# 自检
def _check():
    from modules.vuln.detection.heap_analysis.insn_parser import Instruction
    g1 = GuardRecord(0x100, 'A:1', 0x40, 'ja', 0x180, taken_le_bound=False)
    ev = analyze_guards_for_write(0x120, 'A:1', [g1])
    v, _ = guard_safety_check(ev, CapExpr.const(64), 0)
    assert v == 'SAFE', v

    # 反例守卫: jbe 跳过写入 → 写入仅在 size>cap 时可达
    g2 = GuardRecord(0x100, 'A:1', 0x40, 'jbe', 0x180, taken_le_bound=True)
    ev2 = analyze_guards_for_write(0x120, 'A:1', [g2])
    assert ev2.overflow_hint == 0x40
    assert ev2.safe_upper_bound is None

    # 钳位守卫: jbe 目标在写入前, 且有钳位 mov → 安全
    g3 = GuardRecord(0x100, 'A:1', 0x40, 'jbe', 0x110,
                     taken_le_bound=True, operand_key='rbp:16')
    insns = [
        Instruction(0x100, 'cmp', 'QWORD PTR [rbp+0x10],0x40', ''),
        Instruction(0x108, 'jbe', '0x110', ''),
        Instruction(0x10a, 'mov', 'QWORD PTR [rbp+0x10],0x40', ''),
        Instruction(0x120, 'call', 'memcpy', ''),
    ]
    ev3 = analyze_guards_for_write(0x120, 'A:1', [g3], insns)
    v3, _ = guard_safety_check(ev3, CapExpr.const(64), 0)
    assert v3 == 'SAFE', v3

    # 无钳位的 jbe 目标在写入前 → 不构成安全证据
    insns_no = [Instruction(0x100, 'cmp', 'QWORD PTR [rbp+0x10],0x40', ''),
                Instruction(0x108, 'jbe', '0x110', '')]
    ev4 = analyze_guards_for_write(0x120, 'A:1', [g3], insns_no)
    assert ev4.safe_upper_bound is None, ev4

    # 无守卫
    ev5 = analyze_guards_for_write(0x120, 'A:1', [])
    v5, _ = guard_safety_check(ev5, CapExpr.const(64), 0)
    assert v5 == 'UNKNOWN'
    print('[OK] guard_dominance passed')


if __name__ == '__main__':
    _check()
