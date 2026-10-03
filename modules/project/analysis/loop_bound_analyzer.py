# 循环界精确化分析器 (Trip-Count Analyzer)
# 技术问题: 原 _estimate_loop_iterations 对未知边界的循环回退为
#   [0, 0x100000] 的宽区间, 使任何循环写入都产生 POSSIBLE_OVERFLOW,
#   这是循环类误报的主要来源. 且对 "for(i=0;i<=n;i++)" 的非严格上界
#   循环少计一次迭代 (漏报风险).
# 解决手段: 识别循环的三要素 (初始化/增量/边界) 精确计算迭代次数:
#   - 严格性映射 (跳转方向 × 计数器侧别 × 跳转码 → strict/nonstrict)
#   - 迭代次数计算 (严格/非严格/相等性退出)
#   - 相等性循环的奇偶一致性精确求解 (展开循环)
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .value_range import ValueRange
from .instruction_parser import InstructionParser

_UPPER_CAP = 0x100000  # 迭代次数保守上限 (与原实现一致)
_LOOKBACK_WINDOW = 40  # 初始化候选回溯窗口

# 条件跳转集合
_EQUALITY_EXIT = {'jne', 'jnz', 'je', 'jz'}
# 严格性映射参与的条件跳转 (next_jcc 过滤用)
_STRICTNESS_BY_JCC = {'jl', 'jb', 'jle', 'jbe', 'jge', 'jae', 'jg', 'ja'}

# 严格性映射: (方向, 计数器侧, jcc) → 'strict' | 'nonstrict' | None
# 回边 (跳转=继续): jcc 编码循环条件
# 出口 (跳转=离开): jcc 编码退出条件
_STRICTNESS = {
    ('back', 'left', 'jl'): 'strict', ('back', 'left', 'jb'): 'strict',
    ('back', 'left', 'jle'): 'nonstrict', ('back', 'left', 'jbe'): 'nonstrict',
    ('back', 'right', 'ja'): 'strict', ('back', 'right', 'jg'): 'strict',
    ('back', 'right', 'jae'): 'nonstrict', ('back', 'right', 'jge'): 'nonstrict',
    ('fwd', 'left', 'jge'): 'strict', ('fwd', 'left', 'jae'): 'strict',
    ('fwd', 'left', 'jg'): 'nonstrict', ('fwd', 'left', 'ja'): 'nonstrict',
    ('fwd', 'right', 'jbe'): 'strict', ('fwd', 'right', 'jle'): 'strict',
    ('fwd', 'right', 'jb'): 'nonstrict', ('fwd', 'right', 'jl'): 'nonstrict',
}

# 严格上界循环的出口跳转集合 (供循环耦合判定):
# 回边形式下 counter<bound 的编码
_STRICT_EXIT = {'jl', 'jb', 'jae', 'jge'}


@dataclass
class LoopInfo:
    """循环分析结果."""
    bound_range: Optional[ValueRange] = None  # 迭代次数值域
    step: int = 1                             # 计数器步长
    init_value: int = 0                       # 计数器初始值
    bound_reg: str = ""                       # 边界寄存器 (用于耦合)
    bound_slot: Optional[int] = None          # 边界栈槽 (用于耦合)
    cmp_idx: int = -1                         # cmp 指令索引 (用于耦合)
    exit_jcc: str = ""                        # 循环尾条件跳转
    jump_dir: str = ""                        # 'back' 回边 / 'fwd' 出口
    counter_side: str = "left"                # 计数器所在操作数侧
    strictness: str = ""                      # 'strict' / 'nonstrict' / ''
    is_equality_loop: bool = False            # 相等性退出, 无精确界
    confidence: float = 0.0


class LoopBoundAnalyzer:
    """循环界精确化分析器 (无状态)."""

    @staticmethod
    def analyze(body_indices: List[int],
                instructions: List[str],
                loop_start: int,
                vd_getter: Optional[Callable[[str], ValueRange]] = None,
                instr_addrs: Optional[List[int]] = None
                ) -> LoopInfo:
        """分析循环, 返回迭代次数信息."""
        if not body_indices or not instructions:
            return LoopInfo()

        step = find_increment(body_indices, instructions)
        counter_loc = find_counter_loc(body_indices, instructions)
        init_cands = find_init(instructions, loop_start, counter_loc)
        # 严格/非严格路径取最小候选 (迭代数最多, 溢出检测保守)
        init_val = min(init_cands) if init_cands else 0
        cmp_idx, bound_reg, bound_slot, bound_imm, jcc, jdir, cside = \
            find_bound(body_indices, instructions, counter_loc,
                       instr_addrs)
        strictness = _STRICTNESS.get((jdir, cside, jcc), "")

        if jcc in _EQUALITY_EXIT:
            # 相等性退出循环: 编译器在步长可整除边界时使用
            # cmp/jne 形态 (展开循环), trips = (bound-init)/step 精确.
            # 奇偶剥离路径产生多个候选 init (safe06 release),
            # 按 (bound-init)%step==0 的奇偶一致性筛选唯一可行解.
            eq_trips = None
            if bound_imm is not None:
                eq_trips = LoopBoundAnalyzer._equality_trips_multi(
                    init_cands, bound_imm, step)
            elif bound_reg and vd_getter is not None:
                reg_range = vd_getter(bound_reg)
                if (not reg_range.is_top and reg_range.is_constant
                        and reg_range.constant_value is not None):
                    eq_trips = LoopBoundAnalyzer._equality_trips_multi(
                        init_cands, reg_range.constant_value, step)
            if eq_trips is not None:
                return LoopInfo(
                    bound_range=ValueRange.constant(max(0, eq_trips)),
                    step=step, init_value=init_val,
                    bound_reg=bound_reg, bound_slot=bound_slot,
                    cmp_idx=cmp_idx, exit_jcc=jcc,
                    jump_dir=jdir, counter_side=cside,
                    strictness=strictness,
                    is_equality_loop=True,
                    confidence=0.8)
            return LoopInfo(step=step, init_value=init_val,
                            bound_reg=bound_reg, bound_slot=bound_slot,
                            cmp_idx=cmp_idx, exit_jcc=jcc,
                            jump_dir=jdir, counter_side=cside,
                            strictness=strictness,
                            is_equality_loop=True,
                            confidence=0.1)

        if bound_imm is not None and strictness:
            trips = LoopBoundAnalyzer._trip_count(
                init_val, bound_imm, step, strictness)
            return LoopInfo(
                bound_range=ValueRange.constant(max(0, trips)),
                step=step, init_value=init_val,
                bound_reg=bound_reg, bound_slot=bound_slot,
                cmp_idx=cmp_idx, exit_jcc=jcc,
                jump_dir=jdir, counter_side=cside,
                strictness=strictness,
                confidence=0.9)

        if bound_reg and vd_getter is not None and strictness:
            reg_range = vd_getter(bound_reg)
            if not reg_range.is_top and reg_range.umin >= 0:
                lo = LoopBoundAnalyzer._trip_count(
                    init_val, reg_range.umin, step, strictness)
                hi = LoopBoundAnalyzer._trip_count(
                    init_val, reg_range.umax, step, strictness)
                if lo is not None and hi is not None:
                    if lo > _UPPER_CAP:
                        lo = 0
                    return LoopInfo(
                        bound_range=ValueRange.unsigned_range(
                            max(0, lo), min(hi, _UPPER_CAP)),
                        step=step, init_value=init_val,
                        bound_reg=bound_reg, bound_slot=bound_slot,
                        cmp_idx=cmp_idx, exit_jcc=jcc,
                        jump_dir=jdir, counter_side=cside,
                        strictness=strictness,
                        confidence=0.7)

        return LoopInfo(step=step, init_value=init_val,
                        bound_reg=bound_reg, bound_slot=bound_slot,
                        cmp_idx=cmp_idx, exit_jcc=jcc,
                        jump_dir=jdir, counter_side=cside,
                        strictness=strictness,
                        confidence=0.0)

# 迭代次数计算

    @staticmethod
    def _equality_trips_multi(init_cands: List[int], bound: int,
                              step: int) -> Optional[int]:
        """多候选 init 下的相等性循环精确次数.

        奇偶一致性筛选: (bound - init) % step == 0 的候选可行.
        唯一可行解 → 精确次数; 多解或零解 → None.
        """
        if step <= 0:
            return None
        feasible = set()
        for c in init_cands:
            delta = bound - c
            if delta >= 0 and delta % step == 0:
                feasible.add(delta // step)
        if len(feasible) == 1:
            return max(0, feasible.pop())
        return None

    @staticmethod
    def _equality_trips(init: int, bound: int, step: int) -> Optional[int]:
        """相等性退出循环的精确迭代次数 (单候选).

        计数器以 step 递增至恰好等于 bound (编译器展开前提):
          trips = (bound - init) / step, 要求整除.
        """
        if step <= 0:
            return None
        delta = bound - init
        if delta < 0 or delta % step != 0:
            return None
        return max(0, delta // step)

    @staticmethod
    def _trip_count(init: int, bound: int, step: int,
                    strictness: str) -> Optional[int]:
        """从三要素计算迭代次数.

        计数器从 init 出发以 step 递增至越过 bound:
          strict (counter < bound): trips = ceil((bound-init)/step)
          nonstrict (counter ≤ bound): trips = floor((bound-init)/step)+1
        """
        if step <= 0 or bound < init:
            return 0
        delta = bound - init
        if strictness == 'nonstrict':
            return max(0, delta // step + 1)
        if strictness == 'strict':
            return max(0, (delta + step - 1) // step)
        return None  # 严格性未知: 无法判定


# 三要素提取 (计数器/增量/初始化/边界)

def locate_operand(operand: str) -> Optional[tuple]:
    """操作数位置判定: ('reg', reg64) | ('mem', slot) | None."""
    operand = operand.strip()
    if InstructionParser.is_reg(operand):
        return ('reg', InstructionParser.normalize_reg64(
            InstructionParser.clean_reg(operand)))
    slot = InstructionParser.parse_mem_slot(operand)
    if slot is not None:
        return ('mem', slot)
    return None


def find_increment(body_indices: List[int],
                   instructions: List[str]) -> int:
    """循环体内计数器增量: add counter, imm / inc counter."""
    for idx in body_indices:
        parsed = InstructionParser.parse_line(instructions[idx])
        if parsed is None:
            continue
        op, ops = parsed
        if op == 'inc' and ops:
            return 1
        if op == 'add' and len(ops) >= 2:
            imm = InstructionParser.parse_immediate(ops[1])
            if imm is not None and imm > 0:
                return imm
    return 1


def find_counter_loc(body_indices: List[int],
                     instructions: List[str]) -> Optional[tuple]:
    """确定计数器位置: 优先取增量指令的目标, 其次取边界比较的左操作数.

    返回 ('reg', reg64) 或 ('mem', slot) 或 None.
    """
    for idx in body_indices:
        parsed = InstructionParser.parse_line(instructions[idx])
        if parsed is None:
            continue
        op, ops = parsed
        dst = ops[0].strip() if ops else ""
        if op == 'inc' and ops:
            loc = locate_operand(dst)
            if loc:
                return loc
        if op == 'add' and len(ops) >= 2:
            imm = InstructionParser.parse_immediate(ops[1])
            if imm is not None and imm > 0:
                loc = locate_operand(dst)
                if loc:
                    return loc
    for idx in body_indices:
        parsed = InstructionParser.parse_line(instructions[idx])
        if parsed is None:
            continue
        op, ops = parsed
        if op == 'cmp' and len(ops) >= 2:
            loc = locate_operand(ops[0].strip())
            if loc:
                return loc
    return None


def find_init(instructions: List[str], loop_start: int,
              counter_loc: Optional[tuple] = None) -> List[int]:
    """循环头前窗口内的计数器初始化候选值.

    返回去重排序的候选列表. 匹配计数器位置, 否则会误取
    malloc/calloc 参数等无关的 mov reg, imm (safe06 回归根因).
    xor reg,reg 视为清零候选. 奇偶剥离 (peel) 会产生多个候选.
    参数装配排除: call 前 5 条指令内的 mov 是调用参数, 非初始化.
    """
    cands: List[int] = []
    for i in range(loop_start - 1,
                   max(0, loop_start - _LOOKBACK_WINDOW) - 1, -1):
        parsed = InstructionParser.parse_line(instructions[i])
        if parsed is None:
            continue
        op, ops = parsed
        if not ops:
            continue
        dst = ops[0].strip()
        val = None
        if op == 'xor' and len(ops) >= 2 and ops[0] == ops[1]:
            val = 0
        elif op == 'mov' and len(ops) >= 2:
            val = InstructionParser.parse_immediate(ops[1])
        if val is None:
            continue
        if counter_loc is not None:
            loc = locate_operand(dst)
            if loc != counter_loc:
                continue
        elif not InstructionParser.is_reg(dst):
            continue
        if is_arg_setup(instructions, i):
            continue
        cands.append(val)
    if not cands:
        return [0]
    return sorted(set(cands))


def is_arg_setup(instructions: List[str], idx: int) -> bool:
    """指令是否为随后 call 的参数装配 (5 条指令窗口内)."""
    for j in range(idx + 1, min(idx + 5, len(instructions))):
        parsed = InstructionParser.parse_line(instructions[j])
        if parsed is None:
            continue
        op, _ = parsed
        if op == 'call':
            return True
        if op in ('ret', 'jmp'):
            break
    return False


def find_bound(body_indices: List[int],
               instructions: List[str],
               counter_loc: Optional[tuple] = None,
               instr_addrs: Optional[List[int]] = None
               ) -> tuple:
    """循环尾的边界比较.

    返回 (cmp_idx, bound_reg, bound_slot, bound_imm, jcc, jdir, cside).
    计数器可能位于左操作数 (cmp i, bound) 或右操作数 (cmp bound, i),
    通过计数器位置与寄存器溯源判定侧别.
    bound_reg: 边界为寄存器时的 64 位名
    bound_slot: 边界为栈槽时的槽偏移
    bound_imm: 边界为立即数
    jdir: jcc 目标相对 cmp 的方向 ('back' 回边 / 'fwd' 出口)
    cside: 计数器所在操作数侧 ('left' / 'right')
    """
    for idx in reversed(body_indices):
        parsed = InstructionParser.parse_line(instructions[idx])
        if parsed is None:
            continue
        op, ops = parsed
        if op not in ('cmp', 'test'):
            continue
        if op == 'test' and len(ops) >= 1:
            return idx, "", None, 0, 'jne', 'back', 'left'
        if len(ops) < 2:
            continue
        left = ops[0].strip()
        right = ops[1].strip()
        left_is_c = operand_is_counter(left, counter_loc, idx,
                                       instructions)
        right_is_c = operand_is_counter(right, counter_loc, idx,
                                        instructions)
        jcc, jdir = next_jcc(idx, instructions, instr_addrs)
        cside = 'right' if right_is_c and not left_is_c else 'left'

        if right_is_c and not left_is_c:
            # cmp <bound>, <counter>: 边界在左
            return classify_bound(idx, left, jcc, jdir, cside)
        if left_is_c:
            # cmp <counter>, <bound>: 边界在右
            return classify_bound(idx, right, jcc, jdir, cside)
        # 侧别未知: 按常规 (计数器在左) 处理
        return classify_bound(idx, right, jcc, jdir, cside)
    return -1, "", None, None, "", "", "left"


def classify_bound(idx: int, operand: str, jcc: str, jdir: str,
                   cside: str) -> tuple:
    """按操作数形态分类边界: 立即数/寄存器/栈槽."""
    imm = InstructionParser.parse_immediate(operand)
    if imm is not None:
        return idx, "", None, imm, jcc, jdir, cside
    if InstructionParser.is_reg(operand):
        return (idx,
                InstructionParser.normalize_reg64(
                    InstructionParser.clean_reg(operand)),
                None, None, jcc, jdir, cside)
    slot = InstructionParser.parse_mem_slot(operand)
    if slot is not None:
        return idx, "", slot, None, jcc, jdir, cside
    return idx, "", None, None, jcc, jdir, cside


def operand_is_counter(operand: str, counter_loc: Optional[tuple],
                       cmp_idx: int,
                       instructions: List[str]) -> bool:
    """操作数是否为循环计数器.

    判定规则: 位置直接匹配计数器, 或寄存器可溯源到计数器槽位.
    """
    if counter_loc is None:
        return False
    loc = locate_operand(operand)
    if loc is not None and loc == counter_loc:
        return True
    if InstructionParser.is_reg(operand):
        r64 = InstructionParser.normalize_reg64(
            InstructionParser.clean_reg(operand))
        if counter_loc[0] == 'mem':
            slot = InstructionParser.trace_reg_to_source_slot(
                cmp_idx, instructions, r64)
            if slot == counter_loc[1]:
                return True
    return False


def next_jcc(cmp_idx: int, instructions: List[str],
             instr_addrs: Optional[List[int]] = None
             ) -> tuple:
    """cmp 之后的条件跳转: 返回 (操作码, 方向).

    方向: 跳转目标地址低于 cmp 地址 → 'back' (回边);
          高于 → 'fwd' (出口). 无地址表时默认 'back'.
    """
    for i in range(cmp_idx + 1, min(cmp_idx + 4, len(instructions))):
        parsed = InstructionParser.parse_line(instructions[i])
        if parsed is None:
            continue
        op, ops = parsed
        if op not in _STRICTNESS_BY_JCC and op not in _EQUALITY_EXIT:
            if op == 'jmp':
                return "", ""
            continue
        if not ops:
            return op, 'back'
        target_str = ops[0].split('<')[0].strip()
        try:
            target = int(target_str, 16)
        except ValueError:
            return op, 'back'
        cmp_addr = (instr_addrs[cmp_idx]
                    if instr_addrs and cmp_idx < len(instr_addrs)
                    else None)
        if cmp_addr is None:
            return op, 'back'
        return op, ('back' if target < cmp_addr else 'fwd')
    return "", ""
