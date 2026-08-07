"""UAF 释放指针追踪器 — 寄存器级 freed 标记传播 + realloc 别名悬空检测.

核心数据结构: FreedPtr(释放地址, 原始寄存器, 传播链)
追踪规则:
  - mov freed_reg → other_reg: 标记传播 (freed 标记随数据流)
  - mov [freed_reg], ...: 释放后写入 (UAF 写)
  - mov dst, [freed_reg]: 释放后读取 (UAF 读)
  - call free(freed_reg): 二次释放 (Double-Free)
  - call realloc(freed_reg, n): 旧内存释放 → 别名全悬空 (RAP)
  - xor freed_reg, freed_reg: 清零 → 安全实践, 停止追踪
  - ret: 函数返回 → 清除所有跟踪 (作用域退出)

跨函数保守性: call 后清除 caller-saved regs (rcx/rdx/r8-r11/rax),
保留 callee-saved 和参数传递寄存器.

设计决策:
  - 仅追踪寄存器 (不追踪栈): free→use 间隔短, 编译器鲜少溢出 freed 指针到栈
  - 不追踪内存别名: 需要指针分析, stripped binary 不可靠
  - realloc(ptr, 0) ≡ free(ptr): 按 C23 §7.24.3.7 处理
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import sys, os

# 导入指令解析器
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction


@dataclass
class FreedPtr:
    """已释放指针的追踪记录."""
    free_addr: int          # free()/realloc() 调用地址
    ptr_reg: str            # 释放时所在的寄存器
    free_type: str = "free"  # "free" | "realloc" | "realloc_zero"
    propagations: List[int] = field(default_factory=list)  # 传播到的指令地址


@dataclass
class UafFinding:
    """UAF 检测发现."""
    insn_addr: int
    type: str = "use_after_free"
    subtype: str = ""       # "deref_after_free" | "double_free" | "pass_as_arg"
    freed_at: int = 0
    reason: str = ""
    confidence: float = 0.0


class FreedPtrTracker:
    """释放指针追踪器 — 寄存器级 freed 状态管理.

    与 BinaryUafScanner 解耦: 专注追踪逻辑, 检测器负责指令解释和判定.
    """

    # free 类函数
    FREE_FUNCS = {'free', '_free', 'operator_delete', 'delete'}
    # realloc 类函数 (释放旧内存)
    REALLOC_FUNCS = {'realloc', '_realloc', 'reallocarray'}
    # callee-saved 寄存器 (call 不清除)
    CALLEE_SAVED = {'rbx', 'rbp', 'rsp', 'r12', 'r13', 'r14', 'r15', 'rdi', 'rsi'}
    # 调用方破坏寄存器 (call 后清除 freed 标记)
    CALLER_CLOBBERED = {'r8', 'r9', 'r10', 'r11', 'rax', 'rcx', 'rdx'}
    # 可能持有指针的寄存器
    PTR_REGS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}

    def __init__(self):
        self._freed: Dict[str, FreedPtr] = {}
        self._stack_freed: Dict[str, FreedPtr] = {}
        self._insns: List[ParsedInstruction] = []

    # 公共 API

    def set_instructions(self, insns: List[ParsedInstruction]):
        self._insns = insns

    def mark_freed(self, reg: str, addr: int,
                   free_type: str = "free") -> Optional[FreedPtr]:
        """标记寄存器为已释放. 若已存在 → 返回旧记录 (二次释放)."""
        if reg in self._freed:
            return self._freed[reg]
        fp = FreedPtr(free_addr=addr, ptr_reg=reg, free_type=free_type)
        fp.propagations = [addr]
        self._freed[reg] = fp
        return None  # 首次释放, 无二次释放

    def mark_realloc_freed(self, ptr_reg: str, addr: int) -> List[str]:
        """realloc: 释放旧内存 → 旧指针所有别名标记为 freed.
        返回所有因此新标记的寄存器列表.
        """
        newly_freed = []
        # 查找所有指向同一 free_addr 的别名
        aliases_to_free = []
        for r, fp in self._freed.items():
            if fp.free_addr == addr:
                continue  # 同一调用点, 不重复标记
        # 标记 ptr_reg 及其别名
        alias_regs = self._find_aliases_at(ptr_reg, addr)
        for r in alias_regs:
            if r not in self._freed:
                fp = FreedPtr(free_addr=addr, ptr_reg=r,
                              free_type="realloc")
                fp.propagations = [addr]
                self._freed[r] = fp
                newly_freed.append(r)
        # 也标记 ptr_reg 自身
        if ptr_reg not in self._freed:
            fp = FreedPtr(free_addr=addr, ptr_reg=ptr_reg,
                          free_type="realloc")
            fp.propagations = [addr]
            self._freed[ptr_reg] = fp
            newly_freed.append(ptr_reg)
        return newly_freed

    def propagate(self, src_reg: str, dst_reg: str, addr: int):
        """mov dst, src_reg — freed 标记传播到 dst."""
        if src_reg in self._freed:
            fp = self._freed[src_reg]
            self._freed[dst_reg] = FreedPtr(
                free_addr=fp.free_addr, ptr_reg=fp.ptr_reg,
                free_type=fp.free_type,
                propagations=fp.propagations + [addr])

    def propagate_derived(self, base_reg: str, dst_reg: str, addr: int):
        """lea dst, [base+off] — 衍生指针继承 freed 标记."""
        if base_reg in self._freed:
            fp = self._freed[base_reg]
            self._freed[dst_reg] = FreedPtr(
                free_addr=fp.free_addr, ptr_reg=fp.ptr_reg,
                free_type=fp.free_type,
                propagations=fp.propagations + [addr])

    def is_freed(self, reg: str) -> bool:
        return reg in self._freed

    def get_freed(self, reg: str) -> Optional[FreedPtr]:
        return self._freed.get(reg)

    def clear_reg(self, reg: str):
        """清除单个寄存器的 freed 标记 (用于 xor reg,reg 检测)."""
        self._freed.pop(reg, None)

    def clear_caller_clobbered(self, keep_freed: bool = False):
        """call 后清除 caller-saved regs 中的 freed 标记.
        keep_freed=True: 保留已释放指针 (用于 free/realloc 后追踪)."""
        for r in list(self._freed.keys()):
            if r in self.CALLER_CLOBBERED:
                if not keep_freed:
                    del self._freed[r]

    def clear_all(self):
        """ret — 函数返回, 清除所有追踪."""
        self._freed.clear()
        self._stack_freed.clear()

    def __contains__(self, reg: str) -> bool:
        return reg in self._freed

    def items(self):
        return self._freed.items()

    # 栈槽追踪

    @staticmethod
    def extract_stack_slot(operand: str) -> Optional[str]:
        """从操作数提取栈槽: [rbp-0x8] → 'rbp-0x8'."""
        o = operand.strip().lower()
        if '[' not in o or ']' not in o:
            return None
        inner = o[o.index('[') + 1:o.rindex(']')]
        inner = inner.replace('*', '').strip()
        if 'rbp' in inner or 'rsp' in inner:
            return inner.replace(' ', '')
        return None

    def propagate_to_stack(self, slot: str, src_reg: str, addr: int):
        """mov [rbp-0xN], src_reg — freed 标记传播到栈槽."""
        if src_reg in self._freed:
            fp = self._freed[src_reg]
            self._stack_freed[slot] = FreedPtr(
                free_addr=fp.free_addr, ptr_reg=fp.ptr_reg,
                free_type=fp.free_type,
                propagations=fp.propagations + [addr])

    def propagate_from_stack(self, slot: str, dst_reg: str, addr: int):
        """mov dst_reg, [rbp-0xN] — freed 标记从栈槽传播到寄存器."""
        if slot in self._stack_freed:
            fp = self._stack_freed[slot]
            self._freed[dst_reg] = FreedPtr(
                free_addr=fp.free_addr, ptr_reg=fp.ptr_reg,
                free_type=fp.free_type,
                propagations=fp.propagations + [addr])

    def clear_stack_slot(self, slot: str):
        """清除栈槽的 freed 标记 (mov [rbp-0xN], imm)."""
        self._stack_freed.pop(slot, None)

    def is_stack_freed(self, slot: str) -> bool:
        return slot in self._stack_freed

    # 别名追踪

    def find_aliases(self, reg: str, call_addr: int) -> Set[str]:
        """反向追踪: 在 call 前查找 mov alias_reg, reg 的别名寄存器.
        最多回溯 5 条指令, 跨一层寄存器链.
        """
        aliases = set()
        call_idx = -1
        for i, ins in enumerate(self._insns):
            if ins.address == call_addr:
                call_idx = i
                break
        if call_idx < 0:
            return aliases

        for offset in range(1, 6):
            j = call_idx - offset
            if j < 0:
                break
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs"):
                if ins.mnemonic == "call":
                    break
                continue
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst == reg:
                src = ins.operands[1].strip()
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    aliases.add(src_reg)
                    break
                break
        return aliases

    def _find_aliases_at(self, reg: str, addr: int) -> Set[str]:
        """在指定地址处查找 reg 的别名 (前向, 用于 realloc)."""
        aliases = set()
        for r, fp in self._freed.items():
            if r != reg and fp.ptr_reg == reg:
                aliases.add(r)
        return aliases

    @staticmethod
    def is_ptr_reg(reg: str) -> bool:
        return reg in FreedPtrTracker.PTR_REGS
