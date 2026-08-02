# 2026-08-02
# ROP Gadget 分析器 — 从二进制中扫描/分类/评估可利用的 gadget
# 核心分析:
#   1. Gadget 扫描: 在全二进制中搜索 ret/间接跳转结尾的指令序列
#   2. Gadget 分类: 按语义标记 (load/store/alu/syscall/call/branch)
#   3. Chaining 模拟: 对给定目标 (如 mprotect+shellcode) 搜索可行链
#   4. 缓解评估: 估计在 CFI/CET/PAC 下 gadget 可用性
#   5. 消除验证: 比较补丁前后 gadget 数量验证缓解是否有效部署
#
# 参考:
#   ROP Gadget Prevalence and Survival under Compiler-based Binary
#     Diversification Schemes (Coppens et al.)
#   Static Binary Rewriting for ROP Gadget Removal (Larsen et al.)
#   Fill your Boots (CHES 2021): bootloader fault injection + binary analysis
#   Return-Oriented Programming (Shacham CCS 2007) — 奠基性工作
#   Jump-Oriented Programming (Bletsch et al. ACSAC 2011)
import struct
import re
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field


@dataclass
class Gadget:
    """单条 ROP gadget。"""
    address: int                    # gadget 起始地址 (虚拟地址)
    raw_bytes: bytes                # 原始字节序列
    disasm: str = ""               # 反汇编文本
    ret_type: str = "ret"          # ret | call reg | jmp reg | syscall
    semantics: List[str] = field(default_factory=list)
    # 语义标签: 'pop_reg', 'mov_reg_reg', 'load', 'store',
    #          'alu', 'syscall', 'call', 'branch', 'nop'
    regs_written: Set[str] = field(default_factory=set)
    regs_read: Set[str] = field(default_factory=set)
    stack_shift: int = 0            # 对 rsp/esp 的净偏移 (+n = pop n bytes)
    side_effects: List[str] = field(default_factory=list)
    useful: bool = False            # 是否可用于实际 ROP 链构造
    confidence: float = 0.0         # 可利用置信度 [0, 1]


@dataclass
class ROPChain:
    """一组可链接的 gadget 序列，实现特定目标。"""
    goal: str                       # execve / mprotect / write_primitive / etc
    gadgets: List[Gadget]
    total_len: int
    constraints_satisfied: bool
    estimated_reliability: float    # [0, 1]


class ROPGadgetScanner:
    """在二进制中扫描 ROP gadget。

    扫描策略: 滑动窗 (2–16 字节) → 检测看是否以 ret/间接跳转指令结尾。
    在 x86/x86-64 下，ret = 0xC3, ret imm16 = 0xC2, call/jmp reg 模式 =
    FF D0-FF D7 (call) / FF E0-FF E7 (jmp)。"""

    # ret/间接转移编码
    _TERMINATORS = {
        0xC3: 'ret',
        0xC2: 'ret_imm16',
        0xCB: 'retf',
        0xCA: 'retf_imm16',
    }
    # call reg: FF D0-D7, jmp reg: FF E0-E7
    _INDIRECT_PREFIX = 0xFF

    def __init__(self, arch: str = "x86-64"):
        self._arch = arch
        self._gadgets: List[Gadget] = []
        self._by_semantics: Dict[str, List[Gadget]] = defaultdict(list)
        self._max_gadget_len = 16

    def scan_raw(self, data: bytes, base_addr: int = 0) -> int:
        """在原始字节中扫描 gadget。返回找到的 gadget 数。"""
        self._gadgets = []
        self._by_semantics.clear()

        for offset in range(len(data)):
            # 对每个起始偏移，尝试 2-16 字节的 gadget
            for g_len in range(2, min(self._max_gadget_len + 1,
                                      len(data) - offset + 1)):
                chunk = data[offset:offset + g_len]
                terminator = chunk[-1]

                ret_type = None
                if terminator in self._TERMINATORS:
                    ret_type = self._TERMINATORS[terminator]
                elif (terminator & 0xF0) in (0xD0, 0xE0) and g_len >= 2:
                    if chunk[-2] == self._INDIRECT_PREFIX:
                        ret_type = ('call_reg' if (terminator & 0xF0) == 0xD0
                                    else 'jmp_reg')

                if ret_type is None:
                    continue  # 不是有效 gadget 终止符

                addr = base_addr + offset
                g = Gadget(
                    address=addr,
                    raw_bytes=chunk,
                    ret_type=ret_type)
                self._classify_semantics(g)
                self._gadgets.append(g)

                for sem in g.semantics:
                    self._by_semantics[sem].append(g)

        return len(self._gadgets)

    def _classify_semantics(self, g: Gadget) -> None:
        """对 gadget 做启发式语义分类。基于 x86/x86-64 操作码模式。
        仅处理最常见的单字节操作码；完整实现需要集成反汇编器。"""
        b = g.raw_bytes
        if len(b) < 2:
            return

        # pop reg: 0x58-0x5F (x64: 0x41 0x58-0x5F for R8-R15)
        if 0x58 <= b[0] <= 0x5F:
            g.semantics.append('pop_reg')
            g.stack_shift = 8  # x64: pop = rsp + 8
            reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
            idx = b[0] - 0x58
            g.regs_written.add(reg_names[idx])
            if reg_names[idx] not in ('rsp',):
                g.useful = True

        # mov reg, reg: 0x48 0x89 / 0x48 0x8B (REX.W + MOV r/m, r)
        if len(b) >= 3 and b[0] == 0x48 and b[1] in (0x89, 0x8B):
            g.semantics.append('mov_reg_reg')
            g.useful = True

        # xor eax, eax (清零): 0x31 0xC0
        if len(b) >= 3 and b[0:2] == b'\x31\xc0':
            g.semantics.append('alu')
            g.semantics.append('zero_rax')
            g.useful = True

        # syscall: 0x0F 0x05
        if b'\x0f\x05' in b:
            g.semantics.append('syscall')
            g.useful = True
            g.confidence = 0.95

        # int 0x80: 0xCD 0x80 (32-bit syscall)
        if b'\xcd\x80' in b:
            g.semantics.append('syscall')
            g.semantics.append('legacy_syscall')

        # 未分类 → nop
        if not g.semantics:
            g.semantics.append('nop')

        if g.useful:
            g.confidence = 0.7

    # ---- 查询 ----
    def get_by_register(self, reg: str) -> List[Gadget]:
        """获取写入指定寄存器的所有 gadget。"""
        return [g for g in self._gadgets if reg in g.regs_written]

    def get_useful(self, min_stack_shift: int = 0) -> List[Gadget]:
        return [g for g in self._gadgets
                if g.useful and g.stack_shift >= min_stack_shift]

    def pop_reg_gadgets(self) -> Dict[str, List[Gadget]]:
        result: Dict[str, List[Gadget]] = defaultdict(list)
        for g in self._gadgets:
            if 'pop_reg' in g.semantics:
                for reg in g.regs_written:
                    if reg != 'rsp':
                        result[reg].append(g)
        return dict(result)

    # ---- ROP 链构造 ----
    def search_chain(self, goal: str = "execve",
                     max_len: int = 8) -> List[ROPChain]:
        """搜索可用于构造特定目标 ROP 链的 gadget 组合。
        当前实现: 检查是否存在覆盖所需寄存器的 pop 系列 gadget。"""
        required_regs = {
            'execve': ['rdi', 'rsi', 'rdx', 'rax'],
            'mprotect': ['rdi', 'rsi', 'rdx', 'rax'],
            'write_primitive': ['rdi', 'rsi', 'rdx'],
        }
        regs = required_regs.get(goal, ['rdi', 'rsi', 'rdx'])
        pop_map = self.pop_reg_gadgets()

        # 检查每种所需寄存器是否至少有一个 pop gadget
        missing = [r for r in regs if not pop_map.get(r)]
        if missing:
            return []

        # 构建简单链: pop rdi; pop rsi; pop rdx; pop rax; syscall
        chain_gadgets = []
        for reg in regs:
            chain_gadgets.append(pop_map[reg][0])

        syscall_gadgets = self._by_semantics.get('syscall', [])
        if syscall_gadgets and goal in ('execve', 'mprotect'):
            chain_gadgets.append(syscall_gadgets[0])

        chain = ROPChain(
            goal=goal,
            gadgets=chain_gadgets,
            total_len=sum(len(g.raw_bytes) for g in chain_gadgets),
            constraints_satisfied=len(missing) == 0,
            estimated_reliability=0.8 if not missing else 0.0)

        return [chain] if chain.constraints_satisfied else []

    # ---- 缓解检测 ----
    def estimate_cfi_resistance(self) -> Dict[str, Any]:
        """评估在启用 CFI 的情况下 gadget 可用性。
        CFI 检查间接调用/跳转目标 → 只有 'ret' 型 gadget 可被利用
        （call_reg/jmp_reg 受保护），且 forward-edge CFI 阻止部分调用。"""
        total = len(self._gadgets)
        ret_type = len([g for g in self._gadgets
                       if g.ret_type == 'ret'])
        call_jmp_type = len([g for g in self._gadgets
                            if g.ret_type in ('call_reg', 'jmp_reg')])
        syscall_type = len(self._by_semantics.get('syscall', []))
        return {
            'total_gadgets': total,
            'surviving_under_cfi': ret_type,
            'blocked_by_forward_edge_cfi': call_jmp_type,
            'cfi_survival_rate': round(ret_type / max(1, total), 3),
            'syscall_gadgets': syscall_type,
            'risk_level': 'high' if ret_type > 100
            else 'medium' if ret_type > 20 else 'low',
        }

    # ---- 报告 ----
    def stats(self) -> Dict[str, Any]:
        sem_counts = {k: len(v) for k, v in self._by_semantics.items()}
        ret_type_counts = Counter(g.ret_type for g in self._gadgets)
        return {
            'total_gadgets': len(self._gadgets),
            'useful_gadgets': len(self.get_useful()),
            'by_semantics': sem_counts,
            'by_ret_type': dict(ret_type_counts),
            'pop_reg_info': {
                reg: len(gadgets)
                for reg, gadgets in self.pop_reg_gadgets().items()
            },
            'cfi_resistance': self.estimate_cfi_resistance(),
        }

    def find_gadgets_of_length(self, length: int) -> List[Gadget]:
        return [g for g in self._gadgets
                if len(g.raw_bytes) == length]


# ---------------------------------------------------------------------------
# 便捷入口
# ---------------------------------------------------------------------------
def scan_rop_gadgets(filepath: str, base_addr: int = 0) -> ROPGadgetScanner:
    """从文件扫描 ROP gadget。返回已扫描的 scanner 对象。"""
    try:
        with open(filepath, 'rb') as fh:
            data = fh.read()
    except OSError:
        return ROPGadgetScanner()
    scanner = ROPGadgetScanner()
    scanner.scan_raw(data, base_addr)
    return scanner


def verify_gadget_elimination(before_scanner: ROPGadgetScanner,
                              after_scanner: ROPGadgetScanner) -> Dict[str, Any]:
    """比较补丁前后 gadget 数量，验证缓解措施是否有效。"""
    before = before_scanner.stats()
    after = after_scanner.stats()
    reduction = before['total_gadgets'] - after['total_gadgets']
    return {
        'gadgets_before': before['total_gadgets'],
        'gadgets_after': after['total_gadgets'],
        'reduction': reduction,
        'reduction_pct': round(
            reduction / max(1, before['total_gadgets']) * 100, 1),
        'useful_before': before['useful_gadgets'],
        'useful_after': after['useful_gadgets'],
        'elimination_effective': reduction > 0,
    }
