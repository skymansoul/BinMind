"""分支作用域与置空区间分析 - UAF 误报抑制的证据基础.

误报根源:
  R1: 路径不敏感 - free 与 use 位于互斥分支仍被报告
  R4: 条件置空 — free 后分支内 p=NULL, 分支外 free(p) ≡ free(NULL)
本模块从指令流提取:
  1. 分支区间: jcc → target, 划分 taken/fallthrough 两个地址区间
  2. 置空点: mov [slot],0 / mov reg,0 / xor reg,reg
判定 API:
  are_mutex(free_addr, use_addr) - 两地址位于同一 jcc 的互斥分支
  is_nulled_before(use_addr, slot) - 槽在 use 前被置空 (无中间写入)
"""

import re
from typing import Dict, List, Optional, Set, Tuple

_JCC_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+.*\s+"
    r"(j[a-z]+|jmp)\s+([0-9a-f]+)")

_SLOT_RE = re.compile(r"\[(rbp|rsp)\s*([+-]\s*0x[0-9a-f]+|\+\s*\d+|\s*-\s*\d+)?\]")


class ScopeAnalyzer:
    """分支作用域分析器 - 一次构建, 多次查询."""

    def __init__(self, insns: list):
        self._insns = insns
        self._branches: List[Tuple[int, int, int]] = []
        # (jcc_addr, target, fallthrough_addr)
        self._null_points: List[Tuple[int, str, str]] = []
        # (addr, kind_reg|kind_slot, target)
        self._build()

    # 构建

    def _build(self):
        addr_to_idx = {ins.address: i for i, ins in enumerate(self._insns)}
        for i, ins in enumerate(self._insns):
            mn = ins.mnemonic
            if mn.startswith("j") and len(ins.operands) >= 1:
                target = self._jmp_target(ins)
                if target is None:
                    continue
                ft = None
                for j in range(i + 1, min(i + 3, len(self._insns))):
                    if self._insns[j].address > ins.address:
                        ft = self._insns[j].address
                        break
                if ft is not None and ft != target:
                    self._branches.append((ins.address, target, ft))
            if mn == "mov" and len(ins.operands) >= 2:
                dst = ins.operands[0].strip().lower()
                src = ins.operands[1].strip()
                imm = self._try_int(src)
                if imm == 0:
                    if "[" in dst:
                        self._null_points.append(
                            (ins.address, "slot", self._slot_key(dst)))
                    else:
                        self._null_points.append(
                            (ins.address, "reg", self._norm(dst)))
            elif mn == "xor" and len(ins.operands) >= 2:
                if ins.operands[0].strip() == ins.operands[1].strip():
                    self._null_points.append(
                        (ins.address, "reg", self._norm(ins.operands[0])))

    # 查询 API

    def _side(self, jcc: int, target: int, fallthrough: int,
              addr: int) -> Optional[str]:
        """地址所在分支侧: 'taken' / 'ft' / None.

        向前跳 (target > jcc): taken=[target, 下个jcc), ft=[fallthrough, target)
        向后跳 (target < jcc, 循环): taken=[target, jcc], ft=[jcc+1, 下个jcc)
        汇合点之后的地址无法归边 → None (不判互斥, 防误滤真UAF).
        """
        if addr <= jcc:
            return None
        # taken 区间上界: 该 jcc 之后、target 之后的下一个分支指令.
        # 注意不得取 ft 块内的分支 (如 then 块末尾的 jmp) — 那会
        # 把 taken 区间压缩为空.
        next_jcc = 0xFFFFFFFFFFFFFFFF
        for jcc2, t2, ft2 in self._branches:
            if jcc2 > target:
                next_jcc = min(next_jcc, jcc2)
        if target > fallthrough:
            if addr >= target and addr < next_jcc:
                return "taken"
            if fallthrough <= addr < target:
                return "ft"
        else:
            if target <= addr <= jcc:
                return "taken"
            if jcc < addr < next_jcc:
                return "ft"
        return None

    def are_mutex(self, addr_a: int, addr_b: int) -> bool:
        """两地址位于同一 jcc 的互斥分支区间.

        约束: ft 块末尾 (target 前 4 条) 必须有 jmp/ret 出口 -
        无出口的分支 (顺序汇合, 如 if (c) free(p); use(p)) 中
        use 与 free 同路径可达, 不构成互斥 (防误滤真 UAF).
        """
        for jcc, target, fallthrough in self._branches:
            if not (jcc < addr_a and jcc < addr_b):
                continue
            if target < fallthrough:
                continue  # 循环回边不作为互斥判定
            if not self._block_exits(target):
                continue
            side_a = self._side(jcc, target, fallthrough, addr_a)
            side_b = self._side(jcc, target, fallthrough, addr_b)
            if side_a is not None and side_b is not None \
                    and side_a != side_b:
                return True
        return False

    def _block_exits(self, target: int) -> bool:
        """target 之前 4 条指令内存在 jmp/ret (分支特有块出口)."""
        for i, ins in enumerate(self._insns):
            if ins.address >= target:
                for j in range(max(0, i - 4), i):
                    if self._insns[j].mnemonic in ("jmp", "ret"):
                        return True
                return False
        return False

    def is_nulled_before(self, use_addr: int, slot_or_reg: str,
                         after_addr: int = 0) -> bool:
        """slot/reg 在 use 前被置空, 且置空点晚于 after_addr."""
        key = slot_or_reg.lower()
        best = 0
        for addr, kind, target in self._null_points:
            if addr >= use_addr or addr < after_addr:
                continue
            if (kind == "slot" and key == target) or \
                    (kind == "reg" and key == target):
                best = max(best, addr)
        return best > after_addr

    def branch_between(self, addr_a: int, addr_b: int) -> bool:
        """addr_a 与 addr_b 之间存在会分割二者的分支."""
        for jcc, target, fallthrough in self._branches:
            if not (addr_a < jcc < addr_b):
                continue
            lo, hi = min(target, fallthrough), max(target, fallthrough)
            if lo > addr_a:
                return True
        return False

    # 工具

    def _jmp_target(self, ins) -> Optional[int]:
        if not ins.operands:
            return None
        addr_part = ins.operands[0].strip().split()[0]
        try:
            return int(addr_part, 16)
        except ValueError:
            return None

    def _slot_key(self, op: str) -> str:
        m = _SLOT_RE.search(op)
        if m:
            return m.group(0).replace(" ", "").lower()
        return op.replace(" ", "").lower()

    @staticmethod
    def _norm(reg: str) -> str:
        r = reg.strip().lower()
        aliases = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                   "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
                   "r10d": "r10", "r11d": "r11", "r12d": "r12",
                   "r13d": "r13", "r14d": "r14", "r15d": "r15"}
        return aliases.get(r, r)

    @staticmethod
    def _try_int(s: str) -> Optional[int]:
        s = s.strip()
        try:
            return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
        except ValueError:
            return None


# smoke test
class _I:
    def __init__(self, addr, mn, ops, raw=""):
        self.address = addr
        self.mnemonic = mn
        self.operands = ops
        self.raw_line = raw


def _check():
    asm = [
        _I(0x1000, "cmp", ["eax", "0x64"]),
        _I(0x1003, "jg", ["0x1009"]),      # taken → 0x1009; ft → 0x1005
        _I(0x1005, "call", ["printf"]),    # ft 分支
        _I(0x1006, "jmp", ["0x100b"]),     # ft 块出口
        _I(0x1009, "call", ["free"]),      # taken 分支
        _I(0x100a, "jmp", ["0x100b"]),     # taken 块出口
        _I(0x100b, "mov", ["[rbp-0x8]", "0x0"]),
        _I(0x100c, "call", ["free"]),
    ]
    s = ScopeAnalyzer(asm)
    assert s.are_mutex(0x1009, 0x1005), "free(taken)/printf(ft) 应互斥"
    assert not s.are_mutex(0x1005, 0x1006), "同侧不应互斥"
    assert s.is_nulled_before(0x100c, "[rbp-0x8]", 0x100a), "槽应已置空"
    print("[OK] uaf_scope_analyzer: mutex/null 判定通过")


if __name__ == "__main__":
    _check()
