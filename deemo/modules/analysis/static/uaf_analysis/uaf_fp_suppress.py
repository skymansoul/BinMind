"""UAF 误报融合抑制 — 消费 BinaryUafScanner 原始 findings 做证据过滤.

规则 (每条给出可审计证据, 无法证明安全的保持原样):
  S1 pass_as_arg 无害化 — callee 分类 HARMLESS (printf %p 等)
  S2 分支互斥 — use 与 freed 源位于同一 jcc 的互斥分支
  S3 置空 free — double_free 的实参槽在 free 前被置空 ≡ free(NULL)
  S4 伪逃逸 — 被调函数 free 后 ret 前 rax 无显式定义 (残留值)
  S5 realloc 语义 — freed 源为 realloc 且判空成功路径重赋值
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from .uaf_callee_class import CalleeClassifier, CalleeClass
from .uaf_scope_analyzer import ScopeAnalyzer


class UafFpSuppressor:
    """UAF 误报抑制器 — findings 级后处理."""

    def __init__(self, insns: list, binary_path: Optional[str] = None,
                 func_map: Optional[Dict[int, str]] = None):
        self._insns = insns
        self._scope = ScopeAnalyzer(insns)
        self._classifier = CalleeClassifier(binary_path)
        self._func_map = func_map or {}
        self._suppressed: List[Tuple[dict, str]] = []

    def suppress(self, findings: List[dict]) -> List[dict]:
        """过滤 findings, 返回保留项; 抑制项带证据."""
        kept = []
        for f in findings:
            verdict, reason = self._decide(f)
            if verdict == "keep":
                kept.append(f)
            else:
                self._suppressed.append((f, reason))
        return kept

    def suppressed_evidence(self) -> List[dict]:
        return [{"insn_addr": f.get("insn_addr", 0),
                 "subtype": f.get("subtype", ""),
                 "reason": r}
                for f, r in self._suppressed]

    # 判定

    def _decide(self, f: dict) -> Tuple[str, str]:
        subtype = f.get("subtype", "")
        addr = f.get("insn_addr", 0)
        call_idx = self._addr_idx(addr)

        if subtype == "pass_as_arg":
            return self._decide_pass(f, addr, call_idx)
        if subtype == "double_free":
            return self._decide_double_free(f, addr, call_idx)
        if subtype == "cross_func_return":
            return self._decide_cross_return(f, addr)
        if subtype in ("realloc_dangling", "realloc_zero_free"):
            return self._decide_realloc(f, addr, call_idx)
        return "keep", ""

    def _decide_pass(self, f: dict, addr: int,
                     call_idx: Optional[int]) -> Tuple[str, str]:
        reason = f.get("reason", "")
        m = re.search(r"passed to (\S+?)\(\)", reason)
        callee = m.group(1) if m else ""
        fm = re.search(r"freed ptr in (\w+) passed", reason)
        freed_reg = fm.group(1) if fm else "rcx"
        fm_addr = re.search(r"freed@0x([0-9a-f]+)", reason)
        free_addr = int(fm_addr.group(1), 16) if fm_addr else 0
        # S1: 无害 callee
        cls = self._classifier.classify(
            callee, fmt_reg="rcx", call_idx=call_idx, insns=self._insns)
        if cls == CalleeClass.HARMLESS:
            return "drop", f"S1 harmless callee {callee} (value-only pass)"
        # S2: 分支互斥 (free 与 use)
        if free_addr and self._scope.are_mutex(free_addr, addr):
            return "drop", f"S2 free@{hex(free_addr)} and use " \
                           f"@{hex(addr)} on mutex branches"
        # S5: realloc 源 — 判空+改名是唯一判据; realloc 源不走 S7
        if free_addr and self._is_realloc_source(free_addr):
            if self._realloc_renamed(free_addr):
                return "drop", f"S5 realloc@{hex(free_addr)} " \
                               f"guarded + renamed on success"
            return "keep", ""
        # S6: 置空后判空守卫
        if free_addr and self._guard_nulled(free_addr, addr, call_idx,
                                            freed_reg):
            return "drop", f"S6 slot nulled after free@{hex(free_addr)} " \
                           f"and use guarded by null check"
        # S7: 陈旧标记 — freed 寄存器被非 freed 源重定义, 且
        # 其它参数寄存器无 freed 链 (单参函数形态)
        if call_idx is not None and self._stale_marker(
                call_idx, freed_reg):
            return "drop", f"S7 arg {freed_reg} redefined by non-freed " \
                           f"source — stale marker, no freed chain in args"
        return "keep", ""

    def _stale_marker(self, call_idx: int, freed_reg: str) -> bool:
        """判定 freed 标记是否陈旧 (实参实际非 freed).

        条件: (a) freed 寄存器在 call 前被非 freed 源重定义;
              (b) 其它参数寄存器在 call 前无任何寄存器/槽定义
                  (无 freed 链可能) — 保守: 有定义即不滤.
        """
        if not self._redefined_non_freed(call_idx, freed_reg):
            return False
        freed_norm = self._reg_of(freed_reg)
        for reg in ("rcx", "rdx", "r8", "r9"):
            if reg == freed_norm:
                continue
            if self._arg_defined(call_idx, reg):
                return False
        return True

    def _arg_defined(self, call_idx: int, reg: str) -> bool:
        """call 前 reg 是否有定义 (寄存器或内存来源)."""
        for j in range(call_idx - 1, max(0, call_idx - 8), -1):
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs", "lea", "movzx",
                                    "movsx") or len(ins.operands) < 2:
                continue
            if self._reg_of(ins.operands[0]) == reg:
                src = ins.operands[1].strip()
                if "[" in src or self._reg_of(src):
                    return True
                return False
        return False

    def _redefined_non_freed(self, call_idx: int, reg: str) -> bool:
        """call 前 reg 被非 freed 来源重新定义, 支持寄存器链追迹.

        rcx ← mov rcx, rax ← lea rax,[rip+fmt] — 链式判定非 freed.
        """
        reg = self._reg_of(reg)
        for hop in range(3):
            defined = False
            for j in range(call_idx - 1, max(0, call_idx - 8), -1):
                ins = self._insns[j]
                if ins.mnemonic not in ("mov", "movabs", "lea") or \
                        len(ins.operands) < 2:
                    continue
                if self._reg_of(ins.operands[0]) != reg:
                    continue
                defined = True
                src = ins.operands[1].strip()
                if ins.mnemonic == "lea":
                    base, _, _, _ = self._parse_mem(src)
                    return base == "rip" or base in ("rbp", "rsp")
                if self._try_int(src) is not None:
                    return True
                base, _, _, _ = self._parse_mem(src)
                if base == "rip":
                    return True
                r = self._reg_of(src)
                if r:
                    reg = r
                    call_idx = j
                else:
                    return False
                break
            if not defined:
                return False
        return False

    @staticmethod
    def _parse_mem(op: str):
        import re as _re
        m = _re.search(r"\[(.+)\]", op)
        if not m:
            return None, None, 1, 0
        inner = m.group(1)
        for part in inner.replace("-", "+-").split("+"):
            part = part.strip()
            if part in ("rip", "rbp", "rsp", "rax", "rcx", "rdx",
                        "rbx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                return part, None, 1, 0
        return None, None, 1, 0

    @staticmethod
    def _try_int(s: str):
        s = s.strip()
        try:
            return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
        except ValueError:
            return None

    def _decide_double_free(self, f: dict, addr: int,
                            call_idx: Optional[int]) -> Tuple[str, str]:
        # S3: 实参槽被置空 → free(NULL)
        if call_idx is None:
            return "keep", ""
        for reg in ("rcx", "rdi"):
            slot = self._arg_source_slot(call_idx, reg)
            if slot:
                if self._scope.is_nulled_before(addr, slot,
                                                f.get("freed_at", 0)):
                    return "drop", f"S3 arg slot {slot} nulled before " \
                                   f"free@{hex(addr)} ≡ free(NULL)"
        # S2: 两次 free 互斥分支 (条件释放)
        fm = f.get("freed_at", 0)
        if fm and self._scope.are_mutex(fm, addr):
            return "drop", f"S2 first free@{hex(fm)} and second " \
                           f"@{hex(addr)} on mutex branches"
        return "keep", ""

    def _decide_cross_return(self, f: dict, addr: int) -> Tuple[str, str]:
        # S4: 被调函数 free 后 ret 前 rax 无显式定义 → 伪逃逸
        reason = f.get("reason", "")
        m = re.search(r"(\w+)\(\) returns freed ptr", reason)
        func = m.group(1) if m else ""
        if not func:
            return "keep", ""
        if not self._callee_defines_rax_after_free(addr, func):
            return "drop", f"S4 {func}() frees but never defines rax " \
                           f"before ret — stale value, not escaped freed ptr"
        return "keep", ""

    def _decide_realloc(self, f: dict, addr: int,
                        call_idx: Optional[int]) -> Tuple[str, str]:
        # S5 同类: 该 realloc 调用点有判空+重赋值 → 旧指针保留合法
        if self._realloc_renamed(addr):
            return "drop", f"S5 realloc@{hex(addr)} renamed on success " \
                           f"— old ptr valid only on failure path"
        return "keep", ""

    # realloc 语义辅助

    def _is_realloc_source(self, addr: int) -> bool:
        idx = self._addr_idx(addr)
        if idx is None:
            return False
        ins = self._insns[idx]
        return ins.mnemonic == "call" and "realloc" in \
            (ins.operands[0] if ins.operands else "")

    def _realloc_renamed(self, realloc_addr: int) -> bool:
        """realloc 后有 test rax 判空且成功路径将新指针写入 freed 槽."""
        idx = self._addr_idx(realloc_addr)
        if idx is None:
            return False
        has_null_check = False
        for j in range(idx + 1, min(idx + 12, len(self._insns))):
            ins = self._insns[j]
            if ins.mnemonic in ("test", "cmp"):
                ops = " ".join(ins.operands)
                if "rax" in ops or "eax" in ops or \
                        ("[" in ops and "0x0" in ops):
                    has_null_check = True
                    continue
            if ins.mnemonic.startswith("j") and ins.operands and \
                    has_null_check:
                # 判空分支存在; 成功路径必须将新指针写入槽 (改名)
                for k in range(j + 1, min(j + 6, len(self._insns))):
                    nxt = self._insns[k]
                    if nxt.mnemonic == "mov" and len(nxt.operands) >= 2:
                        src = nxt.operands[1].strip()
                        if self._reg_of(src) in ("rax", "eax"):
                            if "[" in nxt.operands[0]:
                                return True
                return False  # 判空但成功路径未改名 → 非"失败保留"形态
        return False

    # 伪逃逸辅助

    def _callee_defines_rax_after_free(self, call_addr: int,
                                       func: str) -> bool:
        """被调函数内 free 之后到 ret 之间 rax 是否被显式定义.

        扫描被调函数的指令区间 (call 目标 → 下一函数起始),
        而非调用点之后的调用者指令 — 调用者区间不包含函数体.
        """
        idx = self._addr_idx(call_addr)
        if idx is None:
            return False
        ins = self._insns[idx]
        target = self._jmp_target_of(ins)
        if target is None:
            return False
        # 函数边界: 下一函数起始地址 (符号表) — 缺省为指令流末
        # TODO: 剥离二进制的函数边界恢复, 当前退化为指令流末,
        # 跨函数 rax 定义判定可能误扫到相邻函数
        func_end = 0xFFFFFFFFFFFFFFFF
        for start in sorted(self._func_map):
            if start > target:
                func_end = start
                break
        if func_end == 0xFFFFFFFFFFFFFFFF:
            for x in self._insns:
                if x.address > target:
                    func_end = x.address
                    break
        saw_free = False
        for ins in self._insns:
            if ins.address < target or ins.address >= func_end:
                continue
            ops = " ".join(ins.operands)
            if ins.mnemonic == "call":
                if not saw_free and "free" in ops:
                    saw_free = True
                continue
            if ins.mnemonic == "ret":
                break
    def _callee_defines_rax_after_free(self, call_addr: int,
                                       func: str) -> bool:
        """被调函数内 free 之后到 ret 之间 rax 是否被显式定义.

        扫描被调函数的指令区间 (call 目标 → 下一函数起始).
        与 free 位于互斥分支的 rax 定义不算逃逸证据 (normal 路径
        的继续使用, 非释放后逃逸).
        """
        idx = self._addr_idx(call_addr)
        if idx is None:
            return False
        ins = self._insns[idx]
        target = self._jmp_target_of(ins)
        if target is None:
            return False
        # 函数边界: 下一函数起始地址 (符号表) — 缺省为指令流末
        # TODO: 剥离二进制的函数边界恢复, 当前退化为指令流末,
        # 跨函数 rax 定义判定可能误扫到相邻函数
        func_end = 0xFFFFFFFFFFFFFFFF
        for start in sorted(self._func_map):
            if start > target:
                func_end = start
                break
        if func_end == 0xFFFFFFFFFFFFFFFF:
            for x in self._insns:
                if x.address > target:
                    func_end = x.address
                    break
        saw_free = False
        free_addr = 0
        for ins in self._insns:
            if ins.address < target or ins.address >= func_end:
                continue
            ops = " ".join(ins.operands)
            if ins.mnemonic == "call":
                if not saw_free and "free" in ops:
                    saw_free = True
                    free_addr = ins.address
                continue
            if ins.mnemonic == "ret":
                break
            if not saw_free:
                continue
            if ins.mnemonic in ("mov", "movabs", "lea") and \
                    len(ins.operands) >= 2:
                dst_raw = ins.operands[0].strip().lower()
                # 只认 64 位 rax 定义 — mov eax, -1 是显式返回值,
                # 不是逃逸 freed 指针的证据
                if dst_raw.startswith("r") and \
                        self._reg_of(dst_raw) == "rax":
                    if not self._scope.are_mutex(free_addr, ins.address):
                        return True
        return False

    def _jmp_target_of(self, ins) -> Optional[int]:
        if not ins.operands:
            return None
        addr_part = ins.operands[0].strip().split()[0]
        try:
            return int(addr_part, 16)
        except ValueError:
            return None

    # S6: 置空 + 判空守卫

    def _guard_nulled(self, free_addr: int, use_addr: int,
                      call_idx: Optional[int],
                      freed_reg: str = "rcx") -> bool:
        """free 后槽被置空, use 前存在对槽/寄存器的判空守卫.

        遍历 4 个参数寄存器 — freed 标记可能落在陈旧寄存器
        (fmt 占位), 真实解引用参数在其它寄存器.
        """
        if call_idx is None:
            return False
        for reg in ("rcx", "rdx", "r8", "r9"):
            arg_reg = self._arg_reg_at(call_idx, reg)
            if arg_reg is None or arg_reg.startswith("rip"):
                continue
            nulled = self._scope.is_nulled_before(use_addr, arg_reg,
                                                  free_addr)
            if not nulled:
                continue
            if self._null_guard_before(use_addr, arg_reg):
                return True
        return False

    def _null_guard_before(self, use_addr: int, arg_reg: str) -> bool:
        """use 前是否存在对 arg_reg 的判空 jcc, use 在非空侧."""
        arg_key = arg_reg.replace(" ", "").lower()
        for i, ins in enumerate(self._insns):
            if ins.address >= use_addr:
                break
            if ins.mnemonic not in ("cmp", "test"):
                continue
            ops = " ".join(ins.operands).replace(" ", "").lower()
            if arg_key not in ops:
                continue
            if "0x0" not in ops and not ops.endswith(",0"):
                continue
            for k in range(i + 1, min(i + 3, len(self._insns))):
                jcc = self._insns[k]
                if not jcc.mnemonic.startswith("j"):
                    continue
                tgt = self._jmp_target_of(jcc)
                if tgt is None:
                    continue
                if use_addr >= tgt and jcc.mnemonic in ("jne", "jnz"):
                    return True
                if use_addr < tgt and jcc.mnemonic in ("je", "jz"):
                    return True
        return False

    def _arg_reg_at(self, call_idx: int,
                    reg: str = "rcx", hops: int = 5) -> Optional[str]:
        """call 点实参寄存器 (reg 的赋值来源), 递归追迹到槽.

        处理 movzx/movsx/movsxd 读取链: edx ← eax ← movzx eax,[rax]
        ← rax ← mov rax,[rbp-0x8] — 返回槽 [rbp-0x8].
        """
        if hops <= 0:
            return None
        reg = self._reg_of(reg)
        for j in range(call_idx - 1, max(0, call_idx - 8), -1):
            ins = self._insns[j]
            if ins.mnemonic not in ("mov", "movabs", "lea", "movzx",
                                    "movsx", "movsxd") or \
                    len(ins.operands) < 2:
                continue
            dst = self._reg_of(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if "[" in src:
                base, _, _, _ = self._parse_mem(src)
                if base in ("rbp", "rsp"):
                    return self._slot_key(src)
                if base:
                    return self._arg_reg_at(j, base, hops - 1)
                return self._slot_key(src)
            r = self._reg_of(src)
            if r:
                return self._arg_reg_at(j, r, hops - 1)
            return None
        return None

    # 通用辅助

    def _arg_source_slot(self, call_idx: int, reg: str) -> Optional[str]:
        """call 前 reg 的赋值来源: [rbp-0xN] 槽, 支持寄存器链追迹."""
        reg = self._reg_of(reg)
        for hop in range(3):
            found = False
            for j in range(call_idx - 1, max(0, call_idx - 8), -1):
                ins = self._insns[j]
                if ins.mnemonic not in ("mov", "movabs", "lea") or \
                        len(ins.operands) < 2:
                    continue
                if self._reg_of(ins.operands[0]) != reg:
                    continue
                src = ins.operands[1].strip()
                if "[" in src:
                    return self._slot_key(src)
                r = self._reg_of(src)
                if r:
                    reg = r
                    call_idx = j
                    found = True
                break
            if not found:
                return None
        return None

    @staticmethod
    def _slot_key(op: str) -> str:
        """统一槽键: '[rbp-0x8]' 形态 (去 QWORD PTR 等前缀)."""
        import re as _re
        m = _re.search(r"\[(rbp|rsp)\s*([+-]\s*0x[0-9a-f]+|[+-]\s*\d+)\]",
                       op)
        if m:
            return f"[{m.group(1)}{m.group(2).replace(' ', '')}]"
        return op.lower().replace(" ", "")

    def _addr_idx(self, addr: int) -> Optional[int]:
        for i, ins in enumerate(self._insns):
            if ins.address == addr:
                return i
        return None

    @staticmethod
    def _reg_of(op: str) -> str:
        aliases = {"eax": "rax", "ebx": "rbx", "ecx": "rcx",
                   "edx": "rdx", "esi": "rsi", "edi": "rdi",
                   "r8d": "r8", "r9d": "r9", "r10d": "r10",
                   "r11d": "r11", "al": "rax", "bl": "rbx",
                   "cl": "rcx", "dl": "rdx", "sil": "rsi",
                   "dil": "rdi", "r8b": "r8", "r9b": "r9",
                   "r10b": "r10", "r11b": "r11",
                   "ax": "rax", "bx": "rbx", "cx": "rcx",
                   "dx": "rdx", "si": "rsi", "di": "rdi",
                   "r8w": "r8", "r9w": "r9", "spl": "rsp",
                   "bpl": "rbp", "ah": "rax", "bh": "rbx",
                   "ch": "rcx", "dh": "rdx"}
        op = op.strip().lower()
        m = re.search(r"\b([re]?[a-z0-9]+|r[0-9]+[bwd]?)\b", op)
        if m:
            r = m.group(1)
            return aliases.get(r, r)
        return ""


# smoke test
def _check():
    insns = []
    f = {"type": "uaf", "subtype": "pass_as_arg", "insn_addr": 0x200,
         "reason": "freed ptr in rcx passed to strlen() "
                   "(freed@0x100)"}
    s = UafFpSuppressor(insns)
    v, r = s._decide(f)
    assert v == "keep", f"strlen 应保留, got {v} {r}"
    f2 = {"type": "uaf", "subtype": "pass_as_arg", "insn_addr": 0x200,
          "reason": "freed ptr in rcx passed to free() (freed@0x100)"}
    v, r = s._decide(f2)
    assert v == "keep", "free 应保留 (double-free 语义)"
    print("[OK] uaf_fp_suppress: 危险 callee 保留, 抑制逻辑就绪")


if __name__ == "__main__":
    _check()
