# AWSC — Allocation-Write Co-Sourcing (分配-写入同源关联引擎).
#
# 决策逻辑:
#   堆溢出静态检测最大的误报类: malloc(N) 与 memcpy(ptr, src, M) 中
#   N 和 M 实际来自同一数据流 (同一栈槽/参数/寄存器链), 即
#   "分配=写入" 不可能溢出. 区间分析只看到两区间重叠即告警.
#   本引擎从分配/写入调用点的 size 参数寄存器出发, 沿指令流反向做
#   def-use 根来源追踪, 归约到四类根: 立即数/栈槽/函数参数/返回值.
#   同根且线性变换相同 → SAFE; 写入根 = 分配根 + k (k>0) → 溢出.
#   padding-safe 仅对精确立即数分配根启用 (符号根值未知 → 视为风险).
#   32 位立即数按寄存器宽度符号扩展 (0xffffff80 → -128).
#
#   本文件实现 AWSC 核心管线: 根来源类型与 Root → 操作数反推 → 同源引擎 → 过滤器.

import re
from typing import Dict, List, Optional, Tuple


# 根来源类型与 Root

ROOT_IMM = "imm"          # 立即数
ROOT_STACK = "stack"      # 栈槽 [rbp-0x20]
ROOT_PARAM = "param"      # 函数入口参数寄存器
ROOT_CALLRET = "callret"  # 被调函数返回值 (read/recv → 外部输入)
ROOT_UNKNOWN = "unknown"

_SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_WIN64_ARGS = ("rcx", "rdx", "r8", "r9")

_CALLER_SAVED = set(_SYSV_ARGS) | {"r10", "r11", "rax"}


class Root:
    """size 参数的根来源."""
    __slots__ = ("kind", "value", "coeff", "const", "confidence")

    def __init__(self, kind: str, value, coeff: int = 1,
                 const: int = 0, confidence: float = 1.0):
        self.kind = kind
        self.value = value
        self.coeff = coeff      # 相对根的线性系数
        self.const = const      # 相对根的常量偏移
        self.confidence = confidence

    def is_unknown(self) -> bool:
        return self.kind == ROOT_UNKNOWN

    def __repr__(self) -> str:
        if self.kind == ROOT_UNKNOWN:
            return "?"
        base = {"imm": f"#{self.value}", "stack": f"[{self.value}]",
                "param": f"arg({self.value})",
                "callret": f"ret({self.value})"}.get(self.kind, "?")
        if self.coeff != 1 or self.const != 0:
            return f"{self.coeff}*{base}{self.const:+d}"
        return base


# 内联 norm_reg

_W32_TO_W64_NORM = {"eax": "rax", "ebx": "rbx", "ecx": "rcx",
                    "edx": "rdx", "esi": "rsi", "edi": "rdi",
                    "r8d": "r8", "r9d": "r9", "ax": "rax",
                    "bx": "rbx", "cx": "rcx", "dx": "rdx",
                    "si": "rsi", "di": "rdi"}


def norm_reg(reg: str) -> str:
    """寄存器归一化: ecx→rcx, eax→rax (32→64bit). 剥离objdump注释."""
    r = reg.strip().lower().lstrip("%").replace("$", "")
    if "#" in r:
        r = r.split("#")[0].strip()
    if "[" in r:
        return r
    return _W32_TO_W64_NORM.get(r, r)


# 操作数反推

class CoSourceOperandMixin:
    """操作数反推与解析方法, 由 AWSCEngine 继承."""

    _W32_TO_W64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx",
                   "edx": "rdx", "esi": "rsi", "edi": "rdi",
                   "r8d": "r8", "r9d": "r9", "r10d": "r10",
                   "r11d": "r11", "r12d": "r12", "r13d": "r13",
                   "r14d": "r14", "r15d": "r15"}

    def _step_reg(self, ins: dict, current: str, coeff: int, const: int):
        """寄存器态反推: 找出对 current 的最后一次定义.

        返回: Root | None (无相关定义) | (kind, payload, coeff, const).
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if not ops:
            return None

        dst = self._norm(ops[0]) if len(ops) >= 1 else ""

        # mov/lea 族: dst ← src
        if mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            if dst != current:
                return None
            src = ops[1].strip()
            if self._is_imm(src):
                v = self._parse_imm_signed(src, ops[0])
                if v is None:
                    return ("imm", 0, coeff, const)
                return ("imm", v * coeff + const, 1, 0)
            if "[" in src.lower():
                slot = self._slot_of(src)
                if slot:
                    return ("slot", slot, coeff, const)
                return Root(ROOT_UNKNOWN, 0)
            return ("reg", self._norm(src), coeff, const)

        if mnem == "lea" and len(ops) >= 2:
            if dst != current:
                return None
            base, off, scale = self._parse_mem_full(ops[1])
            if base is None:
                return Root(ROOT_UNKNOWN, 0)
            if scale not in (0, 1):
                # lea rcx, [rbx*4+0] → rcx = 4*rbx → 系数缩放
                return ("reg", self._norm(base), coeff * scale,
                        const + off * coeff)
            return ("reg", self._norm(base), coeff, const + off * coeff)

        # 常量算术: add/sub current, imm|reg
        if mnem in ("add", "sub") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                delta = v if mnem == "add" else -v
                return ("reg", current, coeff, const + delta * coeff)
            # add/sub current, reg: dst_new = dst_old ± src.
            # 主数据流是 dst_old (current 自身), src 通常为次要偏移或
            # 循环变量. 追根应回到 dst_old, 否则误追到 src 导致同源
            # 判定失效. 与 lea rcx,[rcx+rdx] 的语义保持一致.
            return ("reg", current, coeff, const)

        # and current, imm — 位掩码收窄宽度, 不改变根来源与系数
        if mnem == "and" and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                return ("reg", current, coeff, const)
            return None

        # shl/shr current, imm → 系数缩放
        if mnem in ("shl", "shr") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                return ("reg", current, coeff * (1 << v), const)
            return Root(ROOT_UNKNOWN, 0)

        # imul/mul: 非常量乘数使写入量非线性, 单变量线性根无法表达.
        # 若乘数为立即数 → 系数缩放; 否则根来源无法归约 (避免
        # count*elem 与 count 被误判同源而漏报).
        if mnem in ("imul", "mul") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                return ("reg", current, coeff * v, const)
            return Root(ROOT_UNKNOWN, 0)

        # call: 返回值(rax)或 clobber caller-saved
        if mnem == "call":
            if current == "rax":
                func = self._extract_func(ops[0])
                return Root("callret", func, coeff, const)
            if current in _CALLER_SAVED:
                return Root(ROOT_UNKNOWN, 0)
            return None

        return None

    def _step_slot(self, ins: dict, slot_key: str, coeff: int, const: int):
        """栈槽态反推: 找出对 slot_key 的最后一次写入.

        返回: Root | None | (kind, payload, coeff, const).
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if not ops or mnem != "mov":
            return None

        dst = ops[0].strip()
        if "[" not in dst.lower():
            return None
        dst_slot = self._slot_of(dst)
        if dst_slot is None or dst_slot != slot_key:
            return None
        if len(ops) < 2:
            return Root(ROOT_UNKNOWN, 0)

        src = ops[1].strip()
        if self._is_imm(src):
            v = self._parse_imm_signed(src, dst)
            if v is None:
                return ("imm", 0, coeff, const)
            return ("imm", v * coeff + const, 1, 0)
        if "[" in src.lower():
            s2 = self._slot_of(src)
            if s2:
                return ("slot", s2, coeff, const)
            return Root(ROOT_UNKNOWN, 0)
        return ("reg", self._norm(src), coeff, const)

    @staticmethod
    def _slot_of(op: str) -> Optional[str]:
        m = re.search(r'\[(r[bs]p[+-]0x[0-9a-f]+)\]', op.lower())
        if m:
            return m.group(1)
        m = re.search(r'\[(r[bs]p)\]', op.lower())
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _parse_mem_full(op: str) -> Tuple[Optional[str], int, int]:
        """解析内存操作数, 返回 (基址寄存器, 偏移, scale系数).

        支持 [rbp-0x20], [rax+0x10], [rbx*4+0x0] (scaled index),
        [rax+rax*1] (base 与 index 同寄存器 → 系数=1+scale).
        """
        op = op.lower().replace(" ", "")
        m = re.search(r'\[(r[bs]p[+-]0x[0-9a-f]+)\]', op)
        if m:
            base = m.group(1)
            sign = -1 if "-" in base else 1
            try:
                off = sign * int(base.split(("+" if sign > 0 else "-"))[1], 16)
            except (IndexError, ValueError):
                off = 0
            base_reg = "rbp" if "rbp" in base else "rsp"
            return base_reg, off, 1
        m = re.search(r'\[([a-z][a-z0-9]*)(?:\*([0-9]+))?'
                      r'(?:\+([a-z][a-z0-9]*)(?:\*([0-9]+))?)?'
                      r'([+-]0x[0-9a-f]+)?\]', op)
        if m:
            base_reg = m.group(1) or ""
            base_scale = int(m.group(2) or 1)
            idx_reg = m.group(3) or ""
            idx_scale = int(m.group(4) or 1)
            off_str = m.group(5) or ""
            off = 0
            if off_str:
                try:
                    off = int(off_str, 16) if "+" in off_str \
                        else -int(off_str[1:], 16)
                except ValueError:
                    off = 0
            # base 与 index 同寄存器: [rax+rax*2] → 系数 = 1 + 2 = 3
            if idx_reg and idx_reg == base_reg:
                return base_reg, off, base_scale + idx_scale
            if idx_reg:
                return base_reg, off, 1
            if base_reg:
                return base_reg, off, base_scale
        return None, 0, 1

    @staticmethod
    def _parse_mem(op: str) -> Tuple[Optional[str], int]:
        base, off, _ = CoSourceOperandMixin._parse_mem_full(op)
        return base, off

    def _norm(self, reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        if "#" in r:
            r = r.split("#")[0].strip()
        if "[" in r:
            return r
        return self._W32_TO_W64.get(r, r)

    @staticmethod
    def _is_imm(op: str) -> bool:
        s = op.strip().lower().lstrip("$").split("#")[0].strip()
        return (s.startswith("0x") or s.isdigit()
                or (s.startswith("-") and s[1:].isdigit()))

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    def _parse_imm_signed(self, op: str, reg: str = "") -> Optional[int]:
        """按目标寄存器宽度符号扩展 (0xffffff80 → -128)."""
        v = self._parse_imm(op)
        if v is None or v < 0:
            return v
        r = reg.strip().lower().lstrip("%")
        if "[" in r or not r:
            return v
        if r in self._W32_TO_W64 or r.endswith("d"):
            if v >= 0x80000000:
                return v - 0x100000000
        return v

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        m = re.search(r"<([^>]+)>", t)
        if m:
            t = m.group(1)
        return t.split("@")[0].split("(")[0].split(".")[-1]


# 同源引擎

class AWSCEngine(CoSourceOperandMixin):
    """分配-写入同源关联引擎.

    对单个指令序列执行后向 def-use 根来源追踪,
    判定分配大小与写入大小是否来自同一根来源.
    """

    MAX_WINDOW = 300   # 后向扫描最大指令数 (跨函数风险控制)

    def __init__(self, use_win64_abi: bool = False):
        self._args = _WIN64_ARGS if use_win64_abi else _SYSV_ARGS
        self._param_set = set(self._args)

    def trace_size_root(self, instructions: List[dict],
                        call_addr: int, size_reg: str,
                        func_ranges: Optional[List[Tuple[int, int]]] = None
                        ) -> Root:
        """从 call_addr 处 size_reg 反向追踪根来源.

        状态机: state ∈ {"reg", "slot"}, 从 size 寄存器出发,
        沿 def-use 反推, 直至归约到 立即数/参数/返回值/未知.
        """
        if not instructions:
            return Root(ROOT_UNKNOWN, 0)
        idx = self._find_insn(instructions, call_addr)
        if idx < 0:
            return Root(ROOT_UNKNOWN, 0)

        func_lo = self._func_lower_bound(instructions, call_addr, func_ranges)

        state = "reg"
        current = self._norm(size_reg)
        coeff, const = 1, 0

        for i in range(idx - 1, max(0, idx - self.MAX_WINDOW) - 1, -1):
            ins = instructions[i]
            addr = ins.get("address", 0)
            if addr < func_lo:
                break

            if state == "reg":
                root = self._step_reg(ins, current, coeff, const)
            else:  # slot
                root = self._step_slot(ins, current, coeff, const)

            if isinstance(root, Root):
                return root
            if root is None:
                continue

            kind, payload = root[0], root[1]
            if kind == "imm":
                return Root(ROOT_IMM, payload, 1, 0)
            coeff, const = root[2], root[3]
            if kind == "slot":
                state = "slot"
                current = payload
            else:
                state = "reg"
                current = payload

        if state == "reg" and current in self._param_set:
            return Root(ROOT_PARAM, self._args.index(current),
                        coeff, const)
        return Root(ROOT_UNKNOWN, 0, coeff, const)

    def correlate(self, alloc_root: Optional[Root],
                  write_root: Optional[Root],
                  usable_size: int = 0,
                  alloc_value: Optional[int] = None,
                  dst_offset: int = 0
                  ) -> Tuple[str, Optional[int], str]:
        if alloc_root is None or write_root is None:
            return ("unknown", None, "missing_root")
        if alloc_root.is_unknown() or write_root.is_unknown():
            return ("unknown", None, "unknown_root")

        # Case 1: 两常量 → 数值比较 (含写入偏移)
        if (alloc_root.kind == ROOT_IMM and write_root.kind == ROOT_IMM):
            a = alloc_root.value + alloc_root.const
            w = write_root.value + write_root.const + dst_offset
            if w <= a:
                return ("safe", 0, f"imm: write_end={w}<=alloc={a}")
            return ("overflow", w - a, f"imm: write_end={w}>alloc={a}")

        # Case 2: 同根来源 (同栈槽/同参数/同返回值)
        if self._same_base(alloc_root, write_root):
            a_c, a_k = alloc_root.coeff, alloc_root.const
            w_c, w_k = write_root.coeff, write_root.const
            if a_c == w_c:
                # 写入末端 = 写入根 + 目标偏移, 与分配根比较.
                # 偏移计入后 diff>0 即溢出风险, 不因同源即判安全.
                diff = (w_k + dst_offset) - a_k
                if diff <= 0:
                    return ("safe", 0,
                            f"co_source: {alloc_root}=={write_root}")
                # padding-safe 仅当分配根为精确立即数且值可靠时适用.
                # 符号根 (param/stack) 的值无法静态确定 → 偏移视为溢出风险.
                if alloc_root.kind == ROOT_IMM and usable_size > 0:
                    a_val = alloc_root.value + alloc_root.const
                    if a_val + diff <= usable_size:
                        return ("safe", 0,
                                f"co_source: write_end("
                                f"{a_val + diff})<=usable({usable_size})")
                return ("overflow", diff,
                        f"co_source: write>alloc by {diff}")
            return ("unknown", None, "coeff_mismatch")

        # Case 3: 分配为立即数, 写入为变量 → 保守保留
        if alloc_root.kind == ROOT_IMM:
            return ("unknown", None, "imm_vs_var")

        return ("unknown", None, "different_base")

    def trace_dst_offset(self, instructions: List[dict],
                         call_addr: int, ptr_reg: str,
                         func_ranges=None) -> int:
        """追踪写入目标指针相对堆基址的常量偏移.

        memcpy(buf+0x10, src, n) 中 dst 寄存器由 lea dst,[base+0x10]
        或 add dst,0x10 产生. 无法归约为纯常量 → 返回 0 (安全侧).
        """
        if not instructions or not ptr_reg:
            return 0
        idx = self._find_insn(instructions, call_addr)
        if idx < 0:
            return 0
        func_lo = self._func_lower_bound(instructions, call_addr, func_ranges)
        current = self._norm(ptr_reg)
        offset = 0
        for i in range(idx - 1, max(0, idx - 30) - 1, -1):
            ins = instructions[i]
            if ins.get("address", 0) < func_lo:
                break
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if not ops:
                continue
            dst = self._norm(ops[0]) if len(ops) >= 1 else ""
            if dst != current:
                continue
            if mnem == "mov" and len(ops) >= 2:
                src = ops[1].strip()
                if "[" in src.lower():
                    base, off, _ = self._parse_mem_full(src)
                    if base in ("rbp", "rsp"):
                        # 栈槽装载: 分配基址通常存于 [rbp-X], 该装载即
                        # 分配指针. 已累计的偏移即为目标相对分配基址的
                        # 偏移, 返回累计值而非清零 (漏检方向从安全侧走).
                        return offset
                current = self._norm(src)
                continue
            if mnem == "lea" and len(ops) >= 2:
                base, off, scale = self._parse_mem_full(ops[1])
                if base is None or scale != 1:
                    return 0  # 复杂表达式或缩放, 放弃
                offset += off
                current = self._norm(base)
                continue
            if mnem in ("add", "sub") and len(ops) >= 2:
                if self._is_imm(ops[1]):
                    v = self._parse_imm_signed(ops[1], ops[0])
                    if v is None:
                        return 0
                    offset += v if mnem == "add" else -v
                    continue
                return 0  # 寄存器偏移无法静态确定
            return 0  # 其他定义指令, 无法继续追踪
        return offset

    @staticmethod
    def _same_base(a: Root, b: Root) -> bool:
        if a.kind != b.kind:
            return False
        if a.kind in (ROOT_IMM, ROOT_CALLRET, ROOT_PARAM, ROOT_STACK):
            return a.value == b.value
        return False

    def _find_insn(self, instructions: List[dict], addr: int) -> int:
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == addr:
                return i
        return -1

    @staticmethod
    def _func_lower_bound(instructions: List[dict], addr: int,
                          func_ranges: Optional[List[Tuple[int, int]]]
                          ) -> int:
        if func_ranges:
            for lo, hi in func_ranges:
                if lo <= addr < hi:
                    return lo
        return 0


# 过滤器 (alloc_tracker 参数保留为空引用)

class AWSCFPFilter:
    """AWSC 同源关联过滤器."""

    def __init__(self, use_win64_abi: bool = False,
                 alloc_model=None):
        self._engine = AWSCEngine(use_win64_abi=use_win64_abi)
        self._alloc_model = alloc_model
        self._filtered = 0
        self._overflow_confirmed = 0
        self._passed = 0

    def filter(self, findings: List[dict],
               instructions: List[dict],
               alloc_tracker=None,
               func_ranges: Optional[List[Tuple[int, int]]] = None
               ) -> List[dict]:
        """对 Stage1-9 存活告警执行 AWSC 同源过滤."""
        survivors = []
        for finding in findings:
            if "heap" not in finding.get("type", "").lower():
                survivors.append(finding)
                continue

            verdict, detail = self._analyze_one(
                finding, instructions, func_ranges)

            if verdict == "safe":
                # soundness守卫: 同源判定safe但数值写量已超可用量时,
                # 数值证据优先, 保守保留不滤 (避免滤掉真实溢出).
                # 仅当写量为已知具体值 (非未知区间 sentinel) 才应用,
                # 否则未知写量不构成对同源判定的反证.
                ws = finding.get("write_size")
                alloc_value = finding.get("alloc_size", 0) or None
                if isinstance(ws, int) and 0 < ws < 2**31 - 1 \
                        and alloc_value and 0 < alloc_value < 2**31 - 1:
                    usable_guard = self._compute_usable(finding)
                    if ws > usable_guard:
                        self._passed += 1
                        survivors.append(finding)
                        continue
                finding["fp_stage"] = "stage10_awsc"
                finding["fp_reason"] = detail
                self._filtered += 1
                continue
            if verdict == "overflow":
                finding["awsc_confirmed"] = True
                finding["awsc_detail"] = detail
                finding["awsc_dst_offset"] = finding.get("_awsc_offset", 0)
                self._overflow_confirmed += 1

            self._passed += 1
            survivors.append(finding)

        return survivors

    def _analyze_one(self, finding: dict, instructions: List[dict],
                     func_ranges) -> Tuple[str, str]:
        """对单条告警执行同源分析.

        返回: (verdict, detail), verdict ∈ {"safe", "overflow", "unknown"}.
        """
        write_addr = finding.get("write_addr", 0)
        alloc_addr = finding.get("_snapshot_alloc_addr",
                                 finding.get("alloc_addr", 0))
        write_reg = norm_reg(finding.get("size_operand", ""))
        ptr_reg = norm_reg(finding.get("ptr_operand", ""))
        alloc_reg = self._find_alloc_size_reg(
            instructions, alloc_addr, func_ranges)
        usable = finding.get("usable_size", 0) or 0

        if not write_reg:
            return ("unknown", "no_write_reg")
        if alloc_reg is None:
            return ("unknown", "no_alloc_reg")

        write_root = self._engine.trace_size_root(
            instructions, write_addr, write_reg, func_ranges)
        alloc_root = self._engine.trace_size_root(
            instructions, alloc_addr, alloc_reg, func_ranges)

        alloc_value = finding.get("alloc_size", 0) or None
        if usable == 0 and alloc_value:
            usable = self._compute_usable(finding)

        # 写入目标偏移: memcpy(buf+0x10, src, n) 的 +0x10 计入写末端.
        # 偏移来自目标指针 (ptr_operand) 相对分配基址的 lea/add 常量,
        # 若追踪失败视为 0 (安全侧).
        dst_offset = 0
        if ptr_reg:
            dst_offset = self._engine.trace_dst_offset(
                instructions, write_addr, ptr_reg, func_ranges)
        finding["_awsc_offset"] = dst_offset

        verdict, over, reason = self._engine.correlate(
            alloc_root, write_root, usable, alloc_value, dst_offset=dst_offset)
        return verdict, f"alloc_root={alloc_root} write_root={write_root} " \
                        f"usable={usable} dst_offset={dst_offset} {reason}"

    def _compute_usable(self, finding: dict) -> int:
        """计算分配器可用量 (含 padding).

        优先使用 finding 保留的原始请求 alloc_request; 缺失时回退
        alloc_size (对齐上界) 逆推请求下界. usable_size 以原始请求
        为输入做 request2size 映射, 避免对齐值导致可用量偏高.
        """
        request = finding.get("alloc_request")
        if not request or request >= 2**31 - 1:
            alloc_size = finding.get("alloc_size", 0) or 0
            request = max(0, alloc_size - 15)
        if self._alloc_model is not None:
            return self._alloc_model.usable_size(request)
        # 默认 glibc 近似: chunk = align(request+24), usable = chunk - 8
        chunk = max(32, (request + 8 + 15) & ~15)
        return chunk - 8

    @staticmethod
    def _find_alloc_size_reg(instructions: List[dict], alloc_addr: int,
                             func_ranges) -> Optional[str]:
        """在分配调用点前方查找 size 参数寄存器 (SysV rdi / Win64 rcx)."""
        if not instructions:
            return None
        # 向后最多看 20 条, 找到最近一次写 rdi/rcx 的指令
        idx = -1
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == alloc_addr:
                idx = i
                break
        if idx < 0:
            return None
        for j in range(idx - 1, max(0, idx - 20) - 1, -1):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            dst = norm_reg(ops[0])
            if dst in ("rdi", "rcx", "edi", "ecx"):
                src = ops[1].strip()
                src_reg = norm_reg(src)
                if "[" not in src.lower() and src_reg:
                    return src_reg
                return dst
        return None

    @property
    def stats(self) -> dict:
        return {
            "stage10_awsc_filtered": self._filtered,
            "awsc_overflow_confirmed": self._overflow_confirmed,
            "passed": self._passed,
            "total_processed": self._filtered + self._overflow_confirmed
                              + self._passed,
        }


__all__ = [
    "Root", "AWSCEngine", "AWSCFPFilter",
    "ROOT_IMM", "ROOT_STACK", "ROOT_PARAM", "ROOT_CALLRET", "ROOT_UNKNOWN",
]
