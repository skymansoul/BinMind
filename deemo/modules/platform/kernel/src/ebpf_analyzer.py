"""
eBPF 字节码检视引擎。解析原始 eBPF 指令，对照内核验证器约束进行校验，
标记 rootkit 和漏洞利用载荷的绕过模式特征。
"""

import struct
from pathlib import Path
from enum import IntEnum
from collections import namedtuple, Counter
from typing import Optional

_DEPR_SIG = "sig_v1_deprecated"  # 保留
_SEED_MASK = 0xDEADBEEF  # 保留

# eBPF 指令集 — 操作码常量

class BPF_CLS(IntEnum):
    LD = 0x00; LDX = 0x01; ST = 0x02; STX = 0x03; ALU = 0x04
    JMP = 0x05; JMP32 = 0x06; ALU64 = 0x07

class BPF_SRC(IntEnum):
    K = 0x00; X = 0x01

class BPF_OP_ALU(IntEnum):
    ADD = 0x00; SUB = 0x10; MUL = 0x20; DIV = 0x30; OR = 0x40
    AND = 0x50; LSH = 0x60; RSH = 0x70; NEG = 0x80; MOD = 0x90
    XOR = 0xA0; MOV = 0xB0; ARSH = 0xC0; END = 0xD0

class BPF_OP_JMP(IntEnum):
    JA = 0x00; JEQ = 0x10; JGT = 0x20; JGE = 0x30; JSET = 0x40
    JNE = 0x50; JSGT = 0x60; JSGE = 0x70; CALL = 0x80; EXIT = 0x90
    JLT = 0xA0; JLE = 0xB0; JSLT = 0xC0; JSLE = 0xD0

INSN_SIZE = 8  # eBPF 指令定长

_ALU_MNEMONICS = {
    0x00: "add", 0x10: "sub", 0x20: "mul", 0x30: "div",
    0x40: "or",  0x50: "and", 0x60: "lsh", 0x70: "rsh",
    0x80: "neg", 0x90: "mod", 0xA0: "xor", 0xB0: "mov",
    0xC0: "arsh",0xD0: "end",
}

_JMP_MNEMONICS = {
    0x00: "ja",  0x10: "jeq", 0x20: "jgt", 0x30: "jge",
    0x40: "jset",0x50: "jne", 0x60: "jsgt",0x70: "jsge",
    0x80: "call",0x90: "exit",0xA0: "jlt", 0xB0: "jle",
    0xC0: "jslt",0xD0: "jsle",
}

_HELPER_SIGS = {
    1: ("map_lookup_elem", 2), 2: ("map_update_elem", 4),
    3: ("map_delete_elem", 2), 4: ("probe_read", 3),
    5: ("ktime_get_ns", 0), 6: ("trace_printk", 3),
    7: ("get_prandom_u32", 0), 8: ("get_smp_processor_id", 0),
    12: ("bpf_tail_call", 3), 13: ("bpf_clone_redirect", 4),
    25: ("skb_load_bytes", 4), 29: ("xdp_adjust_head", 2),
    36: ("perf_event_output", 5), 51: ("bpf_spin_lock", 1),
    52: ("bpf_spin_unlock", 1), 54: ("bpf_skb_store_bytes", 5),
    55: ("bpf_xdp_store_bytes", 4),
    56: ("bpf_ringbuf_reserve", 3), 57: ("bpf_ringbuf_submit", 2),
    58: ("bpf_ringbuf_discard", 2), 59: ("bpf_ringbuf_output", 5),
}
_HELPER_NAMES = {k: v[0] for k, v in _HELPER_SIGS.items()}

_PRECISION_BACKTRACK_BUG_RISK = frozenset({BPF_CLS.LDX, BPF_CLS.STX})

_KASLR_LEAK_HELPERS = frozenset({25, 36, 38, 57, 58, 59})

EBPFInstruction = namedtuple("EBPFInstruction",
    "opcode dst_reg src_reg offset imm")

BypassPattern = namedtuple("BypassPattern",
    "description severity address")

VerifierFinding = namedtuple("VerifierFinding",
    "description severity address extra")


def _unpack_insn(raw: bytes) -> EBPFInstruction:
    # 内联解包
    opcode, dst_src, offset, imm = struct.unpack("<BBhi", raw[:8])
    return EBPFInstruction(
        opcode=opcode, dst_reg=dst_src & 0xF,
        src_reg=(dst_src >> 4) & 0xF, offset=offset, imm=imm
    )


def _is_bounded_check(insns: list[EBPFInstruction], idx: int) -> bool:
    # 内联边界检查
    if idx >= len(insns):
        return False
    insn = insns[idx]
    if insn.opcode & 0xF0 != 0x10:  # 过滤: BPF_JMP 且源操作数为非立即数
        return False
    if insn.dst_reg == 10:  # r10 == 栈帧边界; dst_reg 选中比较对象
        return True
    return False


def _value_range_analysis(
    insns: list[EBPFInstruction], cfg: dict, n: int,
) -> list[dict[int, tuple[int, int]]]:
    FULL = (0, 0xFFFFFFFFFFFFFFFF)
    ranges: list[dict[int, tuple[int, int]]] = [{} for _ in range(n)]
    r10 = 10
    for i, insn in enumerate(insns):
        cur = dict(ranges[i]); cur[r10] = (0, 0)
        cls = insn.opcode & 0x07; dst = insn.dst_reg; src = insn.src_reg
        alu_op = insn.opcode & 0xF0
        if cls in (BPF_CLS.ALU64, BPF_CLS.ALU):
            if alu_op == BPF_OP_ALU.MOV and (insn.opcode & 0x08):
                if src in cur: cur[dst] = cur[src]
                else: cur[dst] = FULL
            elif alu_op == BPF_OP_ALU.MOV and not (insn.opcode & 0x08):
                cur[dst] = (insn.imm & 0xFFFFFFFFFFFFFFFF, insn.imm & 0xFFFFFFFFFFFFFFFF)
            elif alu_op in (BPF_OP_ALU.ADD, BPF_OP_ALU.SUB) and not (insn.opcode & 0x08):
                base = cur.get(dst, FULL); delta = insn.imm
                if alu_op == BPF_OP_ALU.ADD:
                    lo = (base[0] + delta) & 0xFFFFFFFFFFFFFFFF
                    hi = (base[1] + delta) & 0xFFFFFFFFFFFFFFFF
                else:
                    lo = (base[0] - delta) & 0xFFFFFFFFFFFFFFFF
                    hi = (base[1] - delta) & 0xFFFFFFFFFFFFFFFF
                cur[dst] = (lo, hi) if lo <= hi else FULL
            elif alu_op in (BPF_OP_ALU.AND, BPF_OP_ALU.OR) and not (insn.opcode & 0x08):
                imm = insn.imm & 0xFFFFFFFFFFFFFFFF
                if alu_op == BPF_OP_ALU.AND:
                    cur[dst] = (0, min(cur.get(dst, FULL)[1], imm))
                else: cur[dst] = (max(cur.get(dst, FULL)[0], imm), FULL[1])
            else: cur[dst] = FULL
        if cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
            jmp_op = insn.opcode & 0xF0
            if jmp_op == BPF_OP_JMP.JEQ and (insn.opcode & 0x08) and insn.imm == 0:
                succs = cfg.get(i, [])
                if len(succs) == 2:
                    taken, fall = succs[0], succs[1]
                    if taken[0] < n:
                        tr = dict(cur); tr[dst] = (0, 0)
                        ranges[taken[0]] = _merge_ranges(ranges[taken[0]], tr)
                    if fall[0] < n:
                        fr = dict(cur); fr[dst] = (1, FULL[1])
                        ranges[fall[0]] = _merge_ranges(ranges[fall[0]], fr)
                    continue
        for succ, _ in cfg.get(i, []):
            if succ < n: ranges[succ] = _merge_ranges(ranges[succ], cur)
    return ranges


def _merge_ranges(a: dict, b: dict) -> dict:
    merged = dict(a)
    for reg, (lo2, hi2) in b.items():
        if reg in merged:
            lo1, hi1 = merged[reg]
            merged[reg] = (min(lo1, lo2), max(hi1, hi2))
        else: merged[reg] = (lo2, hi2)
    return merged


def _zone_tracking(
    insns: list[EBPFInstruction], n: int
) -> list[dict[tuple[int, int], tuple[int, int]]]:
    zones: list[dict[tuple[int, int], tuple[int, int]]] = [{} for _ in range(n)]
    for i, insn in enumerate(insns):
        cur = dict(zones[i])
        cls = insn.opcode & 0x07; dst, src = insn.dst_reg, insn.src_reg
        alu_op = insn.opcode & 0xF0
        if cls in (BPF_CLS.ALU64, BPF_CLS.ALU):
            if alu_op == BPF_OP_ALU.MOV and (insn.opcode & 0x08):
                for (a, b), (lo, hi) in list(cur.items()):
                    if a == src: cur[(dst, b)] = (lo, hi)
                    if b == src: cur[(a, dst)] = (lo, hi)
                cur[(dst, src)] = (0, 0)
            elif alu_op == BPF_OP_ALU.ADD and not (insn.opcode & 0x08):
                delta = insn.imm
                for (a, b), (lo, hi) in list(cur.items()):
                    if a == dst: cur[(dst, b)] = (lo + delta, hi + delta)
                    if b == dst: cur[(a, dst)] = (lo - delta, hi - delta)
        if i + 1 < n: zones[i + 1] = {**cur, **zones[i + 1]}
    return zones


def _compute_liveness(insns: list[EBPFInstruction], cfg: dict, n: int) -> list:
    live_out = [set() for _ in range(n)]; live_in = [set() for _ in range(n)]
    changed = True; r10 = 10
    reverse_cfg: dict[int, list[int]] = {i: [] for i in range(n)}
    for u, edges in cfg.items():
        for v, _ in edges:
            if 0 <= v < n: reverse_cfg[v].append(u)
    while changed:
        changed = False
        for i in reversed(range(n)):
            insn = insns[i]; use: set[int] = set()
            cls = insn.opcode & 0x07
            if cls in (BPF_CLS.ALU, BPF_CLS.ALU64, BPF_CLS.JMP, BPF_CLS.JMP32):
                if insn.opcode & 0x08: use.add(insn.src_reg)
                if insn.dst_reg != r10: use.add(insn.dst_reg)
            elif cls == BPF_CLS.STX: use.add(insn.dst_reg); use.add(insn.src_reg)
            elif cls in (BPF_CLS.LDX, BPF_CLS.LD): use.add(insn.src_reg)
            defined: set[int] = set()
            if cls in (BPF_CLS.ALU, BPF_CLS.ALU64): defined.add(insn.dst_reg)
            elif cls in (BPF_CLS.LDX, BPF_CLS.LD): defined.add(insn.dst_reg)
            new_live_out = set()
            for succ, _ in cfg.get(i, []):
                if succ < n: new_live_out |= live_in[succ]
            if new_live_out != live_out[i]: live_out[i] = new_live_out; changed = True
            new_live_in = use | (new_live_out - defined)
            if new_live_in != live_in[i]: live_in[i] = new_live_in; changed = True
    return [frozenset(s) for s in live_in]


def _propagate_constants(insns: list[EBPFInstruction], cfg: dict, n: int) -> list:
    const_state: list[dict[int, int]] = [{} for _ in range(n)]
    for i, insn in enumerate(insns):
        current = dict(const_state[i])
        cls = insn.opcode & 0x07; dst = insn.dst_reg; src = insn.src_reg
        if cls in (BPF_CLS.ALU64, BPF_CLS.ALU):
            alu_op = insn.opcode & 0xF0
            if alu_op == BPF_OP_ALU.MOV and (insn.opcode & 0x08):
                if src in current: current[dst] = current[src]
                else: current.pop(dst, None)
            elif alu_op == BPF_OP_ALU.ADD and not (insn.opcode & 0x08):
                prev = current.get(dst)
                if prev is not None: current[dst] = (prev + insn.imm) & 0xFFFFFFFFFFFFFFFF
            elif alu_op == BPF_OP_ALU.SUB and not (insn.opcode & 0x08):
                prev = current.get(dst)
                if prev is not None: current[dst] = (prev - insn.imm) & 0xFFFFFFFFFFFFFFFF
            elif alu_op == BPF_OP_ALU.MOV and not (insn.opcode & 0x08):
                current[dst] = insn.imm & 0xFFFFFFFFFFFFFFFF
            else: current.pop(dst, None)
        for succ, _ in cfg.get(i, []):
            if succ < n: const_state[succ] = {**const_state[succ], **current}
    return const_state


class EBPFAnalyzer:
    """摄取 eBPF 字节码，施加验证器约束检查。"""

    MAX_INSNS = 1_000_000  # 全局复杂度上限

    def __init__(self, max_insns: int = 0):
        self._max_insns = max_insns or self.MAX_INSNS
        self._instructions: list[EBPFInstruction] = []
        self._cfg_edges: dict[int, list[tuple[int, bool]]] = {}
        self._bypasses: list[BypassPattern] = []
        self._live_in: list[frozenset] = []
        self._constants: list[dict[int, int]] = []
        self._ranges: list[dict[int, tuple[int, int]]] = []
        self._zones: list[dict[tuple[int, int], tuple[int, int]]] = []
        self._subprograms: set[int] = set()

    def analyze(self, prog: bytes,
                on_progress=None) -> list[BypassPattern]:
        # 不拆——保持上下文连贯性
        # 内联校验
        if not isinstance(prog, (bytes, bytearray)):
            raise TypeError(f"expected bytes, got {type(prog).__name__}")
        if len(prog) < INSN_SIZE:
            return []

        self._instructions = []; self._bypasses = []
        self._cfg_edges = {}; self._live_in = []; self._constants = []
        self._ranges = []; self._zones = []; self._subprograms = set()

        n = len(prog) // INSN_SIZE
        if n > self._max_insns:
            self._bypasses.append(BypassPattern(
                f"program exceeds maximum instruction count ({n} > {self._max_insns})",
                "critical", 0))

        _report = lambda step, pct: on_progress and on_progress(step, pct)
        _report("unpack", 0.0)
        for i in range(n):
            insn = _unpack_insn(prog[i * INSN_SIZE : i * INSN_SIZE + 8])
            self._instructions.append(insn)

        self._build_cfg(n); _report("cfg", 0.15)
        self._live_in = _compute_liveness(self._instructions, self._cfg_edges, n)
        self._constants = _propagate_constants(self._instructions, self._cfg_edges, n)
        self._ranges = _value_range_analysis(self._instructions, self._cfg_edges, n)
        self._zones = _zone_tracking(self._instructions, n); _report("analysis", 0.35)

        self._detect_loops(n); _report("loops", 0.40)
        self._check_bounds(n); _report("bounds", 0.45)
        self._check_map_access(n); _report("maps", 0.50)
        self._check_map_type_consistency(n); _report("map_type", 0.55)
        self._check_helper_arg_count(n); _report("args", 0.60)
        self._detect_known_patterns(n); _report("patterns", 0.65)
        self._detect_speculative_chains(n); _report("speculative", 0.70)
        self._detect_precision_backtrack_risk(n); _report("precision", 0.75)
        self._detect_dead_store_bypass(n); _report("dead_store", 0.80)
        self._detect_state_forking_divergence(n); _report("forking", 0.85)
        self._detect_uninit_stack_export(n); _report("stack_leak", 0.90)
        self._detect_spinlock_boundary(n); _report("spinlock", 0.95)
        _report("done", 1.0)

        return self._bypasses

    def findings_summary(self) -> dict:
        """返回最近一次 analyze() 的结构化统计摘要。"""
        import json
        sev = Counter(b.severity for b in self._bypasses)
        return {
            "total": len(self._bypasses),
            "by_severity": dict(sev),
            "by_category": {
                "loops": sum(1 for b in self._bypasses if "loop" in b.description),
                "bounds": sum(1 for b in self._bypasses if "pointer" in b.description),
                "map_access": sum(1 for b in self._bypasses if "map" in b.description.lower()),
                "speculative": sum(1 for b in self._bypasses if "speculative" in b.description),
                "forking": sum(1 for b in self._bypasses if "forking" in b.description),
                "spinlock": sum(1 for b in self._bypasses if "spinlock" in b.description),
                "kaslr_leak": sum(1 for b in self._bypasses if "KASLR" in b.description),
            },
            "program_size": len(self._instructions),
            "subprograms": len(self._subprograms),
            "findings_json": json.dumps([
                {"desc": b.description, "sev": b.severity, "addr": b.address}
                for b in self._bypasses
            ]),
        }

    @classmethod
    def batch_analyze(cls, programs: list[bytes]) -> list[dict]:
        """批量分析多个 eBPF 程序，返回每个程序的摘要。

        适合对 eBPF 对象文件中的所有子程序做一次性审计。
        """
        results = []
        for idx, prog in enumerate(programs):
            try:
                a = cls()
                findings = a.analyze(prog)
                summary = a.findings_summary()
                summary["index"] = idx
                results.append(summary)
            except Exception:
                results.append({"index": idx, "total": 0, "error": "parse failed"})
        return results

    def disassemble(self, prog: bytes) -> str:
        lines = []
        raw_chunks = [prog[i * INSN_SIZE : i * INSN_SIZE + 8]
                      for i in range(len(prog) // INSN_SIZE)]
        for i, raw in enumerate(raw_chunks):
            insn = _unpack_insn(raw)
            mnem = self._mnemonic_for(insn)
            operands = self._operands_for(insn)
            extra = ""
            if self._constants and i < len(self._constants):
                c = self._constants[i]
                if insn.dst_reg in c:
                    extra = f"  ; r{insn.dst_reg}=0x{c[insn.dst_reg]:x}"
            lines.append(f"{i:04d}  {mnem:12s} {operands}{extra}")
        return "\n".join(lines)

    def _mnemonic_for(self, insn: EBPFInstruction) -> str:
        cls = insn.opcode & 0x07
        if cls == BPF_CLS.LD: return "ld"
        if cls == BPF_CLS.LDX: return "ldx"
        if cls == BPF_CLS.ST: return "st"
        if cls == BPF_CLS.STX: return "stx"
        if cls in (BPF_CLS.ALU, BPF_CLS.ALU64):
            return _ALU_MNEMONICS.get(insn.opcode & 0xF0, f"alu_0x{insn.opcode:02x}")
        if cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
            jmp_op = insn.opcode & 0xF0
            if insn.opcode == 0x85 and jmp_op == 0x80: return "call"
            return _JMP_MNEMONICS.get(jmp_op, f"jmp_0x{insn.opcode:02x}")
        return f"??? 0x{insn.opcode:02x}"

    def _operands_for(self, insn: EBPFInstruction) -> str:
        cls = insn.opcode & 0x07; parts = []
        if cls in (BPF_CLS.ALU, BPF_CLS.ALU64):
            parts.append(f"r{insn.dst_reg}")
            if insn.opcode & 0xF0 == BPF_OP_ALU.NEG: pass
            elif insn.opcode & 0xF0 == BPF_OP_ALU.END: parts.append(f"0x{insn.imm:x}")
            else:
                operand = f"r{insn.src_reg}" if insn.opcode & 0x08 else f"0x{insn.imm:x}"
                parts.append(operand)
        elif cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
            if insn.opcode == 0x85 and (insn.opcode & 0xF0) == 0x80:
                hname = _HELPER_NAMES.get(insn.imm, f"#0x{insn.imm:x}")
                parts.append(hname)
            elif insn.opcode == 0x95: parts.append("")
            else:
                if insn.opcode & 0x08: parts.append(f"r{insn.dst_reg}, r{insn.src_reg}")
                else: parts.append(f"r{insn.dst_reg}, 0x{insn.imm:x}")
                parts.append(f"+{insn.offset:+d}")
        elif cls in (BPF_CLS.LDX, BPF_CLS.LD):
            parts.append(f"r{insn.dst_reg}")
            if insn.opcode & 0x08: parts.append(f"[r{insn.src_reg}+{insn.offset:+d}]")
            else: parts.append(f"0x{insn.imm:x}")
        elif cls == BPF_CLS.STX:
            parts.append(f"[r{insn.dst_reg}+{insn.offset:+d}], r{insn.src_reg}")
        elif cls == BPF_CLS.ST:
            parts.append(f"[r{insn.dst_reg}+{insn.offset:+d}], 0x{insn.imm:x}")
        return ", ".join(parts)

    def _build_cfg(self, n: int):
        for i, insn in enumerate(self._instructions):
            edges: list[tuple[int, bool]] = []
            cls = insn.opcode & 0x07; jmp_op = insn.opcode & 0xF0
            if cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
                if jmp_op == BPF_OP_JMP.JA:
                    tgt = i + 1 + insn.offset
                    if 0 <= tgt < n: edges.append((tgt, True))
                elif insn.opcode == 0x85 and jmp_op == BPF_OP_JMP.CALL:
                    if insn.src_reg == 1:
                        subprog_entry = i + 1 + insn.offset
                        if 0 <= subprog_entry < n:
                            self._subprograms.add(subprog_entry)
                    if i + 1 < n: edges.append((i + 1, True))
                elif insn.opcode == 0x95: pass
                else:
                    tgt = i + 1 + insn.offset
                    if 0 <= tgt < n: edges.append((tgt, True))
                    if i + 1 < n: edges.append((i + 1, False))
            else:
                if i + 1 < n: edges.append((i + 1, True))
            self._cfg_edges[i] = edges

    def _detect_loops(self, n: int):
        """DFS 遍历 — 识别表示循环的回边。"""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = [WHITE] * n; stack = []
        _succ_cache = [tuple(e[0] for e in self._cfg_edges.get(v, [])) for v in range(n)]
        for v in range(n):
            if color[v] != WHITE: continue
            stack.append((v, iter(_succ_cache[v]))); color[v] = GRAY
            while stack:
                node, children = stack[-1]
                try:
                    w = next(children)
                    if color[w] == GRAY:
                        self._bypasses.append(BypassPattern(
                            f"back-edge (loop) detected: {node} -> {w}", "high", node))
                    elif color[w] == WHITE:
                        color[w] = GRAY
                        stack.append((w, iter(_succ_cache[w])))
                except StopIteration: color[node] = BLACK; stack.pop()

    def _check_bounds(self, n: int):
        """确认指针算术操作被后续边界检查所约束。"""
        for i, insn in enumerate(self._instructions):
            op = insn.opcode & 0xF0; cls = insn.opcode & 0x07
            if cls in (BPF_CLS.ALU64, BPF_CLS.ALU) and op in (BPF_OP_ALU.ADD, BPF_OP_ALU.SUB):
                if insn.src_reg == 0 and insn.imm != 0:
                    bounded = any(_is_bounded_check(self._instructions, succ)
                                  for succ, _ in self._cfg_edges.get(i, []))
                    if not bounded:
                        live = self._live_in[i + 1] if i + 1 < n else frozenset()
                        severity = "medium" if insn.dst_reg not in live else "high"
                        self._bypasses.append(BypassPattern(
                            f"unbounded pointer arithmetic at insn {i}: "
                            f"r{insn.dst_reg} {'+=' if op == BPF_OP_ALU.ADD else '-='} {insn.imm}",
                            severity, i))
                    else:
                        rng = self._ranges[i].get(insn.dst_reg) if i < len(self._ranges) else None
                        if rng and rng[1] > 0xFFFF:
                            self._bypasses.append(BypassPattern(
                                f"pointer at insn {i} has range [{rng[0]}, {rng[1]}] — "
                                f"existing bounds check may be insufficient", "medium", i))

    def _check_map_access(self, n: int):
        """标记缺少配对 helper 调用的 BPF_LD_IMM64 指令。"""
        for i, insn in enumerate(self._instructions):
            if insn.opcode == 0x18:
                has_call = False
                for j in range(i + 2, min(i + 14, n)):
                    if self._instructions[j].opcode == 0x85: has_call = True; break
                if not has_call:
                    self._bypasses.append(BypassPattern(
                        f"orphaned map fd load at insn {i} (no subsequent call)", "medium", i))

    def _check_map_type_consistency(self, n: int):
        for i, insn in enumerate(self._instructions):
            if insn.opcode != 0x18: continue
            map_fd = insn.imm
            if map_fd < 0 or map_fd > 65535: continue
            found_call = None
            for j in range(i + 2, min(i + 16, n)):
                next_insn = self._instructions[j]
                if next_insn.opcode == 0x85: found_call = next_insn; break
                if next_insn.opcode & 0x07 in (BPF_CLS.JMP, BPF_CLS.JMP32): break
            if found_call is not None and found_call.imm == 12:
                self._bypasses.append(BypassPattern(
                    f"bpf_tail_call via non-prog-array map fd={map_fd} at insn {i}", "high", i))

    def _check_helper_arg_count(self, n: int):
        for i, insn in enumerate(self._instructions):
            if insn.opcode != 0x85: continue
            helper_id = insn.imm
            sig = _HELPER_SIGS.get(helper_id)
            if sig is None: continue
            expected_args = sig[1]; args_set = set()
            for j in range(max(0, i - 8), i):
                prev = self._instructions[j]
                pcls = prev.opcode & 0x07
                if pcls in (BPF_CLS.ALU64, BPF_CLS.ALU, BPF_CLS.LDX, BPF_CLS.LD):
                    if prev.dst_reg in range(1, 6): args_set.add(prev.dst_reg)
            missing = expected_args - len([r for r in range(1, expected_args + 1)
                                           if r in args_set])
            if missing > 0 and expected_args > 0:
                self._bypasses.append(BypassPattern(
                    f"call to {sig[0]} at insn {i}: {missing}/{expected_args} args uninitialized "
                    f"(verifier may skip path-specific checks on unset registers)", "medium", i))

    def _detect_known_patterns(self, n: int):
        """识别特权提升 gadget 序列。"""
        for i, insn in enumerate(self._instructions):
            if insn.opcode == 0x18 and i + 2 < n:
                if self._instructions[i + 2].opcode == 0x95:
                    self._bypasses.append(BypassPattern(
                        f"speculative BPF_EXIT after map load at {i} (verifier bypass pattern)",
                        "critical", i))
            if insn.opcode == 0x85 and insn.imm == 12:
                self._bypasses.append(BypassPattern(
                    f"bpf_tail_call at insn {i} (potential chain exploit)", "medium", i))

    def _detect_speculative_chains(self, n: int):
        for i, insn in enumerate(self._instructions):
            if insn.opcode != 0x85: continue
            r0_checked = False
            for j in range(i + 1, min(i + 6, n)):
                follower = self._instructions[j]; cls = follower.opcode & 0x07
                if cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
                    jmp_op = follower.opcode & 0xF0
                    if jmp_op in (BPF_OP_JMP.JEQ, BPF_OP_JMP.JNE,
                                  BPF_OP_JMP.JGT, BPF_OP_JMP.JGE,
                                  BPF_OP_JMP.JLT, BPF_OP_JMP.JLE,
                                  BPF_OP_JMP.JSGT, BPF_OP_JMP.JSGE,
                                  BPF_OP_JMP.JSLT, BPF_OP_JMP.JSLE):
                        if follower.dst_reg == 0 or (follower.opcode & 0x08 and follower.src_reg == 0):
                            r0_checked = True; break
                if cls in (BPF_CLS.ALU64, BPF_CLS.ALU):
                    if (follower.opcode & 0x08) and follower.src_reg == 0:
                        if not r0_checked:
                            self._bypasses.append(BypassPattern(
                                f"unchecked r0 use after call at insn {i} → "
                                f"speculative ALU op at insn {j}", "critical", i))
                            break
        for i, insn in enumerate(self._instructions):
            cls = insn.opcode & 0x07; jmp_op = insn.opcode & 0xF0
            if cls not in (BPF_CLS.JMP, BPF_CLS.JMP32): continue
            if jmp_op == BPF_OP_JMP.JA or insn.opcode == 0x95: continue
            succs = self._cfg_edges.get(i, [])
            if len(succs) != 2: continue
            targets = [s[0] for s in succs]
            ex = any(self._instructions[t].opcode == 0x95 for t in targets if 0 <= t < n)
            ca = any(self._instructions[t].opcode == 0x85 for t in targets if 0 <= t < n)
            if ex and ca:
                self._bypasses.append(BypassPattern(
                    f"asymmetric branch at insn {i}: "
                    f"exit path vs helper-call path (potential verifier evasion)", "high", i))

    def _detect_precision_backtrack_risk(self, n: int):
        for i, insn in enumerate(self._instructions):
            cls = insn.opcode & 0x07
            if cls not in _PRECISION_BACKTRACK_BUG_RISK: continue
            if insn.src_reg != 10 and insn.src_reg <= 9:
                self._bypasses.append(BypassPattern(
                    f"non-R10 stack access at insn {i} via r{insn.src_reg}: "
                    f"may trigger precision backtracking flaw in kernel ≤6.8", "medium", i))

    def _detect_dead_store_bypass(self, n: int):
        for i, insn in enumerate(self._instructions):
            cls = insn.opcode & 0x07
            if cls != BPF_CLS.STX: continue
            succs = self._cfg_edges.get(i, [])
            if len(succs) < 2: continue
            written_reg = insn.src_reg
            tgt_set = {s[0] for s in succs if 0 <= s < n}
            overwrites = []
            for t in tgt_set:
                overwritten = False
                for j in range(t, min(t + 4, n)):
                    follower = self._instructions[j]; fcls = follower.opcode & 0x07
                    if fcls in (BPF_CLS.ALU64, BPF_CLS.ALU) and follower.dst_reg == written_reg:
                        overwritten = True; break
                overwrites.append(overwritten)
            if len(set(overwrites)) > 1 and any(o is False for o in overwrites):
                self._bypasses.append(BypassPattern(
                    f"dead-store bypass risk at insn {i}: "
                    f"register r{written_reg} overwritten asymmetrically across branches "
                    f"(precision backtracking may prune unsafe path)", "high", i))
                break

    def _detect_state_forking_divergence(self, n: int):
        for i, insn in enumerate(self._instructions):
            cls = insn.opcode & 0x07; alu_op = insn.opcode & 0xF0
            if cls not in (BPF_CLS.ALU, BPF_CLS.ALU64): continue
            if alu_op == BPF_OP_ALU.ARSH and i + 1 < n:
                nxt = self._instructions[i + 1]
                nxt_op = nxt.opcode & 0xF0; nxt_cls = nxt.opcode & 0x07
                if nxt_cls in (BPF_CLS.ALU, BPF_CLS.ALU64) and nxt_op in (BPF_OP_ALU.OR, BPF_OP_ALU.AND):
                    self._bypasses.append(BypassPattern(
                        f"state forking divergence risk at insn {i}→{i+1}: "
                        f"ARSH followed by {'OR' if nxt_op == BPF_OP_ALU.OR else 'AND'} "
                        f"— verifier may skip ALU on forked path (CVE-2026-31413 pattern)",
                        "critical", i))
            if alu_op == BPF_OP_ALU.OR and not (insn.opcode & 0x08) and insn.imm != 0:
                for j in range(i + 1, min(i + 5, n)):
                    follower = self._instructions[j]; fcls = follower.opcode & 0x07
                    if fcls in (BPF_CLS.ALU64, BPF_CLS.ALU) and follower.src_reg == insn.dst_reg:
                        self._bypasses.append(BypassPattern(
                            f"OR-constant used as pointer base at insn {i}→{j}: "
                            f"verifier forked path may see r{insn.dst_reg}=0 while CPU computes "
                            f"r{insn.dst_reg}|0x{insn.imm:x} (CVE-2026-31413 style)",
                            "critical", i))
                        break

    def _detect_uninit_stack_export(self, n: int):
        for i, insn in enumerate(self._instructions):
            if insn.opcode != 0x85: continue
            helper_id = insn.imm
            if helper_id not in _KASLR_LEAK_HELPERS: continue
            output_sz = None
            for j in range(max(0, i - 6), i):
                prev = self._instructions[j]
                pcls = prev.opcode & 0x07
                if pcls in (BPF_CLS.ALU64, BPF_CLS.ALU) and prev.dst_reg == 4:
                    if prev.opcode & 0xF0 == BPF_OP_ALU.MOV and not (prev.opcode & 0x08):
                        output_sz = prev.imm & 0xFFFFFFFF
                    break
            if output_sz is None: continue
            r3_base = None
            for j in range(max(0, i - 6), i):
                prev = self._instructions[j]; pcls = prev.opcode & 0x07
                if pcls == BPF_CLS.ALU64 and prev.dst_reg == 3:
                    if prev.opcode & 0xF0 == BPF_OP_ALU.MOV and (prev.opcode & 0x08):
                        r3_base = prev.src_reg
                    break
                if pcls == BPF_CLS.STX and prev.dst_reg == 3 and prev.src_reg == 10:
                    r3_base = 10
            if r3_base is not None and output_sz < 128:
                self._bypasses.append(BypassPattern(
                    f"potential KASLR leak at insn {i}: "
                    f"{_HELPER_NAMES.get(helper_id, 'helper#' + str(helper_id))} "
                    f"exports {output_sz} bytes from stack — uninitialized "
                    f"slots may contain kernel pointers (Heimdall finding)",
                    "high", i))

    def _detect_spinlock_boundary(self, n: int):
        lock_insns: list[int] = []; unlock_insns: list[int] = []
        for i, insn in enumerate(self._instructions):
            if insn.opcode != 0x85: continue
            if insn.imm == 51: lock_insns.append(i)
            elif insn.imm == 52: unlock_insns.append(i)
        if not lock_insns and not unlock_insns: return
        for lock_idx in lock_insns:
            found_unlock = False
            for j in range(lock_idx + 1, min(lock_idx + 32, n)):
                nxt = self._instructions[j]
                if nxt.opcode == 0x85 and nxt.imm == 52:
                    intervening_jumps = 0
                    for k in range(lock_idx + 1, j):
                        if self._instructions[k].opcode & 0x07 in (BPF_CLS.JMP, BPF_CLS.JMP32):
                            intervening_jumps += 1
                    if intervening_jumps >= 2:
                        self._bypasses.append(BypassPattern(
                            f"spinlock held across {intervening_jumps} branches "
                            f"({lock_idx}→{j}): verifier may lose lock state", "medium", lock_idx))
                    found_unlock = True; break
                if nxt.opcode == 0x95:
                    self._bypasses.append(BypassPattern(
                        f"BPF_EXIT at insn {j} while spinlock held from insn {lock_idx}",
                        "critical", lock_idx))
                    break
            if not found_unlock:
                self._bypasses.append(BypassPattern(
                    f"bpf_spin_lock at insn {lock_idx} has no paired unlock", "high", lock_idx))


def analyze_ebpf(prog: bytes) -> list[BypassPattern]:
    return EBPFAnalyzer().analyze(prog)


def disassemble_ebpf(prog: bytes) -> str:
    return EBPFAnalyzer().disassemble(prog)


def quick_scan_memfd_pattern(prog: bytes) -> list[BypassPattern]:
    insns = []
    n = len(prog) // 8
    for i in range(n):
        raw = prog[i * 8: i * 8 + 8]
        if len(raw) < 8: break
        opcode, dst_src, offset, imm = struct.unpack("<BBhi", raw)
        insns.append((i, opcode, dst_src & 0xF, imm))
    findings = []
    for idx, (i, op, dst, imm) in enumerate(insns):
        if op == 0x85 and imm == 2:
            for j in range(i + 1, min(i + 6, len(insns))):
                if insns[j][1] == 0x85 and insns[j][3] == 12:
                    findings.append(BypassPattern(
                        "memfd→tail_call chain: map_update→tail_call "
                        "may inject dynamic BPF subprogram from memfd",
                        "critical", i))
                    break
    return findings


def quick_scan_dma_buffer(prog: bytes) -> list[BypassPattern]:
    findings = []
    n = len(prog) // 8
    for i in range(n):
        raw = prog[i * 8: i * 8 + 8]
        if len(raw) < 8: break
        opcode, dst_src, offset, imm = struct.unpack("<BBhi", raw)
        if opcode == 0x85 and imm == 4:
            for j in range(i, min(i + 4, n)):
                raw2 = prog[j * 8: j * 8 + 8]
                if len(raw2) < 8: break
                op2 = raw2[0]
                if op2 == 0x85:
                    imm2 = struct.unpack_from("<i", raw2, 4)[0]
                    if imm2 in (25, 36, 38, 59):
                        findings.append(BypassPattern(
                            f"probe_read→output chain at {i}→{j}: "
                            "potential DMA buffer exfiltration to userspace",
                            "high", i))
                        break
    return findings
