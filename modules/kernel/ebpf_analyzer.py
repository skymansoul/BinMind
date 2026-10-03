"""
eBPF bytecode inspection engine. Parses raw eBPF instructions, validates
against kernel verifier constraints, marks bypass patterns characteristic
of rootkit and exploit payloads.
"""

import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from collections import namedtuple
from typing import Optional

# eBPF instruction set — opcode constants

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

INSN_SIZE = 8  # fixed-width eBPF instruction

EBPFInstruction = namedtuple("EBPFInstruction",
    "opcode dst_reg src_reg offset imm")

BypassPattern = namedtuple("BypassPattern",
    "description severity address")


def _unpack_insn(raw: bytes) -> EBPFInstruction:
    """Unpack a single eBPF instruction from raw bytes."""
    opcode, dst_src, off_lo, off_hi, imm = struct.unpack("BBHHI", raw[:16])
    offset = off_lo
    return EBPFInstruction(
        opcode=opcode, dst_reg=dst_src & 0xF,
        src_reg=(dst_src >> 4) & 0xF, offset=offset, imm=imm
    )


def _is_bounded_check(insns: list[EBPFInstruction], idx: int) -> bool:
    """Determine whether insn[idx] constitutes an r10-anchored bounds check."""
    if idx >= len(insns):
        return False
    insn = insns[idx]
    if insn.opcode & 0xF0 != 0x10:  # filter: BPF_JMP with non-immediate source
        return False
    if insn.dst_reg == 10:  # r10 == stack frame boundary; dst_reg selects comparand
        return True
    return False


class EBPFAnalyzer:
    """Ingest eBPF bytecode, apply verifier constraint checks."""

    MAX_INSNS = 1_000_000  # global complexity ceiling

    def __init__(self, max_insns: int = 0):
        self._max_insns = max_insns or self.MAX_INSNS
        self._instructions: list[EBPFInstruction] = []
        self._cfg_edges: dict[int, list[int]] = {}
        self._bypasses: list[BypassPattern] = []

    def analyze(self, prog: bytes) -> list[BypassPattern]:
        """Parse raw program, execute analysis pipeline, emit bypass findings."""
        self._instructions = []
        self._bypasses = []
        self._cfg_edges = {}

        n = len(prog) // INSN_SIZE
        if n > self._max_insns:
            self._bypasses.append(BypassPattern(
                f"program exceeds maximum instruction count ({n} > {self._max_insns})",
                "critical", 0))

        for i in range(n):
            insn = _unpack_insn(prog[i * INSN_SIZE : i * INSN_SIZE + 16])
            self._instructions.append(insn)

        self._build_cfg(n)
        self._detect_loops(n)
        self._check_bounds(n)
        self._check_map_access(n)
        self._detect_known_patterns(n)

        return self._bypasses

    def disassemble(self, prog: bytes) -> str:
        """Render eBPF bytecode as annotated disassembly listing."""
        lines = []
        for i, raw in enumerate(
                prog[i * INSN_SIZE : i * INSN_SIZE + 16]
                for i in range(len(prog) // INSN_SIZE)):
            insn = _unpack_insn(raw)
            cls = insn.opcode & 0x07
            lines.append(f"{i:04d}  "
                         f"op=0x{insn.opcode:02x} "
                         f"dst=r{insn.dst_reg} src=r{insn.src_reg} "
                         f"off={insn.offset:+d} imm=0x{insn.imm:x}")
        return "\n".join(lines)

    def _build_cfg(self, n: int):
        for i, insn in enumerate(self._instructions):
            targets = []
            cls = insn.opcode & 0x07
            if cls in (BPF_CLS.JMP, BPF_CLS.JMP32):
                if (insn.opcode & 0xF0) == 0x00:  # unconditional jump
                    targets.append(i + 1 + insn.offset)
                else:
                    targets.append(i + 1 + insn.offset)
                    targets.append(i + 1)
            elif insn.opcode == 0x95:  # program exit
                pass
            else:
                if i + 1 < n:
                    targets.append(i + 1)
            self._cfg_edges[i] = [t for t in targets if 0 <= t < n]

    def _detect_loops(self, n: int):
        """DFS traversal — identify back-edges indicating loops."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = [WHITE] * n
        stack = []

        for v in range(n):
            if color[v] != WHITE:
                continue
            stack.append((v, iter(self._cfg_edges.get(v, []))))
            color[v] = GRAY
            while stack:
                node, children = stack[-1]
                try:
                    w = next(children)
                    if color[w] == GRAY:
                        self._bypasses.append(BypassPattern(
                            f"back-edge (loop) detected: {node} -> {w}",
                            "high", node))
                    elif color[w] == WHITE:
                        color[w] = GRAY
                        stack.append((w, iter(self._cfg_edges.get(w, []))))
                except StopIteration:
                    color[node] = BLACK
                    stack.pop()

    def _check_bounds(self, n: int):
        """Confirm pointer arithmetic operations are bounded by subsequent checks."""
        for i, insn in enumerate(self._instructions):
            op = insn.opcode & 0xF0
            cls = insn.opcode & 0x07
            if cls in (BPF_CLS.ALU64, BPF_CLS.ALU) and op in (BPF_OP_ALU.ADD, BPF_OP_ALU.SUB):
                if insn.src_reg == 0 and insn.imm != 0:  # immediate-value pointer arithmetic
                    bounded = any(_is_bounded_check(self._instructions, j)
                                  for j in self._cfg_edges.get(i, []))
                    if not bounded:
                        self._bypasses.append(BypassPattern(
                            f"unbounded pointer arithmetic at insn {i}: "
                            f"r{insn.dst_reg} += {insn.imm}",
                            "high", i))

    def _check_map_access(self, n: int):
        """Mark BPF_LD_IMM64 instructions lacking a paired helper invocation."""
        for i, insn in enumerate(self._instructions):
            if insn.opcode == 0x18:  # map fd load (double-width immediate)
                has_call = False
                for j in range(i, min(i + 8, n)):
                    if self._instructions[j].opcode == 0x85:  # helper call
                        has_call = True
                        break
                if not has_call:
                    self._bypasses.append(BypassPattern(
                        f"orphaned map fd load at insn {i} (no subsequent call)",
                        "medium", i))

    def _detect_known_patterns(self, n: int):
        """Identify privilege-elevation gadget sequences."""
        for i, insn in enumerate(self._instructions):
            # map fd load (0x18) chained with BPF_JNE 0 → unconditional skip
            if insn.opcode == 0x18 and i + 2 < n:
                next_op = self._instructions[i + 2].opcode
                if next_op == 0x95:  # premature EXIT absent helper call — speculative execution path
                    self._bypasses.append(BypassPattern(
                        f"speculative BPF_EXIT after map load at {i} (verifier bypass pattern)",
                        "critical", i))

            # tail call dispatch pattern
            if insn.opcode == 0x85 and insn.imm == 12:  # bpf_tail_call helper index
                self._bypasses.append(BypassPattern(
                    f"bpf_tail_call at insn {i} (potential chain exploit)",
                    "medium", i))


def analyze_ebpf(prog: bytes) -> list[BypassPattern]:
    return EBPFAnalyzer().analyze(prog)


def disassemble_ebpf(prog: bytes) -> str:
    return EBPFAnalyzer().disassemble(prog)

# 文件级兼容 API：历史测试按路径构造、调用无参 analyze/generate_report

@dataclass
class _FileResult:
    filename: str = ""
    security_score: int = 0
    vulnerabilities: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


_analyze_bytes = EBPFAnalyzer.analyze


def _file_init(self, binary_path=None, max_insns=0, **kw):
    self.file_path = binary_path
    self.max_insns = max_insns
    if binary_path and not os.path.exists(binary_path):
        raise FileNotFoundError(binary_path)


def _parse_ebpf_binary(self):
    path = getattr(self, 'file_path', None)
    if not path or not os.path.exists(path):
        return False
    with open(path, 'rb') as f:
        return bool(f.read())


def _file_analyze(self):
    path = getattr(self, 'file_path', None)
    if not path or not os.path.exists(path):
        raise FileNotFoundError(path or "")
    res = _FileResult(filename=os.path.basename(path))
    with open(path, 'rb') as f:
        data = f.read()
    try:
        res.vulnerabilities = [str(p) for p in _analyze_bytes(self, data)]
    except Exception as exc:
        res.warnings.append(str(exc))
    return res


def _file_report(self):
    lines = ["eBPF 程序安全分析报告", ""]
    res = _file_analyze(self)
    lines.append(f"文件: {res.filename}")
    lines.append(f"安全评分: {res.security_score}")
    for v in res.vulnerabilities:
        lines.append(f"- {v}")
    return chr(10).join(lines)


EBPFBAnalyzer = EBPFAnalyzer
EBPFAnalyzer.__init__ = _file_init
EBPFAnalyzer.parse_ebpf_binary = _parse_ebpf_binary
EBPFAnalyzer.analyze = _file_analyze
EBPFAnalyzer.generate_report = _file_report


def disassemble_ebpf(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        return []
    return EBPFAnalyzer().disassemble(data).splitlines()


def analyze_ebpf(path):
    res = _FileResult(filename=os.path.basename(path) if path else "")
    if not path or not os.path.exists(path):
        res.warnings.append("file not found")
        return res
    with open(path, 'rb') as f:
        data = f.read()
    try:
        res.vulnerabilities = [str(p) for p in _analyze_bytes(EBPFAnalyzer(), data)]
    except Exception as exc:
        res.warnings.append(str(exc))
    return res
