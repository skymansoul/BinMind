# FMTPROV — 格式化字符串常量折叠与污点溯源验证器.
#
# 决策逻辑:
#   从 fmt 参数寄存器反向追踪定义链:
#     lea [rip+off] / mov [rip+off]              → CONST (rodata) → SAFE
#     mov reg, [rbp/rsp+off]                     → 解析栈槽存储源
#     非栈帧基址内存加载 (argv 等)                → TAINT → VULN
#     输入函数 (scanf/fgets/recv...) 输出/缓冲区  → TAINT → VULN
#     其它/未知                                   → UNKNOWN → SUSPICIOUS
#   终止: 跳数上限 12, 槽/寄存器 visited 集合防环.
#
#   本文件实现 FMTPROV 核心管线: 内联 objdump 解析器 → 格式函数签名 → 溯源器 → 管线.


import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# 内联 objdump 解析器

_FUNC_HEADER = re.compile(r"^([0-9a-fA-F]{8,16}) <(.*)>:$")
_INSN_LINE = re.compile(r"^\s+([0-9a-fA-F]{8,16}):\t")

_X86_64_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "ax", "bx", "cx", "dx", "si", "di", "r8w", "r9w",
    "al", "bl", "cl", "dl", "sil", "dil", "r8b", "r9b",
    "rip",
})


@dataclass
class Instruction:
    """单条指令."""
    addr: int
    mnem: str
    ops: List[str] = field(default_factory=list)
    raw: str = ""
    bytes: str = ""

    @property
    def is_call(self) -> bool:
        return self.mnem == "call"

    @property
    def is_jump(self) -> bool:
        return self.mnem.startswith("j")

    def op(self, i: int) -> str:
        return self.ops[i] if i < len(self.ops) else ""

    def __repr__(self) -> str:
        return f"{self.addr:#x}: {self.mnem} {', '.join(self.ops)}"


@dataclass
class Function:
    """一个函数的指令序列."""
    name: str
    start: int
    insns: List[Instruction] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.insns)


def _split_ops(ops_text: str) -> List[str]:
    """拆分逗号分隔的操作数, 忽略方括号内的逗号."""
    if not ops_text:
        return []
    parts: List[str] = []
    depth = 0
    cur = ""
    for ch in ops_text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _parse_insn(line: str) -> Optional[Instruction]:
    """解析单条指令行."""
    m = _INSN_LINE.match(line)
    if not m:
        return None
    addr = int(m.group(1), 16)
    rest = line[m.end():]
    fields = rest.split("\t")
    if len(fields) < 2:
        return None
    byte_field = fields[0].strip()
    text = fields[-1].strip()
    parts = text.split(None, 1)
    mnem = parts[0].lower()
    ops_text = parts[1] if len(parts) > 1 else ""
    if "#" in ops_text:
        ops_text = ops_text.split("#", 1)[0].strip()
    ops = _split_ops(ops_text)
    return Instruction(addr=addr, mnem=mnem, ops=ops, raw=line.strip(),
                       bytes=byte_field)


def parse_disasm(text: str) -> List[Function]:
    """解析整个反汇编文本, 返回函数列表."""
    functions: List[Function] = []
    cur: Optional[Function] = None
    for line in text.splitlines():
        stripped = line.rstrip()
        m = _FUNC_HEADER.match(stripped)
        if m:
            cur = Function(name=m.group(2), start=int(m.group(1), 16))
            functions.append(cur)
            continue
        if cur is None:
            continue
        insn = _parse_insn(stripped)
        if insn is not None:
            cur.insns.append(insn)
    return [f for f in functions if f.insns]


def callee_name(insn: Instruction) -> str:
    """提取 call 指令的目标名: `<malloc>` -> malloc; `rax` -> rax."""
    if not insn.is_call:
        return ""
    tgt = insn.op(0).strip()
    m = re.search(r"<([^>]*)>", tgt)
    if m:
        name = m.group(1)
    else:
        name = tgt.lstrip("*").strip()
    return name.split("@")[0].split(".")[0]


def _plain_reg_token(op: str) -> str:
    """操作数若为纯寄存器返回其名 (忽略类型前缀), 否则 ''."""
    parts = op.split()
    for p in parts:
        if p in _X86_64_REGS:
            return p
    return ""


# 格式函数签名

FORMAT_FUNCS: Dict[str, Dict] = {
    "printf": {"idx": 0, "win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "fprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "sprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "snprintf": {"idx": 2, "win64": ["r8", "r8d"], "sysv": ["rdx", "edx"]},
    "dprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "syslog": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vprintf": {"idx": 0, "win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "vfprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vsprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vsnprintf": {"idx": 2, "win64": ["r8", "r8d"], "sysv": ["rdx", "edx"]},
    "err": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "errx": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "warn": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "warnx": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
}

INPUT_FUNCS = frozenset({
    "scanf", "gets", "fgets", "read", "fread", "recv", "recvfrom",
    "getline", "getenv", "getc", "getchar", "fgetc", "fscanf",
    "__isoc99_scanf", "__isoc99_fscanf",
})


def find_format(callee: str):
    """匹配最长键 (__mingw_snprintf → snprintf, 而非 printf)."""
    best = None
    best_key = ""
    for key, sig in FORMAT_FUNCS.items():
        if key in callee and len(key) > len(best_key):
            best_key = key
            best = sig
    return (best_key, best) if best else (None, None)


# 溯源器

CONST = "CONST"
TAINT = "TAINT"
UNKNOWN = "UNKNOWN"

_WINDOW = 40
_MAX_HOPS = 12

_SLOT_RE = re.compile(r"\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]")
_CALLER_SAVED = frozenset({
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
})
_FRAME = frozenset({"rbp", "rsp", "rip"})


def _slot_key(m) -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}"


def _dst_reg(insn: Instruction) -> str:
    op0 = insn.op(0)
    if not op0:
        return ""
    return _plain_reg_token(op0)


class FmtTaintWalker:
    """格式参数溯源器."""

    def __init__(self):
        self._max_hops = _MAX_HOPS
        self._window = _WINDOW
        self._stats = {"const": 0, "taint": 0, "unknown": 0}

    def resolve(self, insns: List[Instruction], call_idx: int,
                cand_regs: List[str]) -> Tuple[str, str]:
        """解析 fmt 参数分类, 返回 (classification, evidence)."""
        for reg in cand_regs:
            cls, ev = self._walk_reg(insns, call_idx - 1, reg,
                                     self._max_hops, set())
            if cls != UNKNOWN:
                self._stats[cls.lower()] += 1
                return cls, ev
        self._stats["unknown"] += 1
        return UNKNOWN, "fmt 未解析为常量或输入"

    def _walk_reg(self, insns: List[Instruction], start: int, reg: str,
                  hops: int, seen: Set[str]) -> Tuple[str, str]:
        if hops <= 0 or start < 0:
            return UNKNOWN, f"hop-limit@{reg}"
        # 终止性由 hops 递减保证; 槽↔寄存器交替链中同名寄存器可合法复现

        for j in range(start, max(-1, start - _WINDOW), -1):
            insn = insns[j]
            if insn.mnem == "call":
                callee = callee_name(insn)
                if reg == "rax" and any(i in callee for i in INPUT_FUNCS):
                    return TAINT, f"输入函数 {callee} 返回值"
                if reg in _CALLER_SAVED:
                    return UNKNOWN, f"call-clobbered@{reg}"
                continue
            if insn.mnem == "ret":
                break
            dst = _dst_reg(insn)
            if not dst or dst != reg:
                continue
            mnem = insn.mnem
            ops = insn.ops

            if mnem == "lea" and len(ops) >= 2:
                if "[rip" in ops[1]:
                    return CONST, "lea [rip+off] → rodata"
                m = _SLOT_RE.search(ops[1])
                if m:
                    return self._walk_slot(insns, j, _slot_key(m), hops - 1,
                                           seen)
                if "[" in ops[1]:
                    return TAINT, f"lea 非栈帧地址 {ops[1]} (argv/外部)"
                return UNKNOWN, f"lea-{ops[1]}"
            if mnem == "mov" and len(ops) >= 2:
                src = ops[1]
                if "[rip" in src:
                    return CONST, "mov reg,[rip+off] → rodata"
                m = _SLOT_RE.search(src)
                if m:
                    return self._walk_slot(insns, j, _slot_key(m), hops - 1,
                                           seen)
                if "[" in src:
                    return TAINT, f"非栈帧内存加载 {src} (argv/外部)"
                sreg = _plain_reg_token(src)
                if sreg:
                    return self._walk_reg(insns, j - 1, sreg, hops - 1, seen)
                return UNKNOWN, "mov reg, imm"
            return UNKNOWN, f"def-{mnem}"

        return UNKNOWN, "no-def"

    def _walk_slot(self, insns: List[Instruction], start: int, slot: str,
                   hops: int, seen: Set[str]) -> Tuple[str, str]:
        if hops <= 0 or start < 0:
            return UNKNOWN, f"slot-hop-limit@{slot}"

        for j in range(start, max(-1, start - _WINDOW), -1):
            insn = insns[j]
            if insn.mnem == "mov" and len(insn.ops) >= 2:
                m = _SLOT_RE.search(insn.op(0))
                if m and _slot_key(m) == slot:
                    src = insn.op(1)
                    if "[rip" in src:
                        return CONST, f"mov [{slot}], [rip+off]"
                    sreg = _plain_reg_token(src)
                    if sreg:
                        cls, ev = self._walk_reg(insns, j - 1, sreg,
                                                 hops - 1, seen)
                        if cls == CONST:
                            return CONST, f"槽 {slot} ← {ev}"
                        return cls, f"槽 {slot} ← {ev}"
                    return UNKNOWN, f"槽 {slot} 存立即数"
            if insn.mnem == "call":
                callee = callee_name(insn)
                if any(i in callee for i in INPUT_FUNCS):
                    return TAINT, f"输入函数 {callee} 写入缓冲区 {slot}"
        return UNKNOWN, f"槽 {slot} 无可见存储源"

    def stats(self) -> dict:
        return dict(self._stats)


# 管线

SAFE = "SAFE"
VULN = "VULN"
SUSPICIOUS = "SUSPICIOUS"

_LIB_FUNCS = frozenset({
    "malloc", "calloc", "realloc", "free", "_ZdlPv", "_ZdaPv",
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "dprintf", "puts", "putchar",
    "scanf", "gets", "fgets", "fread", "read", "recv", "getenv",
    "strlen", "strchr", "strstr", "strcmp", "strncmp", "atoi",
    "fflush", "fwrite", "fclose", "fopen", "stdin", "stdout",
    "__main", "mainCRTStartup", "WinMainCRTStartup",
    "__tmainCRTStartup", "_setargv", "__mingw_raise_matherr",
    "__report_error", "_amsg_exit", "_fpreset", "_initterm",
    "__getmainargs", "__acrt_iob_func", "__set_app_type",
    "safe_flush", "check_managed_app", "duplicate_ppstrings",
    "mark_section_writable", "restore_modified_sections",
    "do_pseudo_reloc", "__write_memory", "__do_global_dtors",
    "__do_global_ctors", "register_frame_ctor", "atexit",
    "__gcc_register_frame", "__gcc_deregister_frame",
    "_pei386_runtime_relocator", "__mingwthr_run_key_dtors",
    "__mingw_TLScallback", "__tlregdtor", "__dyn_tls_dtor",
    "_initterm_e", "_cexit", "_crt_atexit", "__iob_func",
    "abort", "exit", "_exit",
})

_LIB_SUBSTR = ("mingw", "pseudo_reloc", "section_writable",
               "relocator", "matherr", "_tls", "exception_handler",
               "_initterm", "app_type", "iob_func", "register_frame",
               "frame_info", "ValidateImage", "FindPESection",
               "GetPEImage", "IsNonwritable", "enum_import",
               "chkstk", "getmainargs", "invalid_parameter",
               "configthreadlocale", "specific_handler")


def _is_user_func(name: str) -> bool:
    if name == "main":
        return True
    if name in _LIB_FUNCS or name.startswith("_"):
        return False
    if any(sub in name for sub in _LIB_SUBSTR):
        return False
    return True


@dataclass
class FmtFinding:
    verdict: str = SUSPICIOUS
    rule: str = ""
    func: str = ""
    addr: int = 0
    fmt_func: str = ""
    classification: str = UNKNOWN
    pct_n: bool = False
    evidence: List[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        return self.verdict in (VULN, SUSPICIOUS)


@dataclass
class FmtReport:
    binary_path: str = ""
    n_functions: int = 0
    n_calls: int = 0
    n_safe: int = 0
    n_vuln: int = 0
    n_suspicious: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_ms: float = 0.0
    findings: List[FmtFinding] = field(default_factory=list)
    per_class: Dict[str, int] = field(default_factory=dict)

    @property
    def detected(self) -> bool:
        return self.n_vuln + self.n_suspicious > 0


class FmtProvenancePipeline:
    """格式化字符串验证管线."""

    def __init__(self):
        self._walker = FmtTaintWalker()

    def analyze(self, text: str, binary_path: str = "") -> FmtReport:
        t0 = time.time()
        rep = FmtReport(binary_path=binary_path)
        functions = parse_disasm(text)
        rep.n_functions = len(functions)

        for fn in functions:
            if not _is_user_func(fn.name):
                continue
            insns = fn.insns
            for i, insn in enumerate(insns):
                if not insn.is_call:
                    continue
                callee = callee_name(insn)
                key, sig = find_format(callee)
                if sig is None:
                    continue
                rep.n_calls += 1
                # ABI 候选: win64 优先, 失败回退 sysv
                cands = sig["win64"] + sig["sysv"]
                cls, ev = self._walker.resolve(insns, i, cands)
                rep.per_class[cls] = rep.per_class.get(cls, 0) + 1
                pct_n = "stderr" not in insn.raw and "syslog" not in insn.raw
                if cls == CONST:
                    v, rule = SAFE, "C_const_fmt"
                    rep.n_safe += 1
                elif cls == TAINT:
                    v, rule = VULN, "T_tainted_fmt"
                    rep.n_vuln += 1
                else:
                    v, rule = SUSPICIOUS, "U_unknown_fmt"
                    rep.n_suspicious += 1
                rep.findings.append(FmtFinding(
                    verdict=v, rule=rule, func=fn.name, addr=insn.addr,
                    fmt_func=callee, classification=cls, pct_n=pct_n,
                    evidence=[ev]))

        total = rep.n_safe + rep.n_vuln + rep.n_suspicious
        rep.fp_reduction_pct = round(rep.n_safe / max(1, total) * 100, 1)
        rep.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return rep

    def analyze_binary(self, binary_path: str) -> FmtReport:
        text = _disassemble(binary_path)
        if not text:
            return FmtReport(binary_path=binary_path)
        return self.analyze(text, binary_path)

    def stats(self) -> dict:
        return {"walker": self._walker.stats()}


def _disassemble(binary_path: str) -> str:
    for tool in ("objdump", "llvm-objdump"):
        try:
            proc = subprocess.run(
                [tool, "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


__all__ = [
    "Instruction", "Function", "parse_disasm", "callee_name",
    "FORMAT_FUNCS", "INPUT_FUNCS", "find_format",
    "FmtTaintWalker", "CONST", "TAINT", "UNKNOWN",
    "FmtFinding", "FmtReport", "FmtProvenancePipeline",
    "SAFE", "VULN", "SUSPICIOUS",
]
