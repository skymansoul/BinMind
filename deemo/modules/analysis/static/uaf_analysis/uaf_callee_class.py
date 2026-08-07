"""callee 危害分类 — pass_as_arg 误报抑制的基础.

误报根源: binary_uaf_scanner._check_pass_freed_arg 对 freed 指针
被传给任意函数一律报告, 但 printf("%p", p) 等仅按值传递指针
(不解引用) — 不是 UAF. 本模块按"是否解引用参数"分类 callee:
  DANGEROUS — 解引用参数 (strlen/memcpy/strcmp/free/puts...)
  HARMLESS  — 纯值传递 (printf 家族按格式串判定: %s/%c/%n 解引用,
              仅 %p/%x/%d/%u 为值打印)
  UNKNOWN   — 保守视为危险
printf 家族需解析 .rodata 中的格式串内容 (objdump -s).
"""

import re
import subprocess
from enum import Enum, auto
from typing import Dict, List, Optional, Set

_DEREF_FUNCS = {
    "strlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "memcpy", "memmove", "memcmp", "memset", "strcpy", "strncpy",
    "strcat", "strncat", "strchr", "strstr", "strdup", "strndup",
    "strtol", "strtoul", "strtod", "atoi", "atol",
    "free", "realloc", "_ZdlPv", "_ZdaPv", "g_free", "g_realloc",
    "fwrite", "fread", "read", "recv", "fgets", "gets", "getline",
    "puts", "fputs", "write", "send", "sendto",
    "strncmp", "strnlen", "strncat", "memchr",
    "printf", "fprintf", "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
    "__mingw_snprintf", "sprintf_s", "strcpy_s", "strcat_s",
    "memcpy_s", "strncpy_s",
}

# printf 家族: 格式串需进一步解析 (%.*s 等也解引用)
_PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf", "vsprintf",
    "vsnprintf", "__mingw_printf", "__mingw_fprintf",
    "__mingw_sprintf", "__mingw_snprintf",
}

_HARMLESS_FUNCS = {
    "puts",  # 已在上方? 不 — puts 解引用, 保留在危险集
}


class CalleeClass(Enum):
    DANGEROUS = auto()
    HARMLESS = auto()
    UNKNOWN = auto()


class CalleeClassifier:
    """callee 危害分类器 — 带 printf 格式串解析."""

    def __init__(self, binary_path: Optional[str] = None):
        self._binary_path = binary_path
        self._rodata: Optional[Dict[int, bytes]] = None

    def classify(self, callee: str,
                 fmt_reg: Optional[str] = None,
                 call_idx: Optional[int] = None,
                 insns: Optional[list] = None) -> CalleeClass:
        """分类 callee. printf 家族按格式串内容细分."""
        name = (callee or "").split("@")[0].split("(")[0].strip()
        if not name:
            return CalleeClass.UNKNOWN
        if name in _PRINTF_FAMILY:
            if fmt_reg is None or call_idx is None or insns is None:
                return CalleeClass.DANGEROUS
            fmt_addr = self._resolve_fmt_addr(insns, call_idx, fmt_reg)
            if fmt_addr is None:
                return CalleeClass.DANGEROUS
            content = self._string_at(fmt_addr)
            if content is None:
                return CalleeClass.DANGEROUS
            # %s %c %n %a %f? — %f 按 double 值传参不解引用
            if re.search(r"%[-+ 0-9.*]*[scn]", content):
                return CalleeClass.DANGEROUS
            return CalleeClass.HARMLESS
        if name in _DEREF_FUNCS:
            return CalleeClass.DANGEROUS
        # 未知函数保守危险
        return CalleeClass.DANGEROUS

    # 格式串地址解析 (call 前 lea/mov 到 fmt_reg)

    def _resolve_fmt_addr(self, insns: list, call_idx: int,
                          fmt_reg: str) -> Optional[int]:
        for j in range(call_idx - 1, max(0, call_idx - 12), -1):
            ins = insns[j]
            if len(ins.operands) < 2:
                continue
            dst = self._norm(ins.operands[0])
            if dst != fmt_reg:
                continue
            src = ins.operands[1].strip()
            imm = self._try_int(src)
            if imm is not None:
                return imm
            base, _, _, off = self._parse_mem(src)
            if base == "rip":
                return ins.address + self._insn_len(ins) + off
            if base:
                return self._resolve_fmt_addr(insns, j, base)
        return None

    # .rodata 字符串内容

    def _string_at(self, addr: int) -> Optional[str]:
        data = self._load_rodata()
        if not data:
            return None
        chars = []
        for k in range(0, 256):
            b = data.get(addr + k)
            if b is None:
                break
            if b == 0:
                break
            chars.append(chr(b))
        return "".join(chars) if chars else None

    def _load_rodata(self) -> Optional[Dict[int, bytes]]:
        if self._rodata is not None:
            return self._rodata
        if not self._binary_path:
            self._rodata = {}
            return self._rodata
        try:
            r = subprocess.run(
                ["objdump", "-s", "-j", ".rdata", self._binary_path],
                capture_output=True, text=True, errors="ignore",
                timeout=20)
            if not r.stdout.strip():
                r = subprocess.run(
                    ["objdump", "-s", "-j", ".rodata", self._binary_path],
                    capture_output=True, text=True, errors="ignore",
                    timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._rodata = {}
            return self._rodata
        data: Dict[int, bytes] = {}
        for line in r.stdout.split("\n"):
            m = re.match(r"^\s*([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s+)+)", line)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16)
            except ValueError:
                continue
            blob = bytearray()
            for hg in m.group(2).split():
                try:
                    blob.extend(bytes.fromhex(hg))
                except ValueError:
                    continue
            for k, b in enumerate(blob):
                data[addr + k] = b
        self._rodata = data
        return data

    # 工具

    @staticmethod
    def _norm(op: str) -> str:
        op = op.strip().lower()
        aliases = {"rcx": "rcx", "rdi": "rdi", "r8": "r8", "rdx": "rdx",
                   "ecx": "rcx", "edi": "rdi", "r8d": "r8"}
        return aliases.get(op, op)

    @staticmethod
    def _try_int(s: str) -> Optional[int]:
        s = s.strip()
        try:
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            return int(s)
        except ValueError:
            return None

    @staticmethod
    def _parse_mem(op: str):
        m = re.match(r".*\[(.+)\]", op)
        if not m:
            return None, None, 1, 0
        inner = m.group(1)
        off = 0
        base = None
        for part in inner.replace("-", "+-").split("+"):
            part = part.strip()
            v = CalleeClassifier._try_int(part)
            if v is not None:
                off += v
            elif part in ("rip", "rbp", "rsp", "rax", "rcx", "rdx"):
                base = part
        return base, None, 1, off

    @staticmethod
    def _insn_len(ins) -> int:
        m = re.match(r"^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)",
                     ins.raw_line)
        if m:
            return len(m.group(1).split())
        return 0


# smoke test
def _check():
    c = CalleeClassifier()
    assert c.classify("strlen") == CalleeClass.DANGEROUS
    assert c.classify("free") == CalleeClass.DANGEROUS
    assert c.classify("some_unknown_fn") == CalleeClass.DANGEROUS
    print("[OK] uaf_callee_class: strlen/free/unknown → DANGEROUS")


if __name__ == "__main__":
    _check()
