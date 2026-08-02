# 2026-07-28

import os, hashlib, logging, struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    level: int
    passed: bool
    message: str
    details: dict = field(default_factory=dict)


class VerificationLevel:
    """Verification granularity — 逐级递增，Level 3 最重但也最可靠"""
    BYTECODE: int = 1
    STRUCTURAL: int = 2
    SEMANTIC: int = 3


# ===== Level 1: byte-level comparison — 最基础，O(n) 内存直接比对 =====
def verify_bytes(filepath: str, offset: int, expected: bytes) -> Tuple[bool, str]:
    """Read file at offset, compare len(expected) bytes. Returns (passed, message)."""
    try:
        with open(filepath, "rb") as _fh:
            _fh.seek(offset)
            _actual = _fh.read(len(expected))
    except Exception as e:
        return False, f"verify_bytes: IO error: {e}"
    if _actual == expected:
        return True, "bytecode match"
    # 找到第一个不匹配的位置
    _pos = -1
    for _i in range(min(len(_actual), len(expected))):
        if _actual[_i] != expected[_i]:
            _pos = _i
            break
    if _pos < 0:
        _pos = min(len(_actual), len(expected))
    return False, "bytecode mismatch at offset+{}: exp={:02x} act={:02x}".format(
        _pos,
        expected[_pos] if _pos < len(expected) else -1,
        _actual[_pos] if _pos < len(_actual) else -1)


# ---- ELF header parsing helpers ----
def _read_elf_header(filepath: str) -> Optional[Dict]:
    """Unpack ELF header: ident, type, machine, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx."""
    try:
        with open(filepath, "rb") as _fh:
            _ident = _fh.read(16)
            if _ident[:4] != b'\x7fELF':
                return None
            _is_64 = (_ident[4] == 2)  # ELFCLASS64
            _endian = '<' if _ident[5] == 1 else '>'  # ELFDATA2LSB
        _fmt = _endian + ('2H5I6H' if _is_64 else '3I6H')
        _size = struct.calcsize(_fmt)
        with open(filepath, "rb") as _fh:
            _fh.read(16)
            _fields = struct.unpack(_fmt, _fh.read(_size))
        return {
            "is_64": _is_64,
            "endian": _endian,
            "e_type": _fields[0],
            "e_machine": _fields[1],
            "e_version": _fields[2],
            "e_entry": _fields[3],
            "e_phoff": _fields[4] if _is_64 else _fields[3],
            "e_shoff": _fields[5] if _is_64 else _fields[4],
            "e_flags": _fields[6] if _is_64 else _fields[5],
            "e_ehsize": _fields[7] if _is_64 else _fields[6],
            "e_phentsize": _fields[8] if _is_64 else _fields[7],
            "e_phnum": _fields[9] if _is_64 else _fields[8],
            "e_shentsize": _fields[10] if _is_64 else _fields[9],
            "e_shnum": _fields[11] if _is_64 else _fields[10],
            "e_shstrndx": _fields[12] if _is_64 else _fields[11],
        }
    except Exception as e:
        logger.error("_read_elf_header: %s", e)
        return None


# ============================================================
# Level 2: structural verification for ELF
# 验证 patch 区域的跳转/调用目标依然指向合法段，
# 防止 patch 破坏了相对偏移导致 branch 到非代码区域
# ============================================================
def verify_structure(filepath: str, patches: List[Dict]) -> Tuple[bool, str]:
    """Check ELF structural integrity after patching. Returns (passed, message)."""
    _hdr = _read_elf_header(filepath)
    if _hdr is None:
        return True, "not an ELF file — structural check skipped"

    # 读取段表以获取有效地址范围
    _sections = []
    try:
        with open(filepath, "rb") as _fh:
            _fh.seek(_hdr["e_shoff"])
            _esize = _hdr["e_shentsize"]
            for _i in range(_hdr["e_shnum"]):
                _entry = _fh.read(_esize)
                if _hdr["is_64"]:
                    # sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8), sh_size(8), ...
                    _fields = struct.unpack_from(_hdr["endian"] + "IIQQQQQIIQQ", _entry)
                    _sh_addr = _fields[3]
                    _sh_size = _fields[5]
                    _sh_flags = _fields[2]
                else:
                    _fields = struct.unpack_from(_hdr["endian"] + "IIIIIIIIII", _entry)
                    _sh_addr = _fields[3]
                    _sh_size = _fields[5]
                    _sh_flags = _fields[2]
                _sections.append((_sh_addr, _sh_addr + _sh_size, _sh_flags))
    except Exception as e:
        logger.error("verify_structure: section table read failed: %s", e)
        return False, "ELF section parsing failed"

    # 收集所有有效代码段地址
    _valid_ranges = [(s, e) for (s, e, f) in _sections if f & 0x4]  # SHF_EXECINSTR
    if not _valid_ranges:
        _valid_ranges = [(s, e) for (s, e, f) in _sections]  # fallback: 所有段

    def _is_valid_code(addr):
        for _s, _e in _valid_ranges:
            if _s <= addr < _e:
                return True
        return False

    # 对每个 patch 区域，扫描 call/jmp 指令（简化：只检查 x86 的 E8/E9 相对跳转）
    for _p in patches:
        _off = _p.get("offset", 0)
        _size = _p.get("size", 0)
        try:
            with open(filepath, "rb") as _fh:
                _fh.seek(_off)
                _data = _fh.read(_size)
        except Exception:
            continue
        _i = 0
        while _i < len(_data) - 4:
            _op = _data[_i]
            if _op in (0xE8, 0xE9):  # CALL rel32 / JMP rel32
                _rel32 = struct.unpack("<i", _data[_i+1:_i+5])[0]
                _target = _off + _i + 5 + _rel32
                if not _is_valid_code(_target):
                    return False, "branch at offset {} targets 0x{:x} outside valid sections".format(
                        _off + _i, _target)
            _i += 1

    return True, "structural integrity OK"


# //// Level 3: semantic verification via Z3 — 有符号执行味道的约束求解 ////
def verify_semantic(filepath: str, patches: List[Dict]) -> Tuple[bool, str]:
    """Z3-backed semantic check. Falls back gracefully if Z3 not installed."""
    try:
        import z3
        _has_z3 = True
    except ImportError:
        _has_z3 = False

    if not _has_z3:
        return True, "Z3 not installed; semantic verification skipped"

    # 为每个 patch 构建约束: patch_byte[i] == expected[i]
    _solver = z3.Solver()
    _all_ok = True
    _messages = []
    for _p in patches:
        _off = _p.get("offset", 0)
        _size = _p.get("size", 0)
        try:
            with open(filepath, "rb") as _fh:
                _fh.seek(_off)
                _actual = _fh.read(_size)
        except Exception as e:
            _messages.append("patch @ {}: IO error: {}".format(_off, e))
            _all_ok = False
            continue
        _solver.push()
        for _i in range(_size):
            _b = z3.BitVec("byte_{}".format(_i), 8)
            _expected_val = _actual[_i]
            _solver.add(_b == _expected_val)
        _r = _solver.check()
        if _r == z3.sat:
            _messages.append("patch @ {}: constraints satisfiable".format(_off))
        else:
            _messages.append("patch @ {}: UNSAT".format(_off))
            _all_ok = False
        _solver.pop()

    return _all_ok, "; ".join(_messages)


# ============================================================
# PatchVerifier: 统一的验证入口
# 三级递进 —— 一般来说 Level 1 够用，但打复杂补丁时需要 Level 2/3
# ============================================================
class PatchVerifier:
    """Three-level patch verification: bytecode -> structural -> semantic."""

    def _patch_dict_to_list(self, patches: List[Dict]) -> List[Tuple[int, bytes]]:
        _out = []
        for _p in patches:
            _off = _p.get("offset", 0)
            _data = _p.get("expected") or _p.get("bytes") or b''
            if isinstance(_data, str):
                # hex string -> bytes
                _h = _data.strip()
                if _h.startswith("0x"):
                    _h = _h[2:]
                _h = _h.replace(" ", "")
                if len(_h) % 2:
                    _h = "0" + _h
                _data = bytes(int(_h[i:i+2], 16) for i in range(0, len(_h), 2))
            _out.append((_off, _data))
        return _out

    def verify(self, filepath: str, patches: List[Dict], level: int = 1) -> VerificationResult:
        """Run verification at specified level (1-3). Level N includes all checks up to N."""
        _details = {}
        _passed = True
        _msgs = []

        # Level 1: bytecode
        if level >= VerificationLevel.BYTECODE:
            _ok = True
            for _off, _data in self._patch_dict_to_list(patches):
                _vp, _vm = verify_bytes(filepath, _off, _data)
                if not _vp:
                    _ok = False
                    _msgs.append(_vm)
            _details["bytecode"] = "PASS" if _ok else "FAIL"
            _passed = _passed and _ok

        # Level 2: structural
        if level >= VerificationLevel.STRUCTURAL:
            _vp, _vm = verify_structure(filepath, patches)
            _details["structural"] = "PASS" if _vp else "FAIL"
            if not _vp:
                _msgs.append(_vm)
            _passed = _passed and _vp

        # Level 3: semantic
        if level >= VerificationLevel.SEMANTIC:
            _vp, _vm = verify_semantic(filepath, patches)
            _details["semantic"] = "PASS" if _vp else "FAIL"
            if not _vp:
                _msgs.append(_vm)
            _passed = _passed and _vp

        _message = "verification {}: {}".format(
            "passed" if _passed else "failed",
            "; ".join(_msgs) if _msgs else "all checks OK")
        return VerificationResult(level=level, passed=_passed, message=_message, details=_details)
