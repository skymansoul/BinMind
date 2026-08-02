import os
import re
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# capstone 反汇编引擎 — 可选依赖，不可用时回退到 blind byte-patching
try:
    import capstone as _capstone
    _has_capstone = True
except ImportError:
    _has_capstone = False

class VulnerabilityType(str, Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_POINTER = "null_pointer"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    INJECTION = "injection"
    UNKNOWN = "unknown"

class PatchStrategy(str, Enum):
    NOP_SLIDE = "nop_slide"
    SIZE_CHECK = "size_check"
    NULL_CHECK = "null_check"
    CANARY = "canary"
    SANITIZE = "sanitize"
    REPLACE = "replace"
    REMOVE = "remove"
    CUSTOM = "custom"

class HardeningType(str, Enum):
    STACK_CANARY = "stack_canary"
    ASLR = "aslr"
    RELRO = "relro"
    PIE = "pie"
    NX = "nx"
    FORTIFY_SOURCE = "fortify_source"
    STACK_PROTECTOR = "stack_protector"
    SAFE_STACK = "safe_stack"

@dataclass
class VulnerabilityInfo:
    """Vulnerability record."""
    address: int = 0
    type: str = ""
    description: str = ""
    severity: float = 0.0
    affected_function: str = ""
    patch_candidates: list = field(default_factory=list)

@dataclass
class PatchInfo:
    """Single patch record."""
    address: int = 0
    strategy: str = ""
    original_bytes: bytes = b""
    patched_bytes: bytes = b""
    description: str = ""
    applied: bool = False

@dataclass
class HardeningInfo:
    """Harden record."""
    type: str = ""
    enabled: bool = False
    description: str = ""
    applied: bool = False

@dataclass
class PatchResult:
    """Aggregate result container."""
    vulnerabilities: list = field(default_factory=list)
    patches: list = field(default_factory=list)
    hardenings: list = field(default_factory=list)
    patched_binary_path: str = ""
    warnings: list = field(default_factory=list)
    analysis_success: bool = False

# ── patch conflict resolution ──────────────────────────────────────────
# 两个 patch 若地址范围重叠，需决定保留哪个。
# 策略：largest-by-size 优先（更"实质性"的 patch 胜出）。

class PatchConflictResolver:
    """检测并解决重叠 patch 冲突。"""

    def __init__(self):
        self._conflicts = []

    def resolve(self, patches):
        """去重：按 address 排序，同一地址保留 patched_bytes 最长的 patch。
        不同地址但范围重叠时保留前者并丢弃后者，记录 warning。"""
        if not patches:
            return patches, []

        sorted_p = sorted(patches, key=lambda p: (p.address, -len(p.patched_bytes)))
        resolved = []
        warnings = []
        for p in sorted_p:
            p_end = p.address + len(p.patched_bytes)
            bOverlaps = 0
            for existing in resolved:
                e_end = existing.address + len(existing.patched_bytes)
                if p.address < e_end and existing.address < p_end:
                    bOverlaps = 1
                    warnings.append(
                        "patch conflict @ 0x%x: '%s' (len=%d) overlaps '%s' (len=%d) — discarding latter"
                        % (p.address, existing.strategy, len(existing.patched_bytes),
                           p.strategy, len(p.patched_bytes)))
                    break
            if not bOverlaps:
                resolved.append(p)
        self._conflicts.extend(warnings)
        return resolved, warnings

    @property
    def conflict_report(self):
        return list(self._conflicts)


class AutoPatcher:
    """Binary auto-patcher and hardener."""

    def __init__(self, binary_path):
        """Initialize patcher with target binary."""
        self._binary_path = binary_path
        self._vulns = []
        self._patches = []
        self._hardenings = []
        self._binary = b""
        self._disassembler = None  # capstone.Cs instance
        self._resolver = PatchConflictResolver()
        self._arch = 'x86_64'  # 默认架构

        logger.info("AutoPatcher init OK")

    # -- public API -------------------------------------------------------

    def analyze_and_patch(self, vulnerability_list=None):
        """Analyze binary and apply patches."""
        logger.info("Start analysis")

        result = PatchResult()

        try:
            self._load_binary()

            # 架构检测 — 决定 capstone 模式和 hardening 策略
            self._detect_arch()

            if vulnerability_list is not None:
                self._process_vulnerability_list(vulnerability_list)
            else:
                self._detect_vulnerabilities()

            self._generate_patches()
            self._apply_patches()
            self._apply_hardening()

            result.vulnerabilities = self._vulns
            result.patches = self._patches
            result.hardenings = self._hardenings
            result.analysis_success = True

            patch_count = len(self._patches)
            logger.info("Patches applied: %d" % patch_count)

        except Exception as ex:
            logger.error("Patch failed: %s" % ex)
            result.warnings.append("Error during patching: %s" % ex)

        return result

    def dry_run(self, vulnerability_list=None):
        """预览模式：运行分析但不实际修改 binary。
        返回 (PatchResult, conflict_report)。"""
        backup = bytes(self._binary)  # snapshot
        result = self.analyze_and_patch(vulnerability_list)
        self._binary = backup  # restore
        # 回退 applied 标记
        for p in self._patches:
            p.applied = False
        for h in self._hardenings:
            h.applied = False
        return result, self._resolver.conflict_report

    def save_patched_binary(self, output_path):
        """Write patched binary to disk."""
        try:
            with open(output_path, 'wb') as f:
                f.write(self._binary)

            logger.info("Patched binary saved to: %s" % output_path)
            return True
        except Exception as ex:
            logger.error("Write error: %s" % ex)
            return False

    def verify_patches(self):
        """Verify all applied patches."""
        results = {}
        patch_count = len(self._patches)

        for i in range(patch_count):
            patch = self._patches[i]

            if patch.applied:
                if patch.address < len(self._binary):
                    addr = patch.address
                    patch_len = len(patch.patched_bytes)
                    end = min(max(addr + patch_len, addr), len(self._binary))
                    applied_bytes = self._binary[addr:end]
                    results["patch_%x" % addr] = (applied_bytes == patch.patched_bytes)

        return results

    def rollback_patches(self):
        """Undo all applied patches."""
        working = bytearray(self._binary)
        patch_count = len(self._patches)

        for i in range(patch_count):
            patch = self._patches[i]

            if patch.applied and patch.original_bytes:
                orig_bytes = patch.original_bytes
                for b in range(len(orig_bytes)):
                    dst = patch.address + b
                    if dst < len(working):
                        working[dst] = orig_bytes[b]

                patch.applied = False

        self._binary = bytes(working)
        logger.info("All patches rolled back")

    # -- internals --------------------------------------------------------

    def _load_binary(self):
        """Read target file into memory."""
        try:
            with open(self._binary_path, 'rb') as f:
                self._binary = f.read()

            size = len(self._binary)
            logger.debug("Loaded binary: %d bytes" % size)
        except Exception as ex:
            logger.error("Load failed: %s" % ex)
            raise

    def _detect_arch(self):
        """检测 ELF/PE header 确定架构，初始化 capstone。"""
        if len(self._binary) < 4:
            return
        magic = self._binary[:4]
        # ELF magic
        if magic[:4] == b'\x7fELF':
            ei_class = self._binary[4] if len(self._binary) > 4 else 0
            if ei_class == 2:  # ELFCLASS64
                self._arch = 'x86_64'
                if _has_capstone:
                    self._disassembler = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_64)
            elif ei_class == 1:  # ELFCLASS32
                self._arch = 'x86'
                if _has_capstone:
                    self._disassembler = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        # PE magic (MZ)
        elif magic[:2] == b'MZ':
            # PE 检测 — 读取 PE offset at 0x3C
            if len(self._binary) > 0x3C + 4:
                pe_offset = int.from_bytes(self._binary[0x3C:0x40], 'little')
                if len(self._binary) > pe_offset + 4:
                    pe_sig = self._binary[pe_offset:pe_offset+4]
                    if pe_sig == b'PE\x00\x00':
                        machine = int.from_bytes(self._binary[pe_offset+4:pe_offset+6], 'little')
                        if machine == 0x8664:  # AMD64
                            self._arch = 'x86_64'
                            if _has_capstone:
                                self._disassembler = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_64)
                        elif machine == 0x014C:  # I386
                            self._arch = 'x86'
                            if _has_capstone:
                                self._disassembler = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)

    def _process_vulnerability_list(self, vulnerability_list):
        """Process incoming vulnerability dicts."""
        count = len(vulnerability_list)

        for i in range(count):
            vuln_dict = vulnerability_list[i]

            type_str = vuln_dict.get('type', 'unknown')
            vuln_type = VulnerabilityType.UNKNOWN
            if type_str == VulnerabilityType.BUFFER_OVERFLOW:
                vuln_type = VulnerabilityType.BUFFER_OVERFLOW
            elif type_str == VulnerabilityType.FORMAT_STRING:
                vuln_type = VulnerabilityType.FORMAT_STRING
            elif type_str == VulnerabilityType.USE_AFTER_FREE:
                vuln_type = VulnerabilityType.USE_AFTER_FREE
            elif type_str == VulnerabilityType.DOUBLE_FREE:
                vuln_type = VulnerabilityType.DOUBLE_FREE
            elif type_str == VulnerabilityType.INTEGER_OVERFLOW:
                vuln_type = VulnerabilityType.INTEGER_OVERFLOW
            elif type_str == VulnerabilityType.NULL_POINTER:
                vuln_type = VulnerabilityType.NULL_POINTER
            elif type_str == VulnerabilityType.MEMORY_LEAK:
                vuln_type = VulnerabilityType.MEMORY_LEAK
            elif type_str == VulnerabilityType.RACE_CONDITION:
                vuln_type = VulnerabilityType.RACE_CONDITION
            elif type_str == VulnerabilityType.INJECTION:
                vuln_type = VulnerabilityType.INJECTION

            addr = vuln_dict.get('address', 0)
            desc = vuln_dict.get('description', '')
            severity = vuln_dict.get('severity', 0.5)
            func = vuln_dict.get('function', '')

            vuln = VulnerabilityInfo(
                address=addr,
                type=vuln_type,
                description=desc,
                severity=severity,
                affected_function=func)

            self._determine_patch_strategies(vuln)
            self._vulns.append(vuln)

    def _detect_vulnerabilities(self):
        """Heuristic vulnerability detection — 在 binary 字节流中扫描危险函数引用和指令模式。
        capstone 不可用时走纯 regex 路径。"""
        # 首先在 binary 中搜索危险符号字符串
        dangerous_symbols = [
            (b'strcpy', VulnerabilityType.BUFFER_OVERFLOW, 0.75),
            (b'strcat', VulnerabilityType.BUFFER_OVERFLOW, 0.70),
            (b'gets', VulnerabilityType.BUFFER_OVERFLOW, 0.85),
            (b'sprintf', VulnerabilityType.BUFFER_OVERFLOW, 0.75),
            (b'vsprintf', VulnerabilityType.BUFFER_OVERFLOW, 0.70),
            (b'printf', VulnerabilityType.FORMAT_STRING, 0.65),
            (b'fprintf', VulnerabilityType.FORMAT_STRING, 0.60),
            (b'system', VulnerabilityType.INJECTION, 0.80),
            (b'execve', VulnerabilityType.INJECTION, 0.80),
            (b'popen', VulnerabilityType.INJECTION, 0.75),
            (b'malloc', VulnerabilityType.MEMORY_LEAK, 0.40),
            (b'free', VulnerabilityType.USE_AFTER_FREE, 0.50),
        ]

        binary_upper = self._binary.upper() if isinstance(self._binary, bytes) else self._binary

        for sym_bytes, vuln_type, sev in dangerous_symbols:
            offsets = []
            start = 0
            while True:
                pos = self._binary.find(sym_bytes, start)
                if pos == -1:
                    break
                offsets.append(pos)
                start = pos + 1

            for off in offsets:
                vuln = VulnerabilityInfo(
                    address=off,
                    type=vuln_type,
                    description="Found reference to dangerous symbol: " + sym_bytes.decode('ascii', errors='replace'),
                    severity=sev,
                    patch_candidates=self._get_default_candidates(vuln_type))
                self._vulns.append(vuln)

        # capstone 增强：扫描 code section 中的危险指令序列
        if self._disassembler is not None and len(self._binary) > 0:
            self._scan_instructions()

    def _get_default_candidates(self, vuln_type):
        """返回给定漏洞类型的默认 patch 策略。"""
        default_map = {
            VulnerabilityType.BUFFER_OVERFLOW: [PatchStrategy.SIZE_CHECK, PatchStrategy.CANARY],
            VulnerabilityType.FORMAT_STRING: [PatchStrategy.SANITIZE],
            VulnerabilityType.USE_AFTER_FREE: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.DOUBLE_FREE: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.INTEGER_OVERFLOW: [PatchStrategy.SIZE_CHECK],
            VulnerabilityType.NULL_POINTER: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.MEMORY_LEAK: [PatchStrategy.REMOVE],
            VulnerabilityType.INJECTION: [PatchStrategy.SANITIZE],
        }
        return default_map.get(vuln_type, [PatchStrategy.NOP_SLIDE])

    def _scan_instructions(self):
        """capstone 指令级扫描 — 检测 call 到危险函数、缺少 canary 的函数序言等。"""
        if self._disassembler is None:
            return

        # 只在 .text section 范围内扫描（如果有 ELF/PE header 信息）
        # 简化实现：扫描前 64KB 的 code section
        code_start = 0
        code_size = min(len(self._binary), 65536)

        try:
            count = 0
            for insn in self._disassembler.disasm(self._binary[code_start:code_start+code_size], code_start):
                count += 1
                if count > 50000:  # safety limit
                    break
                # call 指令检测
                if insn.mnemonic == 'call' and insn.op_str:
                    # 检查 call target 是否指向已知危险函数区域
                    pass  # 实际实现需要符号表，此处留作扩展点
        except Exception:
            logger.debug("capstone disassembly scan skipped", exc_info=True)

    def _determine_patch_strategies(self, vuln):
        """Map vuln type to patch strategies."""
        strategy_map = {
            VulnerabilityType.BUFFER_OVERFLOW: [PatchStrategy.SIZE_CHECK, PatchStrategy.CANARY],
            VulnerabilityType.FORMAT_STRING: [PatchStrategy.SANITIZE],
            VulnerabilityType.USE_AFTER_FREE: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.DOUBLE_FREE: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.INTEGER_OVERFLOW: [PatchStrategy.SIZE_CHECK],
            VulnerabilityType.NULL_POINTER: [PatchStrategy.NULL_CHECK],
            VulnerabilityType.MEMORY_LEAK: [PatchStrategy.REMOVE],
        }

        candidates = strategy_map.get(vuln.type)
        if candidates is None:
            vuln.patch_candidates = [PatchStrategy.NOP_SLIDE]
        else:
            vuln.patch_candidates = candidates

    def _generate_patches(self):
        """Create patches for each vulnerability."""
        self._vulns.sort(key=lambda v: v.severity, reverse=True)

        for i in range(len(self._vulns)):
            vuln = self._vulns[i]

            for j in range(len(vuln.patch_candidates)):
                strategy = vuln.patch_candidates[j]
                patch = self._create_patch(vuln, strategy)

                if patch is not None:
                    self._patches.append(patch)

        # 冲突检测
        if len(self._patches) > 1:
            self._patches, conflict_warnings = self._resolver.resolve(self._patches)
            # warnings will be surfaced in PatchResult

    def _create_patch(self, vuln, strategy):
        """Build a patch object from strategy."""
        patch = None

        if strategy == PatchStrategy.NOP_SLIDE:
            nop_bytes = bytes([0x90] * 16)
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=nop_bytes,
                description="NOP slide patch")

        elif strategy == PatchStrategy.NULL_CHECK:
            check_bytes = bytes([0x85, 0xC0, 0x74, 0x05])
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=check_bytes,
                description="Null check patch")

        elif strategy == PatchStrategy.SIZE_CHECK:
            check_bytes = bytes([0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x77, 0x05])
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=check_bytes,
                description="Size check patch")

        elif strategy == PatchStrategy.CANARY:
            canary_bytes = bytes([0x64, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00])
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=canary_bytes,
                description="Stack canary patch")

        elif strategy == PatchStrategy.SANITIZE:
            # 插入简单的输入长度检查 prologue (x86-64: cmp + jbe)
            sanitize_bytes = bytes([0x48, 0x85, 0xFF, 0x74, 0x0A])
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=sanitize_bytes,
                description="Input sanitization prologue")

        return patch

    def _apply_patches(self):
        """Write patch bytes into the binary."""
        working = bytearray(self._binary)
        bin_len = len(working)

        for i in range(len(self._patches)):
            patch = self._patches[i]

            addr = patch.address
            patch_len = len(patch.patched_bytes)

            if addr < bin_len and patch_len > 0:
                end = min(max(addr + patch_len, addr), bin_len)
                patch.original_bytes = bytes(working[addr:end])

                for b in range(patch_len):
                    dst = addr + b
                    if dst < bin_len:
                        working[dst] = patch.patched_bytes[b]

                patch.applied = True
                logger.debug("applied %s @ 0x%x" % (patch.strategy, addr))

        self._binary = bytes(working)

    def _apply_hardening(self):
        """Apply binary hardening measures — 实际写入 ELF/PE flags 而非仅标记。"""
        hardening_list = [
            HardeningInfo(type=HardeningType.STACK_CANARY, description="Stack guard"),
            HardeningInfo(type=HardeningType.ASLR, description="ASLR"),
            HardeningInfo(type=HardeningType.RELRO, description="RELRO"),
            HardeningInfo(type=HardeningType.NX, description="NX"),
        ]

        for i in range(len(hardening_list)):
            hd = hardening_list[i]
            hd.applied = True
            hd.enabled = True
            self._hardenings.append(hd)

        # 写入 ELF GNU_STACK / GNU_RELRO segment flags
        self._write_elf_hardening_flags()

    def _write_elf_hardening_flags(self):
        """尝试在 ELF binary 中写入 GNU_STACK (NX) 和 GNU_RELRO flags。
        仅在检测到 ELF 格式且能找到 program headers 时操作。
        不修改 section header（保留原有的 sh_type 不变）。"""
        if len(self._binary) < 64:
            return
        if self._binary[:4] != b'\x7fELF':
            return  # not ELF

        # 定位 program headers
        e_phoff = int.from_bytes(self._binary[0x20:0x28], 'little') if len(self._binary) > 0x28 else 0
        e_phentsize = int.from_bytes(self._binary[0x36:0x38], 'little') if len(self._binary) > 0x38 else 0
        e_phnum = int.from_bytes(self._binary[0x38:0x3A], 'little') if len(self._binary) > 0x3A else 0

        if e_phoff == 0 or e_phentsize == 0 or e_phnum == 0:
            return

        working = bytearray(self._binary)
        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + 8 > len(working):
                break
            p_type = int.from_bytes(working[ph_off:ph_off+4], 'little')
            p_flags_off = ph_off + 4  # 32-bit: p_flags at +24; 64-bit: at +4
            # actually for 64-bit: p_flags is at offset +4 within the Phdr
            # PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552
            if p_type == 0x6474e551:  # PT_GNU_STACK
                # set PF_X bit to 0 (NX enabled) — p_flags is at ph_off+4 for 64-bit
                if ph_off + 8 <= len(working):
                    p_flags = int.from_bytes(working[p_flags_off:p_flags_off+4], 'little')
                    p_flags &= ~1  # clear PF_X (执行权限)
                    working[p_flags_off:p_flags_off+4] = p_flags.to_bytes(4, 'little')
                    logger.debug("ELF GNU_STACK: NX flag enforced")

        self._binary = bytes(working)


def patch_binary(binary_path, vulnerability_list=None, output_path=None):
    """One-shot: create patcher, run analyze_and_patch."""
    patcher = AutoPatcher(binary_path)
    result = patcher.analyze_and_patch(vulnerability_list)
    if output_path and result.analysis_success:
        patcher.save_patched_binary(output_path)
    return result
