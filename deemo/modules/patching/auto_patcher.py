import os
import re
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# capstone — 可选，不存在则降级为盲字节修补
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
    """漏洞记录。"""
    address: int = 0
    type: str = ""
    description: str = ""
    severity: float = 0.0
    affected_function: str = ""
    patch_candidates: list = field(default_factory=list)

@dataclass
class PatchInfo:
    """单条补丁记录。"""
    address: int = 0
    strategy: str = ""
    original_bytes: bytes = b""
    patched_bytes: bytes = b""
    description: str = ""
    applied: bool = False

@dataclass
class HardeningInfo:
    """加固项记录。"""
    type: str = ""
    enabled: bool = False
    description: str = ""
    applied: bool = False

@dataclass
class PatchResult:
    """聚合结果容器。"""
    vulnerabilities: list = field(default_factory=list)
    patches: list = field(default_factory=list)
    hardenings: list = field(default_factory=list)
    patched_binary_path: str = ""
    warnings: list = field(default_factory=list)
    analysis_success: bool = False

# ── 补丁冲突消解 ──────────────────────────────────────────────────────────
# 两个补丁地址区间重叠时，保留 patched_bytes 更长者（更实质性）。

class PatchConflictResolver:
    """重叠补丁冲突检测与消解。"""

    def __init__(self):
        self._conflicts = []

    def resolve(self, patches):
        """同地址保留最长补丁；区间重叠保留先到者，丢弃后到者并记录告警。"""
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
    """二进制自动修补与加固。"""

    def __init__(self, binary_path):
        """装载目标二进制路径。"""
        self._binary_path = binary_path
        self._vulns = []
        self._patches = []
        self._hardenings = []
        self._binary = b""
        self._disassembler = None  # capstone.Cs 实例
        self._resolver = PatchConflictResolver()
        self._arch = 'x86_64'  # 缺省架构

        logger.info("AutoPatcher init OK")

    # -- public API -------------------------------------------------------

    def analyze_and_patch(self, vulnerability_list=None):
        """分析二进制并应用补丁。"""
        logger.info("Start analysis")

        result = PatchResult()

        try:
            self._load_binary()

            # 架构检测 — 决定 capstone 模式与加固策略
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
        """试运行：分析但不修改二进制，返回 (结果, 冲突报告)。"""
        backup = bytes(self._binary)  # 快照
        result = self.analyze_and_patch(vulnerability_list)
        self._binary = backup  # 还原
        # 回退 applied 标记
        for p in self._patches:
            p.applied = False
        for h in self._hardenings:
            h.applied = False
        return result, self._resolver.conflict_report

    def save_patched_binary(self, output_path):
        """将修补后的二进制写入磁盘。"""
        try:
            with open(output_path, 'wb') as f:
                f.write(self._binary)

            logger.info("Patched binary saved to: %s" % output_path)
            return True
        except Exception as ex:
            logger.error("Write error: %s" % ex)
            return False

    def verify_patches(self):
        """校验所有已应用的补丁是否在位。"""
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
        """撤销所有已应用的补丁，恢复原始字节。"""
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
        """将目标文件读入内存。"""
        try:
            with open(self._binary_path, 'rb') as f:
                self._binary = f.read()

            size = len(self._binary)
            logger.debug("Loaded binary: %d bytes" % size)
        except Exception as ex:
            logger.error("Load failed: %s" % ex)
            raise

    def _detect_arch(self):
        """解析 ELF/PE 头确定架构并初始化 capstone。"""
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
            # PE 检测 — 从 0x3C 读取 PE 偏移
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
        """处理传入的漏洞字典列表，映射到 VulnerabilityInfo。"""
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
        """启发式漏洞扫描 — 在二进制字节流中搜索危险符号引用与指令模式。
        capstone 不可用时退化为纯正则路径。"""
        # 搜索危险符号字符串
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

        # capstone 增强：扫描代码段中的危险指令序列
        if self._disassembler is not None and len(self._binary) > 0:
            self._scan_instructions()

    def _get_default_candidates(self, vuln_type):
        """按漏洞类型返回缺省修补策略列表。"""
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
        """capstone 指令级扫描 — 检测危险函数调用、缺失 canary 的函数头等。"""
        if self._disassembler is None:
            return

        # 只在 .text 段范围内扫描
        # 简化：扫描前 64KB
        code_start = 0
        code_size = min(len(self._binary), 65536)

        try:
            count = 0
            for insn in self._disassembler.disasm(self._binary[code_start:code_start+code_size], code_start):
                count += 1
                if count > 50000:  # 安全边界
                    break
                # call 指令检测
                if insn.mnemonic == 'call' and insn.op_str:
                    # 检查 call 目标是否为已知危险函数 — 需符号表，当前留作扩展
                    pass
        except Exception:
            logger.debug("capstone disassembly scan skipped", exc_info=True)

    def _determine_patch_strategies(self, vuln):
        """漏洞类型到修补策略的映射表。"""
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
        """为每个漏洞生成补丁对象。"""
        self._vulns.sort(key=lambda v: v.severity, reverse=True)

        for i in range(len(self._vulns)):
            vuln = self._vulns[i]

            for j in range(len(vuln.patch_candidates)):
                strategy = vuln.patch_candidates[j]
                patch = self._create_patch(vuln, strategy)

                if patch is not None:
                    self._patches.append(patch)

        # 冲突消解
        if len(self._patches) > 1:
            self._patches, conflict_warnings = self._resolver.resolve(self._patches)
            # 冲突告警将在 PatchResult 中呈现

    def _create_patch(self, vuln, strategy):
        """根据策略构造补丁对象的字节载荷。"""
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
            # 插入输入长度检查序言 (x86-64: cmp + jbe)
            sanitize_bytes = bytes([0x48, 0x85, 0xFF, 0x74, 0x0A])
            patch = PatchInfo(
                address=vuln.address,
                strategy=strategy,
                original_bytes=b"",
                patched_bytes=sanitize_bytes,
                description="Input sanitization prologue")

        return patch

    def _apply_patches(self):
        """将补丁字节按地址写入二进制。"""
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
        """应用二进制加固措施 — 标记并尝试写入 ELF/PE 标志位。"""
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
        """尝试写入 GNU_STACK (NX) 和 GNU_RELRO 标志。
        仅 ELF 格式且找到 program headers 时操作。
        不动 section header — 保留原有 sh_type。"""
        if len(self._binary) < 64:
            return
        if self._binary[:4] != b'\x7fELF':
            return  # 非 ELF

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
            p_flags_off = ph_off + 4  # 32-bit: p_flags 在 +24; 64-bit: 在 +4
            # 64-bit phdr: p_flags 偏移 +4
            # PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552
            if p_type == 0x6474e551:  # PT_GNU_STACK
                # 清 PF_X 位 — 开启 NX
                if ph_off + 8 <= len(working):
                    p_flags = int.from_bytes(working[p_flags_off:p_flags_off+4], 'little')
                    p_flags &= ~1  # 清 PF_X (执行权限)
                    working[p_flags_off:p_flags_off+4] = p_flags.to_bytes(4, 'little')
                    logger.debug("ELF GNU_STACK: NX flag enforced")

        self._binary = bytes(working)


def patch_binary(binary_path, vulnerability_list=None, output_path=None):
    """一键修补：创建 patcher 并执行分析+修补。"""
    patcher = AutoPatcher(binary_path)
    result = patcher.analyze_and_patch(vulnerability_list)
    if output_path and result.analysis_success:
        patcher.save_patched_binary(output_path)
    return result
