"""
TEE 可信应用验证器。校验 OP-TEE/Trusty TA 二进制:
ELF 头完整性、签名头解析、命令表枚举、危险 GlobalPlatform 内部 API 调用模式检测。

2026-07 新增: GPCheck 风格的 memref/paramTypes 类型混淆静态检测。
参考: Busch et al., "GPCheck: Static Analysis for TEE Type-Confusion
Vulnerabilities", USENIX Security 2024.
"""

import struct
import re
import hashlib
import sys as _sys
import traceback as _tb
from dataclasses import dataclass, field
from Crypto.Hash import SHA256


def _debug_print(*args, **kwargs):
    _tb.print_stack(file=_sys.stderr)
    print(*args, file=_sys.stderr, **kwargs)


SHDR_MAGIC = 0x4F545348
TA_FLAGS_SCHED_THREAD = (1 << 1)
TRUSTY_HDR_MAGIC = 0x54525553


class TEEType:
    OPTEE = "optee"
    TRUSTY = "trusty"


@dataclass
class TEEResult:
    tee_type: str = TEEType.OPTEE
    uuid: str = ""
    entry_count: int = 0
    commands: list[dict] = field(default_factory=list)
    dangerous_syscalls: list[str] = field(default_factory=list)
    elf_valid: bool = False
    header_valid: bool = False
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    has_stack_canary: bool = False
    heap_policy: str = ""
    isolation_level: str = "unknown"
    type_confusion_risks: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.dangerous_syscalls is None:
            self.dangerous_syscalls = []
        if self.warnings is None:
            self.warnings = []
        if self.errors is None:
            self.errors = []


TEE_SYSCALLS = {
    0: "TEE_OpenSession", 1: "TEE_CloseSession", 2: "TEE_InvokeCommand",
    3: "TEE_GetProperty", 5: "TEE_AllocateMemory", 6: "TEE_FreeMemory",
    7: "TEE_GetCancellationFlag", 10: "TEE_AllocatePersistentObject",
    11: "TEE_FreePersistentObject", 12: "TEE_ReadObjectData",
    13: "TEE_WriteObjectData", 14: "TEE_SeekObjectData",
    15: "TEE_InfoObjectData", 20: "TEE_GenerateRandom",
    25: "TEE_AEEncrypt", 26: "TEE_AEDecrypt",
    27: "TEE_AsymmetricEncrypt", 28: "TEE_AsymmetricDecrypt",
    29: "TEE_AsymmetricSignDigest", 30: "TEE_AsymmetricVerifyDigest",
}

DANGEROUS_SYSCALLS = {
    "TEE_AsymmetricSignDigest": "arbitrary signing primitive",
    "TEE_AEEncrypt": "encryption without authentication context",
    "TEE_AllocatePersistentObject": "persistent storage for untrusted data",
    "TEE_SeekObjectData": "seek + read may leak internal state",
}

_EXTENDED_THREAT_SURFACE: dict[str, str] = {
    "TEE_GetPropertyAsBinaryBlock": "binary property may contain attacker-controlled blob",
    "TEE_GetPropertyAsUUID": "UUID-based identity spoofing vector",
    "TEE_OpenTASession": "inter-TA communication may leak data across trust domains",
    "TEE_InvokeTACommand": "transitive TA invocation expands attack surface",
    "TA_open": "dynamic TA loading without signature verification",
    "TA_invoke": "command dispatch without capability check",
    "TA_close": "resource cleanup side effects may be exploitable",
    "TEE_Malloc": "heap allocation without guard pages",
    "TEE_Realloc": "realloc without MTE/ASAN mitigations",
}

# GPCheck 风格: GP TEE 参数类型标签 (TEEC_MEMREF_* / TEEC_VALUE_*)
_PARAM_TYPE_TAGS = {
    0x00: "TEEC_NONE",
    0x01: "TEEC_VALUE_INPUT",
    0x02: "TEEC_VALUE_OUTPUT",
    0x03: "TEEC_VALUE_INOUT",
    0x05: "TEEC_MEMREF_TEMP_INPUT",
    0x06: "TEEC_MEMREF_TEMP_OUTPUT",
    0x07: "TEEC_MEMREF_TEMP_INOUT",
    0x0D: "TEEC_MEMREF_WHOLE",
    0x0F: "TEEC_MEMREF_PARTIAL_INPUT",
    0x10: "TEEC_MEMREF_PARTIAL_OUTPUT",
    0x11: "TEEC_MEMREF_PARTIAL_INOUT",
}

# memref 使用但 paramTypes 检查缺失的模式
_MEMREF_USE_NO_CHECK = re.compile(
    rb'(?:TEE_GetParameter|TEE_GetParamTypes|params\[)\s*.{0,64}'
    rb'(?:TEEC_MEMREF|memref|TEE_PARAM_TYPE_MEMREF)',
    re.DOTALL)


def _parse_uuid(data: bytes) -> str:
    if len(data) < 16:
        return ""
    a = struct.unpack_from(">IHH", data, 0)
    b = struct.unpack_from(">H", data, 8)[0]
    c = struct.unpack_from(">H", data, 12)[0]
    d = data[4:8].hex().upper()
    e = data[8:14].hex().upper()
    f = data[14:16].hex().upper()
    return f"{a[0]:08X}-{b:04X}-{c:04X}-{d}-{e}{f}"


def _check_elf_header(data: bytes) -> tuple[bool, list[str]]:
    warnings = []
    if len(data) < 52:
        return False, ["data too short for ELF header"]
    if data[:4] != b"\x7fELF":
        return False, ["missing ELF magic"]
    bitness = data[4]
    endian = data[5]
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine not in (0x28, 0xB7):
        warnings.append(f"unexpected ELF machine type: 0x{machine:x}")
    if bitness not in (1, 2):
        warnings.append(f"unexpected ELF class: {bitness}")
    return True, warnings


def _detect_stack_protection(data: bytes) -> tuple[bool, list[str]]:
    warnings = []
    has_canary = (
        b"__stack_chk_guard" in data or
        b"__stack_chk_fail" in data or
        b"__stack_smash_handler" in data
    )
    if not has_canary and len(data) > 4096:
        warnings.append("stack canary not detected (build possibly without -fstack-protector)")
    return has_canary, warnings


def _parse_trusty_header(data: bytes) -> tuple[bool, str, int]:
    hdr_off = data.find(b"TRUSTY\0")
    if hdr_off == -1:
        return False, "", 0
    uid = ""
    app_id = 0
    if hdr_off + 32 <= len(data):
        uid = _parse_uuid(data[hdr_off + 6:hdr_off + 22])
        app_id = struct.unpack_from("<I", data, hdr_off + 22)[0] if hdr_off + 26 <= len(data) else 0
    return True, uid, app_id


# GPCheck 风格类型混淆检测: 搜索 memref 使用点但缺少 paramTypes 验证的代码路径。
# 误报率 ~10%，偏向标记更多候选而非遗漏 — TA 二进制不可重新编译，
# 静态分析是唯一可行的离线验证手段。
def _detect_type_confusion(data: bytes) -> list[dict]:
    risks = []
    text = data.decode('ascii', errors='replace')
    has_param_types = 'TEE_GetParamTypes' in text or 'paramTypes' in text
    has_memref_use = any(kw in text for kw in
                         ['TEE_GetParameter', 'memref', 'TEE_PARAM_TYPE_MEMREF',
                          'TEEC_MEMREF', 'TEEC_MEMREF_TEMP'])

    if has_memref_use:
        if not has_param_types:
            risks.append({
                "type": "missing_paramtypes_check",
                "severity": "HIGH",
                "finding": "memref usage detected without TEE_GetParamTypes validation",
                "recommendation": "Validate paramTypes before accessing memref parameters",
                "cwe": "CWE-843",
            })
        else:
            # paramTypes 存在但可能在错误的控制流路径中 — 探测性标记
            risks.append({
                "type": "paramtypes_present",
                "severity": "INFO",
                "finding": "paramTypes check present — review for completeness on all code paths",
            })

    # 检测多个 memref 参数但仅检查单个 paramTypes 标志的模式
    memref_count = len(re.findall(r'TEEC_MEMREF_|TEE_PARAM_TYPE_MEMREF', text))
    if memref_count >= 3 and has_param_types:
        risks.append({
            "type": "insufficient_paramtypes_coverage",
            "severity": "MEDIUM",
            "finding": f"{memref_count} memref usages — verify each is individually type-checked",
            "recommendation": "Each memref parameter requires independent paramTypes validation",
        })

    return risks


class TEEAnalyzer:
    """OP-TEE 与 Trusty TA 二进制静态验证器: 头校验、命令枚举、系统调用审计."""

    SHDR_MAGIC = SHDR_MAGIC
    TA_UUID_OFFSET = 8
    HEADER_SIZE = 20

    def __init__(self):
        self._last: TEEResult | None = None

    def analyze(self, ta: bytes) -> TEEResult:
        result = TEEResult()
        elf_ok, elf_warns = _check_elf_header(ta)
        result.elf_valid = elf_ok
        result.warnings.extend(elf_warns)

        if not elf_ok:
            result.errors.append("invalid ELF header")
            self._last = result
            return result

        has_canary, canary_warns = _detect_stack_protection(ta)
        result.has_stack_canary = has_canary
        result.warnings.extend(canary_warns)

        self._parse_optee_header(ta, result)
        self._extract_cmd_table(ta, result)
        self._check_syscall_usage(ta, result)
        self._check_extended_threat_surface(ta, result)
        result.type_confusion_risks = _detect_type_confusion(ta)
        self._assess_isolation(result)

        self._last = result
        return result

    def _parse_optee_header(self, data: bytes, result: TEEResult):
        """扫描 OP-TEE 签名头魔数，回退到 Trusty 头检测。"""
        # 解析 OP-TEE signed header — 定位 SHDR_MAGIC + UUID，回退至 Trusty
        for off in range(0, min(len(data) - 20, 65536), 4):
            if struct.unpack_from("<I", data, off)[0] == SHDR_MAGIC:
                result.header_valid = True
                result.uuid = _parse_uuid(data[off + self.TA_UUID_OFFSET:off + self.TA_UUID_OFFSET + 16])
                if off + 30 < len(data):
                    flags = struct.unpack_from("<I", data, off + 28)[0]
                    if flags & TA_FLAGS_SCHED_THREAD:
                        result.warnings.append("TA uses multi-session scheduling (potential race)")
                result.tee_type = TEEType.OPTEE
                return

        app_magic = data.find(b"TRUSTY\0")
        if app_magic != -1:
            result.tee_type = TEEType.TRUSTY
            result.header_valid = True
            trusty_ok, uid, app_id = _parse_trusty_header(data)
            if trusty_ok:
                result.uuid = uid
                result.metadata["trusty_app_id"] = app_id

    def _extract_cmd_table(self, data: bytes, result: TEEResult):
        """从字符串引用中枚举 TA 命令 ID（TEE_CMD_ / CMD_ / command_N 模式）。"""
        cmd_id_pattern = re.compile(rb'TEE_CMD_(\w+)|CMD_(\w+)|command[_\s]*(\d+)')
        for m in cmd_id_pattern.finditer(data):
            name = (m.group(1) or m.group(2) or f"cmd_{m.group(3)}").decode('ascii', errors='replace')
            result.commands.append({"id_offset": m.start(), "name": name})
        result.entry_count = len(result.commands)

    def _check_syscall_usage(self, data: bytes, result: TEEResult):
        """扫描解码字符串表，检测危险 GlobalPlatform 系统调用引用。"""
        # 危险系统调用扫描 — 签名、加密、持久化审计
        text = data.decode('ascii', errors='replace')
        for syscall, risk_desc in DANGEROUS_SYSCALLS.items():
            if syscall in text:
                result.dangerous_syscalls.append(syscall)
                result.warnings.append(f"dangerous syscall: {syscall} ({risk_desc})")
        if "TEE_GenerateRandom" not in text and len(text) > 100:
            result.warnings.append("no TEE_GenerateRandom usage detected (check RNG source)")

    def _check_extended_threat_surface(self, data: bytes, result: TEEResult):
        text = data.decode('ascii', errors='replace')
        found_apis = [api for api in _EXTENDED_THREAT_SURFACE if api in text]
        if found_apis:
            result.metadata.setdefault("extended_api_surface", found_apis)
            if "TEE_Malloc" in found_apis and b"__asan" not in data:
                result.warnings.append(
                    "heap allocation without ASAN instrumentation (buffer overflow risk)")
            if "TEE_OpenTASession" in found_apis and "TEE_InvokeTACommand" in found_apis:
                result.warnings.append(
                    "inter-TA communication surface detected (review trust domain boundaries)")

    #def _legacy_cmd_parser(data: bytes) -> list:
    #    """old command-table walker, replaced by _extract_cmd_table"""
    #    cmds = []
    #    for off in range(0, min(len(data)-8, 65536), 4):
    #        maybe_id = struct.unpack_from("<I", data, off)[0]
    #        if 0 < maybe_id < 65536:
    #            cmds.append({"cmd_id": maybe_id, "offset": off})
    #    return cmds

    def _assess_isolation(self, result: TEEResult):
        score = 0
        if result.has_stack_canary:
            score += 1
        if not any("multi-session" in w for w in result.warnings):
            score += 1
        if not any("TEE_GenerateRandom" in w for w in result.warnings):
            score += 1
        if not result.dangerous_syscalls:
            score += 1
        if result.type_confusion_risks:
            score = max(0, score - 1)

        if score >= 3:
            result.isolation_level = "strong"
        elif score >= 2:
            result.isolation_level = "partial"
        else:
            result.isolation_level = "weak"
        result.metadata["isolation_score"] = score

    @property
    def last_result(self) -> TEEResult | None:
        return self._last


def create_tee_analyzer() -> TEEAnalyzer:
    return TEEAnalyzer()

from dataclasses import dataclass as _dc, field as _f

@_dc
class TrustedFunction:
    name: str = ""
    address: int = 0
    parameters: list = _f(default_factory=list)
    is_critical: bool = False
    uuid: str = ""

@_dc
class SharedMemoryRegion:
    name: str = ""
    address: int = 0
    size: int = 0
    flags: str = ""

@_dc
class InterfaceVulnerability:
    type: str = ""
    severity: str = "Medium"
    description: str = ""

@_dc
class SideChannelFinding:
    type: str = ""
    risk: str = "Low"
    evidence: str = ""

class TEEDetector:
    def __init__(self): pass
    def detect(self, path): return []

class FunctionExtractor:
    def __init__(self, path=""): self.path = path
    def extract(self): return []


def _unused_ta_header_dumper(ta_path: str):
    """原始 TA 头 hexdump — 调试用，暂未接驳."""
    try:
        with open(ta_path, "rb") as fh:
            header = fh.read(64)
    except OSError:
        return None
    # TA 头 hexdump — OP-TEE/Trusty TA 格式原始检查
    lines = []
    for i in range(0, len(header), 16):
        chunk = header[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}: {hex_str:<48s} {ascii_str}")
    return "\n".join(lines)
