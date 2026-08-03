"""
Intel SGX / ARM TrustZone 安全飞地分析。
验证飞地度量值与已知基线，扫描侧信道基元（RDTSC、缓存时序、缺页预言），
检查密封/解封密钥策略正确性。

2026-07 新增: 推测执行漏洞（Foreshadow/LVI/Spectre）+ CET 指令 + MDS/VERW。
参考: Intel SDM Vol.3 Ch.42 (SGX) + 公开 PoC 汇编模式。
      Slyp (arXiv 2605.05000) ReAct 风格二进制发现模式。
"""

import hashlib, struct, re, pathlib, time as _time, sys as _sys, traceback as _tb
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


def _debug_print(*args, **kwargs):
    _tb.print_stack(file=_sys.stderr)
    print(*args, file=_sys.stderr, **kwargs)


class EnclaveType(str, Enum):
    SGX = "sgx"; TRUSTZONE = "trustzone"; SEV = "sev"

class RiskLevel(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"; INFO = "info"

class EnclaveIssueType(str, Enum):
    CAP_LEAK = "cap_leak"; BOUNDS_VIOLATION = "bounds_violation"
    MEASUREMENT_MISMATCH = "measurement_mismatch"; SIDE_CHANNEL = "side_channel"
    UNSAFE_SEALING = "unsafe_sealing"; ORACLE_EXPOSURE = "oracle_exposure"
    BAD_RANDOMNESS = "bad_randomness"; ECALL_ATTACK = "ecall_attack"
    OCALL_HIJACK = "ocall_hijack"; SPECULATIVE_EXEC = "speculative_exec"
    CET_VIOLATION = "cet_violation"; ATTEST_WEAK = "attest_weak"
    LVI_EXPOSURE = "lvi_exposure"


@dataclass
class EnclaveFinding:
    issue_type: EnclaveIssueType; risk: RiskLevel
    location: str; description: str; evidence: bytes = b""


@dataclass
class EnclaveAnalysisResult:
    enclave_type: EnclaveType; mrenclave: str = ""; mrsigner: str = ""
    is_debug: bool = False; is_production: bool = False
    findings: list[EnclaveFinding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


_WEAK_MRSIGNERS: set[str] = {
    "83d719e77e5a6a8e2d7d0b8d3c6c3e6a4d5f7a8b9c3e2a1f4b5c6d7e8f9a0b1c2",
    "0000000000000000000000000000000000000000000000000000000000000000",
}

_INTERESTING_OPCODES = {b"\x0f\x01\xd7", b"\x0f\x01\xd6", b"\x0f\x30", b"\x0f\x31", b"\x0f\xa2", b"\x48\x89"}
# 推测执行扫描 — Spectre/LVI/Foreshadow 检查

_SPECULATIVE_PATTERNS: list[tuple[bytes, EnclaveIssueType, str]] = [
    (re.compile(rb'\x0f\x01\xd7.{0,32}(?:\x48\x8b|\x8b|\x0f\xb6)').pattern,
     EnclaveIssueType.SPECULATIVE_EXEC, "Foreshadow/L1TF: load after ENCLU without cache flush"),
    (re.compile(rb'\x0f\x01\xd7.{0,64}(?:\x89|\x48\x89)\x0f\x01\xd7').pattern,
     EnclaveIssueType.LVI_EXPOSURE, "LVI exposure: store-then-ENCLU within 64 bytes"),
    (re.compile(rb'\xff[\xe0-\xe7].{0,20}(?!\x0f\xae\xe8)').pattern,
     EnclaveIssueType.SPECULATIVE_EXEC, "Indirect branch without LFENCE — Spectre v2 surface"),
]

_CET_OPCODES = {b'\xf3\x0f\x01\xea': 'WRSSD', b'\xf3\x0f\x01\xeb': 'WRSSQ',
                b'\xf3\x0f\x01\xec': 'RSTORSSP', b'\xf3\x0f\x1e\xfa': 'ENDBR64',
                b'\xf3\x0f\x1e\xfb': 'ENDBR32'}
_VERW_OPCODE = b'\x0f\x00'

# Slyp 风格 ECALL stub 检测: 识别 ECALL 入口的指令序列模式
_ECALL_STUB_PATTERNS = [
    (re.compile(rb'\x0f\x01\xd7.{0,16}\x48\x85\xc0.{0,8}\x75'), "sgx_ecall_error_check"),
    (re.compile(rb'\x48\x8d..\x00\x00\x00.{0,8}\x0f\x01\xd7'), "sgx_ocall_prepare"),
]


class EnclaveAnalyzer:
    MRENCLAVE_LEN = 32; MRSIGNER_LEN = 32

    def __init__(self):
        self._last: Optional[EnclaveAnalysisResult] = None

    def analyze(self, enclave: bytes, enclave_type=EnclaveType.SGX) -> EnclaveAnalysisResult:
        result = EnclaveAnalysisResult(enclave_type=enclave_type); self._last = result
        if enclave_type == EnclaveType.SGX:
            self._parse_sgx_metadata(enclave, result); self._check_measurement(result)
            self._detect_side_channels_sgx(enclave, result); self._check_sealing_patterns(enclave, result)
            self._enumerate_ecalls_ocalls(enclave, result)
            self._detect_speculative_patterns(enclave, result); self._check_cet_presence(enclave, result)
            self._detect_ecall_stubs(enclave, result)
        elif enclave_type == EnclaveType.TRUSTZONE:
            self._check_tz_el_escalation(enclave, result); self._detect_smc_surface(enclave, result)
        elif enclave_type == EnclaveType.SEV:
            self._check_sev_attestation(enclave, result)
        return result

    def _parse_sgx_metadata(self, data, result):
        sig_offset = data.find(b"\x06\x00\x00\x00\xe1\x00\x00\x00")
        if sig_offset >= 0 and sig_offset + 1808 <= len(data):
            sig = data[sig_offset:sig_offset + 1808]
            result.mrenclave = sig[960:960 + 32].hex(); result.mrsigner = sig[128:128 + 32].hex()
            if len(sig) >= 1008:
                attrs = struct.unpack_from("<QQ", sig, 992)
                result.is_debug = bool(attrs[0] & 2); result.is_production = not result.is_debug
            result.metadata["sigstruct_offset"] = sig_offset
        self._find_dispatch_tables(data, result)
        result.metadata["binary_sha256"] = hashlib.sha256(data).hexdigest()

    def _find_dispatch_tables(self, data, result):
        ecall_prologue = re.compile(rb"\x48\x8b\x05....\x48\x8b\x0d...." rb".{0,32}" rb"\xff\xe0")
        for m in ecall_prologue.finditer(data):
            result.metadata.setdefault("ecall_candidates", []).append(hex(m.start()))

    def _check_measurement(self, result):
        if result.mrsigner.lower() in _WEAK_MRSIGNERS:
            result.findings.append(EnclaveFinding(EnclaveIssueType.MEASUREMENT_MISMATCH,
                RiskLevel.CRITICAL, "MRSIGNER", "Enclave signed with known weak/zero signing key",
                bytes.fromhex(result.mrsigner)))

    def _detect_side_channels_sgx(self, data, result):
        ts = sum(1 for i in range(len(data) - 1) if data[i:i + 2] == b"\x0f\x31")
      # RDTSC / WRMSR 扫描 — 时序侧信道与 MSR 操纵检测
        for i in range(len(data) - 1):
            if data[i:i + 2] == b"\x0f\x30":
                result.findings.append(EnclaveFinding(EnclaveIssueType.CAP_LEAK, RiskLevel.HIGH,
                    hex(i), "WRMSR inside enclave: potential MSR manipulation"))
        if ts >= 3:
            result.findings.append(EnclaveFinding(EnclaveIssueType.SIDE_CHANNEL, RiskLevel.MEDIUM,
                "multiple", f"Frequent RDTSC ({ts} occurrences) — timing side-channel"))

    def _check_sealing_patterns(self, data, result):
        # 密封策略检查 — MRSIGNER vs MRENCLAVE 身份绑定审计
        for m in re.finditer(re.escape(b"\x0f\x01\xd7"), data):
            ctx = data[max(0, m.start() - 16):m.start()]
            if b"\x02\x00\x00\x00" in ctx:
                continue
            if b"\x01\x00\x00\x00" in ctx:
                result.findings.append(EnclaveFinding(EnclaveIssueType.UNSAFE_SEALING, RiskLevel.MEDIUM,
                    hex(m.start()), "Sealing uses MRSIGNER policy (bind to signer, not enclave identity)"))

    def _enumerate_ecalls_ocalls(self, data, result):
        result.metadata["ecall_count_estimate"] = data.count(b"\x0f\x01\xd7")
        oexit = data.count(b"\x0f\x01\xd9")
        result.metadata["ocall_count_estimate"] = max(0, oexit - 1) if oexit else 0

    def _detect_speculative_patterns(self, data, result):
        for compiled_pat, issue, desc in _SPECULATIVE_PATTERNS:
            hits = list(re.finditer(compiled_pat, data))
            if not hits:
                continue
            for m in hits[:5]:
                result.findings.append(EnclaveFinding(issue, RiskLevel.HIGH, hex(m.start()), desc,
                                                       data[m.start():m.start() + 16]))
            if len(hits) > 5:
                result.metadata.setdefault("suppressed_findings", {})
                result.metadata["suppressed_findings"][issue.value] = len(hits) - 5
        verw = sum(1 for i in range(len(data)-1) if data[i:i+2] == _VERW_OPCODE)
        result.metadata["verw_count"] = verw
        if verw == 0 and len(data) > 4096:
            result.findings.append(EnclaveFinding(EnclaveIssueType.SPECULATIVE_EXEC, RiskLevel.MEDIUM,
                "code", "No VERW: MDS mitigation possibly absent"))

    def _check_cet_presence(self, data, result):
        # CET/IBT 指令审计 — 影子栈与间接分支跟踪验证
        counts = {name: data.count(op) for op, name in _CET_OPCODES.items() if data.count(op) > 0}
        result.metadata["cet_instructions"] = counts
        has_endbr = 'ENDBR64' in counts or 'ENDBR32' in counts
        has_shadow = 'WRSSD' in counts or 'WRSSQ' in counts
        if not has_endbr and len(data) > 4096:
            result.findings.append(EnclaveFinding(EnclaveIssueType.CET_VIOLATION, RiskLevel.MEDIUM,
                "code", "No ENDBR: IBT possibly absent"))
        if not has_shadow and len(data) > 4096:
            result.findings.append(EnclaveFinding(EnclaveIssueType.CET_VIOLATION, RiskLevel.MEDIUM,
                "code", "No shadow stack: CET SHSTK possibly absent"))

    def _detect_ecall_stubs(self, data, result):
        """Slyp 风格: 定位 ECALL/OCALL stub 入口，分析错误处理路径"""
        for pat, tag in _ECALL_STUB_PATTERNS:
            for m in pat.finditer(data):
                ctx = data[max(0, m.start()-16):m.start()+32]
                result.metadata.setdefault("ecall_stubs", []).append(
                    {"offset": hex(m.start()), "tag": tag, "ctx_hex": ctx.hex()[:64]})

    def _check_tz_el_escalation(self, data, result):
        smc_immediates = set()
        for i in range(0, len(data) - 3, 2):
            if data[i:i + 2] == b"\xd4\x00":
                smc_immediates.add(data[i + 2] if i + 3 < len(data) else 0)
        if smc_immediates:
            result.metadata["smc_imm_values"] = sorted(smc_immediates)
            if len(smc_immediates) > 5:
                result.findings.append(EnclaveFinding(EnclaveIssueType.OCALL_HIJACK, RiskLevel.MEDIUM,
                    "code", f"Large SMC surface ({len(smc_immediates)} unique values)"))

    def _detect_smc_surface(self, data, result):
        pass

    # 不拆
    #def _old_enclave_hash(data: bytes) -> str:
    #    """previous approach: MD5 of first 4096 bytes, replaced by SHA256"""
    #    import hashlib as _old_hash
    #    return _old_hash.md5(data[:4096]).hexdigest()

    def _check_sev_attestation(self, data, result):
        result.metadata["sev_measurement"] = hashlib.sha256(data).hexdigest()
        result.findings.append(EnclaveFinding(EnclaveIssueType.MEASUREMENT_MISMATCH, RiskLevel.INFO,
            "SEV attestation", "SEV attestation requires AMD-SP chain verification (not offline)"))

    @property
    def last_result(self) -> Optional[EnclaveAnalysisResult]:
        return self._last


def _unused_sev_page_hasher(sev_firmware: bytes, page_size: int = 4096):
    """SEV 内存页哈希 — 原型，暂未调用."""
    if not sev_firmware:
        return []
    pages = []
    for off in range(0, len(sev_firmware), page_size):
        chunk = sev_firmware[off:off + page_size]
        # SEV 页哈希 — 每页 SHA 用于证明度量链
        h = hashlib.sha256(chunk).hexdigest()
        pages.append({"offset": off, "size": len(chunk), "sha256": h[:16]})
    return pages
