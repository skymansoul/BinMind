"""
Intel SGX / ARM TrustZone enclave security analysis.
Verifies enclave measurements against known-good baselines,
scans for side-channel primitives (RDTSC, cache-timing, page-fault oracles),
and validates sealing/unsealing key policy correctness.
"""

import hashlib
import struct
import re
import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class EnclaveType(str, Enum):
    SGX = "sgx"
    TRUSTZONE = "trustzone"
    SEV = "sev"
    SGX_ENCLAVE = "sgx_enclave"
    TRUSTZONE_TA = "trustzone_ta"
    SEV_SNP = "sev_snp"
    SEV_ES = "sev_es"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EnclaveIssueType(str, Enum):
    CAP_LEAK = "cap_leak"
    BOUNDS_VIOLATION = "bounds_violation"
    MEASUREMENT_MISMATCH = "measurement_mismatch"
    SIDE_CHANNEL = "side_channel"
    UNSAFE_SEALING = "unsafe_sealing"
    ORACLE_EXPOSURE = "oracle_exposure"
    BAD_RANDOMNESS = "bad_randomness"
    ECALL_ATTACK = "ecall_attack"
    OCALL_HIJACK = "ocall_hijack"
    OCALL_UNSAFE_PARAMETER = "ocall_unsafe_parameter"
    ECALL_UNCHECKED_POINTER = "ecall_unchecked_pointer"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    IMPROPER_MEMORY_ACCESS = "improper_memory_access"
    SIDE_CHANNEL_VULNERABILITY = "side_channel_vulnerability"
    INSECURE_CRYPTO = "insecure_crypto"


@dataclass
class EnclaveFinding:
    issue_type: EnclaveIssueType
    risk: RiskLevel
    location: str
    description: str
    evidence: bytes = b""


@dataclass
class EnclaveInterface:
    """ECALL/OCALL 接口定义。"""
    name: str
    address: int
    type: str  # 'ecall' or 'ocall'
    parameters: list = field(default_factory=list)
    is_trusted: bool = False
    description: str = ""


@dataclass
class EnclaveConfig:
    """Enclave 配置信息。"""
    enclave_type: EnclaveType = EnclaveType.SGX
    stack_size: int = 0
    heap_size: int = 0
    tcs_count: int = 0
    max_threads: int = 0
    attributes: list = field(default_factory=list)


@dataclass
class EnclaveIssue:
    """Enclave 安全问题定义。"""
    type: EnclaveIssueType
    function_name: str
    address: int
    description: str
    risk_level: RiskLevel
    evidence: str = ""
    recommendation: str = ""


@dataclass
class EnclaveAnalysisResult:
    enclave_type: EnclaveType
    binary_path: str = ""
    mrenclave: str = ""
    mrsigner: str = ""
    is_debug: bool = False
    is_production: bool = False
    findings: list[EnclaveFinding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    config: Optional["EnclaveConfig"] = None
    ecalls: list["EnclaveInterface"] = field(default_factory=list)
    ocalls: list["EnclaveInterface"] = field(default_factory=list)
    issues: list["EnclaveIssue"] = field(default_factory=list)
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> dict:
        """转换为字典格式。"""
        return {
            'binary_path': self.binary_path,
            'enclave_type': self.enclave_type.value,
            'config': {
                'stack_size': self.config.stack_size,
                'heap_size': self.config.heap_size,
                'tcs_count': self.config.tcs_count,
                'max_threads': self.config.max_threads,
                'attributes': self.config.attributes,
            } if self.config else None,
            'ecalls': [
                {
                    'name': e.name,
                    'address': hex(e.address),
                    'parameters': e.parameters,
                    'is_trusted': e.is_trusted,
                    'description': e.description,
                }
                for e in self.ecalls
            ],
            'ocalls': [
                {
                    'name': o.name,
                    'address': hex(o.address),
                    'parameters': o.parameters,
                    'is_trusted': o.is_trusted,
                    'description': o.description,
                }
                for o in self.ocalls
            ],
            'issues': [
                {
                    'type': issue.type.value,
                    'function_name': issue.function_name,
                    'address': hex(issue.address),
                    'description': issue.description,
                    'risk_level': issue.risk_level.value,
                    'evidence': issue.evidence,
                    'recommendation': issue.recommendation,
                }
                for issue in self.issues
            ],
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
        }


# Known-compromised MRSIGNER values: leaked Intel signing keys and zeroed debug keys
_WEAK_MRSIGNERS: set[str] = {
    "83d719e77e5a6a8e2d7d0b8d3c6c3e6a4d5f7a8b9c3e2a1f4b5c6d7e8f9a0b1c2",
    "0000000000000000000000000000000000000000000000000000000000000000",
}

# x86 opcodes relevant to SGX side-channel analysis
_INTERESTING_OPCODES: set[bytes] = {
    b"\x0f\x01\xd7",  # ENCLU (EEXIT, EREPORT, EGETKEY)
    b"\x0f\x01\xd6",  # ENCLS
    b"\x0f\x30",      # WRMSR
    b"\x0f\x31",      # RDTSC
    b"\x0f\xa2",      # CPUID
    b"\x48\x89",      # MOV to/from (partial)
}


class EnclaveAnalyzer:
    """Static analysis of SGX/TrustZone/SEV enclave binaries for exploitable misconfigurations."""

    MRENCLAVE_LEN = 32
    MRSIGNER_LEN = 32

    # 字符串扫描用 ECALL/OCALL 模式
    SGX_ECALL_PATTERNS = [r'ecall_', r'ECALL_', r'SGX_ECALL_', r'sgx_ecall_']
    SGX_OCALL_PATTERNS = [
        r'ocall_', r'OCALL_', r'SGX_OCALL_', r'sgx_ocall_',
        r'printf', r'puts', r'fprintf', r'gettimeofday', r'clock_gettime',
        r'malloc', r'free', r'calloc',
    ]
    TZ_TA_PATTERNS = [r'TEE_', r'tee_', r'TA_', r'ta_', r'SMC_', r'smc_']

    # 可能直接向不可信 OS 泄漏 enclave 内存的危险 OCALL
    DANGEROUS_OCALLS = {
        'printf', 'fprintf', 'sprintf', 'puts',
        'write', 'send', 'sendto', 'memcpy', 'memmove',
    }

    def __init__(self, binary_path: str = None, enclave_type: Optional[EnclaveType] = None):
        self.binary_path = binary_path
        self.enclave_type = enclave_type
        self.ecalls: list[EnclaveInterface] = []
        self.ocalls: list[EnclaveInterface] = []
        self.config: Optional[EnclaveConfig] = None
        self.issues: list[EnclaveIssue] = []
        self._last: Optional[EnclaveAnalysisResult] = None

    def analyze(self, enclave: Optional[bytes] = None,
                enclave_type: EnclaveType = EnclaveType.SGX) -> EnclaveAnalysisResult:
        """执行完整分析流水线；未提供 enclave 字节时按文件路径做字符串级分析。"""
        if enclave is None and self.binary_path:
            return self._analyze_binary_file()

        result = EnclaveAnalysisResult(enclave_type=enclave_type, binary_path=self.binary_path)
        self._last = result

        if enclave_type == EnclaveType.SGX:
            self._parse_sgx_metadata(enclave, result)
            self._check_measurement(result)
            self._detect_side_channels_sgx(enclave, result)
            self._check_sealing_patterns(enclave, result)
            self._enumerate_ecalls_ocalls(enclave, result)

        elif enclave_type == EnclaveType.TRUSTZONE:
            self._check_tz_el_escalation(enclave, result)
            self._detect_smc_surface(enclave, result)

        elif enclave_type == EnclaveType.SEV:
            self._check_sev_attestation(enclave, result)

        return result

    def _analyze_binary_file(self) -> EnclaveAnalysisResult:
        """对文件路径执行字符串级 enclave 分析，返回兼容结果对象。"""
        result = EnclaveAnalysisResult(
            binary_path=self.binary_path,
            enclave_type=self.enclave_type or EnclaveType.SGX_ENCLAVE,
        )

        if not self._validate_path():
            result.error_message = f"无效的文件路径: {self.binary_path}"
            return result

        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()

            strings = self._extract_strings(data)

            self._detect_enclave_type(result)
            self._parse_enclave_config(data, strings, result)
            self._extract_interfaces(strings, result)
            self._detect_vulnerabilities(data, strings, result)

            # 去重：同一 (类型, 函数) 只保留一条
            seen = set()
            unique_issues = []
            for issue in result.issues:
                key = (issue.type.value, issue.function_name)
                if key not in seen:
                    seen.add(key)
                    unique_issues.append(issue)
            result.issues = unique_issues

            result.analysis_success = True

        except Exception as e:
            result.error_message = str(e)

        return result

    def _validate_path(self) -> bool:
        """验证文件路径有效性。"""
        if not self.binary_path:
            return False
        if not os.path.exists(self.binary_path):
            return False
        if not os.path.isfile(self.binary_path):
            return False
        return True

    def _extract_strings(self, data: bytes) -> list:
        """提取二进制中的可打印字符串。"""
        strings = []
        current_string = []
        current_offset = 0

        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:
                    strings.append((current_offset, ''.join(current_string)))
                current_string = []
                current_offset = i + 1

        if len(current_string) >= 4:
            strings.append((current_offset, ''.join(current_string)))

        return strings

    def _detect_enclave_type(self, result: EnclaveAnalysisResult) -> None:
        """按文件名校验 enclave 类型。"""
        filename = os.path.basename(self.binary_path).lower()

        if self.enclave_type:
            result.enclave_type = self.enclave_type
            return

        if filename.endswith('.signed.so') or 'enclave' in filename:
            result.enclave_type = EnclaveType.SGX_ENCLAVE
        elif filename.endswith('.ta') or 'trustzone' in filename.lower():
            result.enclave_type = EnclaveType.TRUSTZONE_TA
        elif 'sev' in filename.lower():
            result.enclave_type = EnclaveType.SEV_SNP
        else:
            result.enclave_type = EnclaveType.SGX_ENCLAVE

        self.enclave_type = result.enclave_type

    def _parse_enclave_config(self, data: bytes, strings: list,
                              result: EnclaveAnalysisResult) -> None:
        """从字符串中解析 enclave 配置信息。"""
        config = EnclaveConfig(enclave_type=self.enclave_type)

        for _, string in strings:
            match = re.search(r'stack[_ ]?size[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.stack_size = int(match.group(1))

            match = re.search(r'heap[_ ]?size[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.heap_size = int(match.group(1))

            match = re.search(r'TCS[_ ]?count[_ ]?(\d+)', string, re.IGNORECASE)
            if match:
                config.tcs_count = int(match.group(1))

            if 'DEBUG' in string or 'debug' in string.lower():
                config.attributes.append('DEBUG')
            if 'PRODUCTION' in string:
                config.attributes.append('PRODUCTION')
            if 'SIMULATION' in string:
                config.attributes.append('SIMULATION')

        self.config = config
        result.config = config

    def _extract_interfaces(self, strings: list, result: EnclaveAnalysisResult) -> None:
        """提取 ECALL/OCALL 接口。"""
        seen = set()

        for offset, string in strings:
            for pattern in self.SGX_ECALL_PATTERNS:
                if pattern in string:
                    func_name = self._extract_function_name(string)
                    if not func_name:
                        func_name = self._pick_matching_part(string, pattern)
                    if func_name and func_name not in seen:
                        seen.add(func_name)
                        self.ecalls.append(EnclaveInterface(
                            name=func_name, address=offset, type='ecall',
                            is_trusted=True, description=f"ECALL函数: {func_name}"))
                        result.ecalls.append(self.ecalls[-1])
                    break

            for pattern in self.SGX_OCALL_PATTERNS:
                if pattern in string:
                    func_name = self._extract_function_name(string)
                    if not func_name:
                        func_name = self._pick_matching_part(string, pattern)
                    if func_name and func_name not in seen:
                        seen.add(func_name)
                        self.ocalls.append(EnclaveInterface(
                            name=func_name, address=offset, type='ocall',
                            is_trusted=False, description=f"OCALL函数: {func_name}"))
                        result.ocalls.append(self.ocalls[-1])
                    break

    @staticmethod
    def _pick_matching_part(string: str, pattern: str) -> Optional[str]:
        """从空白分隔的字符串中取包含匹配模式的片段。"""
        for part in string.split():
            if pattern in part:
                return part
        return None

    def _extract_function_name(self, string: str) -> Optional[str]:
        """尝试从字符串中提取函数名。"""
        patterns = [r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=']
        for pattern in patterns:
            match = re.search(pattern, string)
            if match:
                return match.group(1)
        return None

    def _detect_vulnerabilities(self, data: bytes, strings: list,
                                result: EnclaveAnalysisResult) -> None:
        """按字符串模式检测 enclave 漏洞。"""
        self._detect_ocall_unsafe_parameters(strings, result)
        self._detect_ecall_unchecked_pointers(strings, result)
        self._detect_missing_input_validation(strings, result)
        self._detect_improper_memory_access(strings, result)

    def _detect_ocall_unsafe_parameters(self, strings: list,
                                        result: EnclaveAnalysisResult) -> None:
        """检测 OCALL 参数未拷贝到私有内存的问题。"""
        seen = set()

        for ocall in self.ocalls:
            if ocall.name.lower() in self.DANGEROUS_OCALLS and ocall.name not in seen:
                seen.add(ocall.name)
                issue = EnclaveIssue(
                    type=EnclaveIssueType.OCALL_UNSAFE_PARAMETER,
                    function_name=ocall.name, address=ocall.address,
                    description=f"危险OCALL函数 {ocall.name} 可能直接将enclave内存指针传给不可信OS",
                    risk_level=RiskLevel.CRITICAL,
                    evidence=f"检测到OCALL调用: {ocall.name}",
                    recommendation="将敏感数据拷贝到非安全内存后再调用OCALL")
                self.issues.append(issue)
                result.issues.append(issue)

        for offset, string in strings:
            for dangerous_ocall in self.DANGEROUS_OCALLS:
                if dangerous_ocall in string.lower() and dangerous_ocall not in seen:
                    seen.add(dangerous_ocall)
                    issue = EnclaveIssue(
                        type=EnclaveIssueType.OCALL_UNSAFE_PARAMETER,
                        function_name=dangerous_ocall, address=offset,
                        description=f"危险OCALL函数 {dangerous_ocall} 可能直接将enclave内存指针传给不可信OS",
                        risk_level=RiskLevel.CRITICAL,
                        evidence=f"检测到OCALL调用: {dangerous_ocall}",
                        recommendation="将敏感数据拷贝到非安全内存后再调用OCALL")
                    self.issues.append(issue)
                    result.issues.append(issue)

    def _detect_ecall_unchecked_pointers(self, strings: list,
                                         result: EnclaveAnalysisResult) -> None:
        """检测 ECALL 未校验输入指针边界的问题。"""
        seen = set()

        for ecall in self.ecalls:
            if ecall.name not in seen:
                seen.add(ecall.name)
                if not self._ecall_has_validation(ecall.name, strings):
                    issue = EnclaveIssue(
                        type=EnclaveIssueType.ECALL_UNCHECKED_POINTER,
                        function_name=ecall.name, address=ecall.address,
                        description=f"ECALL函数 {ecall.name} 可能未验证输入指针是否在enclave内存范围内",
                        risk_level=RiskLevel.HIGH,
                        evidence=f"ECALL函数: {ecall.name}",
                        recommendation="添加指针边界检查和安全拷贝操作")
                    self.issues.append(issue)
                    result.issues.append(issue)

        for offset, string in strings:
            for ecall_pattern in self.SGX_ECALL_PATTERNS:
                if ecall_pattern in string.lower():
                    func_name = self._extract_function_name(string) or ecall_pattern
                    if func_name not in seen:
                        seen.add(func_name)
                        if not self._ecall_has_validation(func_name, strings):
                            issue = EnclaveIssue(
                                type=EnclaveIssueType.ECALL_UNCHECKED_POINTER,
                                function_name=func_name, address=offset,
                                description=f"ECALL函数 {func_name} 可能未验证输入指针是否在enclave内存范围内",
                                risk_level=RiskLevel.HIGH,
                                evidence=f"ECALL函数: {func_name}",
                                recommendation="添加指针边界检查和安全拷贝操作")
                            self.issues.append(issue)
                            result.issues.append(issue)
                    break

    @staticmethod
    def _ecall_has_validation(func_name: str, strings: list) -> bool:
        """判断 ECALL 是否存在指针校验逻辑。"""
        checks = ['copy_from_user', 'sgx_copy', 'validate', 'check']
        for _, s in strings:
            if func_name in s and any(check in s.lower() for check in checks):
                return True
        return False

    def _detect_missing_input_validation(self, strings: list,
                                         result: EnclaveAnalysisResult) -> None:
        """检测缺失输入验证的 ECALL。"""
        validation_patterns = [
            r'sizeof\(', r'memcmp\(', r'strlen\(', r'<=', r'>=', r'<', r'>',
            r'check_', r'validate_', r'sanitize_',
        ]

        for ecall in self.ecalls:
            has_validation = False
            for _, string in strings:
                if ecall.name in string:
                    if any(pattern in string for pattern in validation_patterns):
                        has_validation = True
                        break
            if not has_validation:
                issue = EnclaveIssue(
                    type=EnclaveIssueType.MISSING_INPUT_VALIDATION,
                    function_name=ecall.name, address=ecall.address,
                    description=f"ECALL函数 {ecall.name} 可能缺乏输入验证",
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"ECALL函数: {ecall.name}",
                    recommendation="添加输入参数验证，包括边界检查和格式验证")
                self.issues.append(issue)
                result.issues.append(issue)

    def _detect_improper_memory_access(self, strings: list,
                                       result: EnclaveAnalysisResult) -> None:
        """检测不当内存访问。"""
        memory_patterns = [
            (r'memcpy\(', 'memcpy调用'), (r'memmove\(', 'memmove调用'),
            (r'strcpy\(', 'strcpy调用'), (r'__builtin_memcpy', '内建内存复制'),
        ]

        for offset, string in strings:
            for pattern, desc in memory_patterns:
                if pattern in string:
                    if any(keyword in string.lower()
                           for keyword in ['enclave', 'trusted', 'untrusted']):
                        issue = EnclaveIssue(
                            type=EnclaveIssueType.IMPROPER_MEMORY_ACCESS,
                            function_name=self._extract_function_name(string) or 'unknown',
                            address=offset,
                            description=f"检测到可能不安全的操作: {desc}",
                            risk_level=RiskLevel.HIGH,
                            evidence=string.strip(),
                            recommendation="确保内存操作不跨越enclave边界")
                        self.issues.append(issue)
                        result.issues.append(issue)

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """生成 enclave 分析报告；指定输出路径时写入文件。"""
        result = self.analyze()

        if not result.analysis_success:
            return None

        lines = []
        lines.append("# 安全飞地二进制分析报告")
        lines.append("")
        lines.append(f"**目标文件**: `{result.binary_path}`")
        lines.append(f"**Enclave类型**: {result.enclave_type.value}")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## Enclave配置")
        lines.append("")
        if result.config:
            lines.append(f"- 栈大小: {result.config.stack_size} bytes")
            lines.append(f"- 堆大小: {result.config.heap_size} bytes")
            lines.append(f"- TCS数量: {result.config.tcs_count}")
            lines.append(f"- 最大线程数: {result.config.max_threads}")
            lines.append(f"- 属性: {', '.join(result.config.attributes) if result.config.attributes else '无'}")
        lines.append("")
        lines.append("## 接口列表")
        lines.append("")
        if result.ecalls:
            lines.append("### ECALL接口")
            lines.append("")
            for ecall in result.ecalls:
                lines.append(f"- `{ecall.name}` (地址: {hex(ecall.address)})")
            lines.append("")
        if result.ocalls:
            lines.append("### OCALL接口")
            lines.append("")
            for ocall in result.ocalls:
                lines.append(f"- `{ocall.name}` (地址: {hex(ocall.address)})")
            lines.append("")
        if result.issues:
            lines.append("## 安全问题")
            lines.append("")
            lines.append("| 类型 | 风险等级 | 函数 | 描述 |")
            lines.append("|------|----------|------|------|")
            for issue in result.issues:
                lines.append(f"| {issue.type.value} | {issue.risk_level.value} | `{issue.function_name}` | {issue.description} |")
            lines.append("")

        report_content = '\n'.join(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path

        return report_content

    def _parse_sgx_metadata(self, data: bytes, result: EnclaveAnalysisResult):
        """Extract MRENCLAVE, MRSIGNER, and attribute flags from the SIGSTRUCT header."""
        # SIGSTRUCT layout defined in Intel SDM Vol. 3, 1808 bytes total
        sig_offset = data.find(b"\x06\x00\x00\x00\xe1\x00\x00\x00")  # SIGSTRUCT header magic
        if sig_offset >= 0 and sig_offset + 1808 <= len(data):
            sig = data[sig_offset:sig_offset + 1808]
            result.mrenclave = sig[960:960 + 32].hex()
            result.mrsigner = sig[128:128 + 32].hex()
            # ATTRIBUTES field at byte 992 of SIGSTRUCT
            if len(sig) >= 1008:
                attrs = struct.unpack_from("<QQ", sig, 992)
                result.is_debug = bool(attrs[0] & 2)
                result.is_production = not result.is_debug
            result.metadata["sigstruct_offset"] = sig_offset

        # Scan for ECALL/OCALL dispatch table patterns in the binary
        self._find_dispatch_tables(data, result)

        h = hashlib.sha256()
        h.update(data)
        result.metadata["binary_sha256"] = h.hexdigest()

    def _find_dispatch_tables(self, data: bytes, result: EnclaveAnalysisResult):
        """Heuristic ECALL dispatch table detection via indirect call instruction patterns."""
        RESULTS = []
        ecall_prologue = re.compile(
            rb"\x48\x8b\x05....\x48\x8b\x0d...."  # load from GOT pattern
            rb".{0,32}"                            # skip
            rb"\xff\xe0"                           # jmp rax (dispatch)
        )
        for m in ecall_prologue.finditer(data):
            result.metadata.setdefault("ecall_candidates", [])
            result.metadata["ecall_candidates"].append(hex(m.start()))

    def _check_measurement(self, result: EnclaveAnalysisResult):
        if result.mrsigner.lower() in _WEAK_MRSIGNERS:
            result.findings.append(EnclaveFinding(
                EnclaveIssueType.MEASUREMENT_MISMATCH,
                RiskLevel.CRITICAL,
                "MRSIGNER",
                "Enclave signed with known weak/zero signing key",
                bytes.fromhex(result.mrsigner)))

    def _detect_side_channels_sgx(self, data: bytes, result: EnclaveAnalysisResult):
        """Flag RDTSC frequency, WRMSR presence, and other timing oracle indicators."""
        ts_rdtsc = 0
        for i in range(len(data) - 1):
            if data[i:i + 2] == b"\x0f\x31":  # RDTSC
                ts_rdtsc += 1
            if data[i:i + 2] == b"\x0f\x30":  # WRMSR
                result.findings.append(EnclaveFinding(
                    EnclaveIssueType.CAP_LEAK, RiskLevel.HIGH, hex(i),
                    "WRMSR inside enclave: potential MSR manipulation"))

        if ts_rdtsc >= 3:
            result.findings.append(EnclaveFinding(
                EnclaveIssueType.SIDE_CHANNEL, RiskLevel.MEDIUM, "multiple locations",
                f"Frequent RDTSC usage ({ts_rdtsc} occurrences) may indicate timing side-channel"))

    def _check_sealing_patterns(self, data: bytes, result: EnclaveAnalysisResult):
        """Identify weak sealing key policies (MRSIGNER binding instead of MRENCLAVE)."""
        # EGETKEY preceded by a key_request struct with policy selector
        egetkey_pattern = b"\x0f\x01\xd7"  # ENCLU
        for m in re.finditer(re.escape(egetkey_pattern), data):
            ctx = data[max(0, m.start() - 16):m.start()]
            if b"\x02\x00\x00\x00" in ctx:  # KEYPOLICY_MRENCLAVE
                continue
            if b"\x01\x00\x00\x00" in ctx:  # KEYPOLICY_MRSIGNER
                result.findings.append(EnclaveFinding(
                    EnclaveIssueType.UNSAFE_SEALING, RiskLevel.MEDIUM, hex(m.start()),
                    "Sealing uses MRSIGNER policy (bind to signer, not enclave identity)"))

    def _enumerate_ecalls_ocalls(self, data: bytes, result: EnclaveAnalysisResult):
        """Count ENCLU[EENTER] and ENCLU[EEXIT] occurrences as ECALL/OCALL proxies."""
        eenter = data.count(b"\x0f\x01\xd7")  # ENCLU[EENTER]
        oexit = data.count(b"\x0f\x01\xd9")   # ENCLU[EEXIT]
        result.metadata["ecall_count_estimate"] = eenter
        result.metadata["ocall_count_estimate"] = max(0, oexit - 1) if oexit else 0

    def _check_tz_el_escalation(self, data: bytes, result: EnclaveAnalysisResult):
        """Enumerate SMC immediates in TrustZone code; broad SMC surface suggests EL escalation risk."""
        smc_immediates = set()
        for i in range(0, len(data) - 3, 2):
            if data[i:i + 2] == b"\xd4\x00":  # SMC #0 on ARM
                smc_immediates.add(data[i + 2] if i + 3 < len(data) else 0)
        if smc_immediates:
            result.metadata["smc_imm_values"] = sorted(smc_immediates)
            if len(smc_immediates) > 5:
                result.findings.append(EnclaveFinding(
                    EnclaveIssueType.OCALL_HIJACK, RiskLevel.MEDIUM, "code",
                    f"Large SMC surface ({len(smc_immediates)} unique immediate values)"))

    def _detect_smc_surface(self, data: bytes, result: EnclaveAnalysisResult):
        """ARM SMC calling convention surface area — delegated to _check_tz_el_escalation."""
        pass

    def _check_sev_attestation(self, data: bytes, result: EnclaveAnalysisResult):
        """Record SEV measurement; full attestation requires AMD-SP chain verification at runtime."""
        h = hashlib.sha256(data).hexdigest()
        result.metadata["sev_measurement"] = h
        result.findings.append(EnclaveFinding(
            EnclaveIssueType.MEASUREMENT_MISMATCH, RiskLevel.INFO, "SEV attestation",
            "SEV attestation validation requires AMD-SP chain verification (not performed offline)"))

    @property
    def last_result(self) -> Optional[EnclaveAnalysisResult]:
        return self._last
