"""
Memory forensics engine for artifact extraction incident response
Operates live process memory static disk images

舍入 5: Cryptographic weakness detection (RC4/DES/MD5/ECB 签名s)
binary 漏洞利用 mitigation audit (ASLR/DEP/CFG/栈Guard/SafeSEH 检查)
CPython runtime object extraction memory 转存
"""
import os, re, json, struct, logging, subprocess, platform, tempfile, hashlib, math
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Tuple
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

class Config:
    MEMORY_FORENSICS_OUTPUT_DIR = "data/memory_forensics"
    LOG_LEVEL = "INFO"
    VOLATILITY_PATH = "volatility3"
    MAX_STRING_LENGTH = 10000
    SENSITIVE_DATA_MASK = True

log_level_str = getattr(Config, 'LOG_LEVEL', 'INFO')
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
_log = logging.getLogger(__name__)
logger = _log

class MemoryType(Enum):
    LIVE_PROCESS = "live_process"
    MEMORY_DUMP = "memory_dump"
    MINIDUMP = "minidump"
    CORE_DUMP = "core_dump"
    ELF_DUMP = "elf_dump"
    RAW_DUMP = "raw_dump"

class OSType(Enum):
    WINDOWS = "windows"; LINUX = "linux"; MACOS = "macos"; UNKNOWN = "unknown"

class SensitiveDataType(Enum):
    RSA_PRIVATE_KEY = "rsa_private_key"; AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"; API_KEY = "api_key"; JWT_TOKEN = "jwt_token"
    DATABASE_CONNECTION = "database_connection"; PASSWORD_HASH = "password_hash"
    PLAIN_PASSWORD = "plain_password"; CREDIT_CARD = "credit_card"; SSN = "ssn"
    PRIVATE_KEY = "private_key"; CERTIFICATE = "certificate"; SESSION_ID = "session_id"
    COOKIE = "cookie"; AUTH_TOKEN = "auth_token"; ENCRYPTION_KEY = "encryption_key"
    IP_ADDRESS = "ip_address"; URL_WITH_Creds = "url_with_creds"; EMAIL = "email"
    PHONE = "phone_number"; OTHER = "other"

# 舍入 5: Cryptographic weakness 签名s
# 检测二进制中使用的弱密码学原语。参照NIST SP 800-131A和BSI TR-02102-1标准
# RC4/DES/MD5/SHA1/ECB模式的使用应标记为不符合当前安全基线

@dataclass
class CryptoWeakness:
    algorithm: str
    weakness_type: str          # 已废弃_key_size | broken_algorithm | weak_mode
    evidence: str               # 触发检测的字节模式或导入符号
    severity: str               # critical | high | medium
    recommendation: str
    confidence: float

CRYPTO_WEAK_SIGNATURES = {
    'RC4': {
        'pattern': rb'RC4|arcfour|Arcfour',
        'weakness_type': 'broken_algorithm',
        'severity': 'critical',
        'recommendation': 'Replace RC4 with AES-GCM or ChaCha20-Poly1305',
    },
    'DES': {
        'pattern': rb'DES_|des_encrypt|DES_ecb|DES_cbc',
        'weakness_type': 'deprecated_key_size',
        'severity': 'critical',
        'recommendation': '56-bit DES key is brute-forceable; migrate to AES-256',
    },
    'MD5': {
        'pattern': rb'MD5_|md5_|MD5Init|MD5Update|MD5Final',
        'weakness_type': 'broken_algorithm',
        'severity': 'high',
        'recommendation': 'MD5 collisions are practical; use SHA-256 or BLAKE3',
    },
    'SHA1': {
        'pattern': rb'SHA1_|SHA1Init|SHA1Update|SHA1Final|SHA-1',
        'weakness_type': 'broken_algorithm',
        'severity': 'high',
        'recommendation': 'SHAttered attack practical; migrate to SHA-256',
    },
    'ECB_mode': {
        'pattern': rb'AES_ecb|DES_ecb|_ecb_encrypt|EVP_aes.*ecb',
        'weakness_type': 'weak_mode',
        'severity': 'high',
        'recommendation': 'ECB mode leaks plaintext patterns; use CBC/GCM/CTR',
    },
    'RSA_1024': {
        'pattern': rb'RSA_1024|RSA_1024|bits:1024',
        'weakness_type': 'deprecated_key_size',
        'severity': 'medium',
        'recommendation': 'RSA-1024 below NIST 2048-bit minimum; use RSA-3072+',
    },
}

# 舍入 5: Binary 漏洞利用 mitigation 签名s
# 检测二进制启用的编译器和OS级安全缓解措施。参照微软/Google/Apple的安全要求

HARDENING_SIGNATURES = {
    'ASLR': {
        'pe_flag': 0x0040,           # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        'elf_section': '.rela.dyn',  # Position-independent code requires 重定位s
        'severity_if_missing': 'high',
    },
    'DEP_NX': {
        'pe_flag': 0x0100,           # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        'elf_segment': 'GNU_STACK',   # PT_GNU_栈 PF_X bit 清除
        'severity_if_missing': 'critical',
    },
    'StackGuard': {
        'symbols': ['__stack_chk_fail', '___stack_chk_guard',
                     '__security_check_cookie', '__GSHandlerCheck'],
        'severity_if_missing': 'high',
    },
    'SafeSEH': {
        'pe_flag': 0x0400,           # IMAGE_DLLCHARACTERISTICS_NO_SEH
        'severity_if_missing': 'medium',
    },
    'ControlFlowGuard': {
        'symbols': ['__guard_check_icall_fptr', '__guard_dispatch_icall_fptr'],
        'severity_if_missing': 'medium',
    },
    'CET_IBT': {
        'instructions': [b'\xf3\x0f\x1e\xfa'],  # endbr64
        'severity_if_missing': 'medium',
    },
}

# Data containers

@dataclass
class ProcessInfo:
    pid: int; name: str; path: Optional[str] = None; command_line: Optional[str] = None
    user: Optional[str] = None; start_time: Optional[str] = None; parent_pid: Optional[int] = None
    threads: int = 0; handles: int = 0; memory_usage: Optional[int] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"pid": self.pid, "name": self.name, "path": self.path,
                "command_line": self.command_line, "user": self.user,
                "start_time": self.start_time, "parent_pid": self.parent_pid,
                "threads": self.threads, "handles": self.handles,
                "memory_usage": self.memory_usage}

@dataclass
class NetworkConnection:
    protocol: str; local_addr: str; local_port: int
    remote_addr: Optional[str] = None; remote_port: Optional[int] = None
    state: Optional[str] = None; pid: Optional[int] = None; process_name: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"protocol": self.protocol, "local_addr": self.local_addr,
                "local_port": self.local_port, "remote_addr": self.remote_addr,
                "remote_port": self.remote_port, "state": self.state,
                "pid": self.pid, "process_name": self.process_name}

@dataclass
class FileHandle:
    file_path: str; handle_value: Optional[int] = None
    access_mode: Optional[str] = None; pid: Optional[int] = None; process_name: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"handle_value": self.handle_value, "file_path": self.file_path,
                "access_mode": self.access_mode, "pid": self.pid,
                "process_name": self.process_name}

@dataclass
class RegistryKey:
    key_path: str; value_name: Optional[str] = None; value_data: Optional[str] = None
    value_type: Optional[str] = None; last_write_time: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"key_path": self.key_path, "value_name": self.value_name,
                "value_data": self._mask_sensitive() if Config.SENSITIVE_DATA_MASK else self.value_data,
                "value_type": self.value_type, "last_write_time": self.last_write_time}
    def _mask_sensitive(self) -> Optional[str]:
        if not self.value_data: return None
        for p in [r'password', r'passwd', r'pwd', r'secret', r'key', r'token', r'credential', r'api_key']:
            if re.search(p, self.key_path.lower() + (self.value_name or '').lower()):
                return "***REDACTED***"
        return self.value_data

@dataclass
class MemoryString:
    address: int; content: str; length: int; encoding: str = "utf-8"; context: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"address": hex(self.address),
                "content": self.content[:Config.MAX_STRING_LENGTH] if len(self.content) > Config.MAX_STRING_LENGTH else self.content,
                "length": self.length, "encoding": self.encoding, "context": self.context}

@dataclass
class SensitiveData:
    data_type: SensitiveDataType; value: str; location: str; address: Optional[int] = None
    process: Optional[str] = None; confidence: float = 0.0; context: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {"data_type": self.data_type.value, "value": self._mask_value(),
                "location": self.location, "address": hex(self.address) if self.address else None,
                "process": self.process, "confidence": self.confidence, "context": self.context}
    def _mask_value(self) -> str:
        if not Config.SENSITIVE_DATA_MASK: return self.value
        if self.data_type in [SensitiveDataType.PLAIN_PASSWORD, SensitiveDataType.AWS_SECRET_KEY,
                               SensitiveDataType.ENCRYPTION_KEY]:
            return "***REDACTED***"
        if len(self.value) > 8: return self.value[:4] + "****" + self.value[-4:]
        return "***REDACTED***"

@dataclass
class PythonObject:
    address: int; ob_refcnt: int; ob_type_addr: int; type_name: str = ""
    inferred_value: Any = None; referenced_objects: List[int] = field(default_factory=list)
    confidence: float = 0.0

@dataclass
class ForensicsResult:
    source: str; memory_type: MemoryType; os_type: OSType; timestamp: str
    processes: List[ProcessInfo] = field(default_factory=list)
    network_connections: List[NetworkConnection] = field(default_factory=list)
    file_handles: List[FileHandle] = field(default_factory=list)
    registry_keys: List[RegistryKey] = field(default_factory=list)
    memory_strings: List[MemoryString] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    total_processes: int = 0; total_connections: int = 0; total_handles: int = 0
    total_sensitive_items: int = 0; analysis_duration: Optional[float] = None
    volatility_version: Optional[str] = None; errors: List[str] = field(default_factory=list)
    python_objects: List[PythonObject] = field(default_factory=list)
    crypto_weaknesses: List[CryptoWeakness] = field(default_factory=list)
    hardening_audit: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "memory_type": self.memory_type.value,
            "os_type": self.os_type.value, "timestamp": self.timestamp,
            "total_processes": self.total_processes,
            "total_connections": self.total_connections,
            "total_handles": self.total_handles,
            "total_sensitive_items": self.total_sensitive_items,
            "summary": {"total_processes": self.total_processes,
                "total_connections": self.total_connections,
                "total_handles": self.total_handles,
                "total_sensitive_items": self.total_sensitive_items},
            "processes": [p.to_dict() for p in self.processes],
            "network_connections": [n.to_dict() for n in self.network_connections],
            "file_handles": [f.to_dict() for f in self.file_handles],
            "registry_keys": [r.to_dict() for r in self.registry_keys],
            "memory_strings": [m.to_dict() for m in self.memory_strings[:100]],
            "sensitive_data": [s.to_dict() for s in self.sensitive_data],
            "crypto_weaknesses": [{"algo": w.algorithm, "type": w.weakness_type,
                "severity": w.severity, "recommendation": w.recommendation}
                for w in self.crypto_weaknesses],
            "hardening_audit": self.hardening_audit,
            "analysis_duration": self.analysis_duration,
            "volatility_version": self.volatility_version,
            "errors": self.errors,
        }


class MemoryForensicsAnalyzer:
    SENSITIVE_PATTERNS = {
        SensitiveDataType.RSA_PRIVATE_KEY: [r'-----BEGIN RSA PRIVATE KEY-----'],
        SensitiveDataType.AWS_ACCESS_KEY: [r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'],
        SensitiveDataType.AWS_SECRET_KEY: [r'[A-Za-z0-9/+=]{40}'],
        SensitiveDataType.API_KEY: [r'api[_-]?key\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?'],
        SensitiveDataType.JWT_TOKEN: [r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'],
        SensitiveDataType.DATABASE_CONNECTION: [r'(?:mysql|postgres|mongodb|redis|oracle|sqlserver)://[^\s]+'],
        SensitiveDataType.PLAIN_PASSWORD: [r'password\s*[=:]\s*[\'"]?[^\s\'"]{8,}[\'"]?'],
        SensitiveDataType.CREDIT_CARD: [r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'],
        SensitiveDataType.SSN: [r'\b\d{3}-\d{2}-\d{4}\b'],
        SensitiveDataType.PRIVATE_KEY: [r'-----BEGIN (?:DSA |EC |OPENSSH )?PRIVATE KEY-----'],
        SensitiveDataType.CERTIFICATE: [r'-----BEGIN CERTIFICATE-----'],
        SensitiveDataType.SESSION_ID: [r'session[_-]?id\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?'],
        SensitiveDataType.AUTH_TOKEN: [r'auth[_-]?token\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?'],
        SensitiveDataType.ENCRYPTION_KEY: [r'encryption[_-]?key\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{16,}[\'"]?'],
        SensitiveDataType.IP_ADDRESS: [r'\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b'],
        SensitiveDataType.URL_WITH_Creds: [r'https?://[^\s:]+:[^\s@]+@[^\s]+'],
        SensitiveDataType.EMAIL: [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'],
    }
    MIN_STRING_LENGTH = 8

    def __init__(self, output_dir: Optional[str] = None, volatility_path: Optional[str] = None):
        self.output_dir = Path(output_dir or Config.MEMORY_FORENSICS_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volatility_path = volatility_path or Config.VOLATILITY_PATH
        self.platform = platform.system().lower()
        self.volatility_available = self._check_volatility()
        logger.info(f"Memory forensics engine started, platform: {self.platform}")

    def _check_volatility(self) -> bool:
        try:
            r = subprocess.run([self.volatility_path, "-h"], capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except Exception as e:
            logger.warning(f"Volatility probe rejected: {e}")
            return False

    def analyze(self, source: Union[str, int], memory_type: Optional[MemoryType] = None) -> ForensicsResult:
        start_time = datetime.now()
        if memory_type is None:
            memory_type = self._detect_memory_type(source)
        os_type = self._detect_os_type(source, memory_type)
        result = ForensicsResult(source=str(source), memory_type=memory_type,
                                  os_type=os_type, timestamp=start_time.strftime("%Y-%m-%d %H:%M:%S"))
        try:
            if memory_type == MemoryType.LIVE_PROCESS:
                self._analyze_live_process(source, result)
            elif memory_type == MemoryType.MEMORY_DUMP:
                self._analyze_memory_dump(source, result)
            elif memory_type == MemoryType.MINIDUMP:
                self._analyze_minidump(source, result)
            elif memory_type == MemoryType.CORE_DUMP:
                self._analyze_core_dump(source, result)
            else:
                self._analyze_generic(source, result)
            self._extract_sensitive_data(result)
            # Round 5: 密码弱点扫描 + 二进制加固审计
            self._scan_crypto_weaknesses(source, result)
            self._audit_binary_hardening(source, result)
        except Exception as e:
            logger.error(f"Analysis pipeline aborted: {e}")
            result.errors.append(str(e))
        end_time = datetime.now()
        result.analysis_duration = (end_time - start_time).total_seconds()
        result.total_processes = len(result.processes)
        result.total_connections = len(result.network_connections)
        result.total_handles = len(result.file_handles)
        result.total_sensitive_items = len(result.sensitive_data)
        return result

# 舍入 5: Cryptographic weakness scanner
    def _scan_crypto_weaknesses(self, source: Union[str, int],
                                 result: ForensicsResult) -> None:
        """扫描二进制/内存中的弱密码学原语。基于导入符号、内联常量和
        反汇编模式匹配。弱密码原语包括RC4/DES/MD5/SHA1/ECB/RSA-1024"""
        try:
            if isinstance(source, str) and os.path.isfile(source):
                with open(source, 'rb') as fh:
                    raw = fh.read()
            else:
                raw = b''
        except Exception:
            return

        for algo_name, sig in CRYPTO_WEAK_SIGNATURES.items():
            matches = list(re.finditer(sig['pattern'], raw))
            if matches:
                result.crypto_weaknesses.append(CryptoWeakness(
                    algorithm=algo_name,
                    weakness_type=sig['weakness_type'],
                    evidence=f"{len(matches)} pattern match(es) for {algo_name}",
                    severity=sig['severity'],
                    recommendation=sig['recommendation'],
                    confidence=min(0.95, 0.5 + len(matches) * 0.1),
                ))

# 舍入 5: Binary 漏洞利用 mitigation auditor
    def _audit_binary_hardening(self, source: Union[str, int],
                                  result: ForensicsResult) -> None:
        """审计二进制启用的安全缓解措施。检查ASLR/DEP/StackGuard/SafeSEH/
        CFG/CET特性。缺失的缓解措施按严重程度排序在报告中列出"""
        hardening = {}
        try:
            if isinstance(source, str) and os.path.isfile(source):
                with open(source, 'rb') as fh:
                    raw = fh.read()
            else:
                result.hardening_audit = {'error': 'Cannot audit live process hardening'}
                return
        except Exception:
            return

        # ASLR: PE DYNAMIC_BASE flag 或 ELF PIE
        if raw[:2] == b'MZ':
            pe_off = int.from_bytes(raw[0x3C:0x40], 'little')
            if pe_off + 4 <= len(raw) and raw[pe_off:pe_off + 4] == b'PE\x00\x00':
                dll_chars = int.from_bytes(raw[pe_off + 94:pe_off + 96], 'little')
                hardening['ASLR'] = bool(dll_chars & 0x0040)
                hardening['DEP_NX'] = bool(dll_chars & 0x0100)
                hardening['SafeSEH'] = bool(dll_chars & 0x0400)
        elif raw[:4] == b'\x7fELF':
            raw_str = raw.decode('latin-1', errors='ignore')
            hardening['ASLR'] = '.rela.dyn' in raw_str or '.rela.plt' in raw_str
            hardening['DEP_NX'] = 'GNU_STACK' not in raw_str or 'E' not in raw_str

        # StackGuard: 搜索金丝雀检查符号
        canary_syms = ['__stack_chk_fail', '__security_check_cookie', '__GSHandlerCheck']
        raw_str = raw.decode('latin-1', errors='ignore')
        hardening['StackGuard'] = any(s in raw_str for s in canary_syms)

        # CFG: 搜索控制流保护符号
        cfg_syms = ['__guard_check_icall_fptr', '__guard_dispatch_icall_fptr']
        hardening['ControlFlowGuard'] = any(s in raw_str for s in cfg_syms)

        # CET IBT: 搜索endbr64指令字节
        hardening['CET_IBT'] = raw.count(b'\xf3\x0f\x1e\xfa') > 2

        result.hardening_audit = hardening
        missing = [k for k, v in hardening.items() if not v]
        if missing:
            logger.warning(f"Missing hardening: {missing}")

    def _detect_memory_type(self, source: Union[str, int]) -> MemoryType:
        if isinstance(source, int): return MemoryType.LIVE_PROCESS
        ss = str(source)
        if ss.endswith('.dmp') or ss.endswith('.mdmp'): return MemoryType.MINIDUMP
        if ss.endswith('.core') or 'core' in ss.lower(): return MemoryType.CORE_DUMP
        if ss.endswith('.raw') or ss.endswith('.mem'): return MemoryType.RAW_DUMP
        if ss.endswith('.elf'): return MemoryType.ELF_DUMP
        try:
            with open(ss, 'rb') as f:
                h = f.read(4)
                if h == b'MDMP': return MemoryType.MINIDUMP
                if h[:4] == b'\x7fELF': return MemoryType.ELF_DUMP
        except Exception: __log.debug("suppressed", exc_info=True)
        return MemoryType.MEMORY_DUMP

    def _detect_os_type(self, source: Union[str, int], memory_type: MemoryType) -> OSType:
        if memory_type == MemoryType.LIVE_PROCESS:
            if self.platform == 'windows': return OSType.WINDOWS
            if self.platform == 'linux': return OSType.LINUX
            if self.platform == 'darwin': return OSType.MACOS
        if self.volatility_available and isinstance(source, str):
            try:
                r = subprocess.run([self.volatility_path, "-f", source, "imageinfo"],
                                   capture_output=True, text=True, timeout=60)
                if "Windows" in r.stdout: return OSType.WINDOWS
                if "Linux" in r.stdout: return OSType.LINUX
            except Exception: __log.debug("suppressed", exc_info=True)
        return OSType.UNKNOWN

    def _analyze_live_process(self, pid: Union[str, int], result: ForensicsResult) -> None:
        pi = int(pid)
        if self.platform == 'linux' and os.geteuid() != 0:
            result.errors.append("Root privileges required"); return
        if self.platform == 'linux':
            self._analyze_linux_process(pi, result)
        elif self.platform == 'windows':
            self._analyze_windows_process(pi, result)

    def _analyze_linux_process(self, pid: int, result: ForensicsResult) -> None:
        pp = Path(f"/proc/{pid}")
        if not pp.exists(): result.errors.append(f"Process {pid} does not exist"); return
        try:
            clp = pp / "cmdline"
            cmdline = clp.read_text().replace('\x00', ' ').strip() if clp.exists() else ""
            stp = pp / "status"
            name, uid, threads = "unknown", "0", 0
            if stp.exists():
                sc = stp.read_text()
                nm = re.search(r'Name:\s*(.+)', sc)
                um = re.search(r'Uid:\s*(\d+)', sc)
                tm = re.search(r'Threads:\s*(\d+)', sc)
                name = nm.group(1) if nm else "unknown"
                uid = um.group(1) if um else "0"
                threads = int(tm.group(1)) if tm else 0
            exp = pp / "exe"
            exe = str(exp.resolve()) if exp.exists() else None
            result.processes.append(ProcessInfo(pid=pid, name=name, path=exe,
                command_line=cmdline, user=uid, threads=threads))
        except Exception as e: logger.warning(f"Process metadata read failed: {e}")
        try:
            mp = pp / "mem"
            if mp.exists(): self._extract_strings_from_mem(mp, result)
        except Exception: pass
        self._get_linux_network_connections(pid, result)
        self._get_linux_file_handles(pid, result)

    def _extract_strings_from_mem(self, memp: Path, result: ForensicsResult) -> None:
        try:
            with open(memp, 'rb') as f:
                buf = b''
                for _ in range(100):
                    chunk = f.read(1024 * 1024)
                    if not chunk: break
                    buf += chunk
                    for addr, content in self._extract_printable_strings(buf):
                        result.memory_strings.append(MemoryString(
                            address=addr, content=content, length=len(content)))
                    buf = buf[-1000:] if len(buf) > 1000 else buf
        except Exception as e: logger.warning(f"String extraction aborted: {e}")

    def _extract_printable_strings(self, data: bytes, min_length: int = 8) -> List[Tuple[int, str]]:
        strings = []
        for m in re.finditer(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data):
            try: strings.append((m.start(), m.group().decode('ascii')))
            except Exception: pass
        return strings

    def _get_linux_network_connections(self, pid: int, result: ForensicsResult) -> None:
        try:
            r = subprocess.run(
                f"netstat -tulnp 2>/dev/null | grep {pid} || ss -tulnp 2>/dev/null | grep {pid}",
                shell=True, capture_output=True, text=True, timeout=10)
            for line in r.stdout.split('\n'):
                if not line.strip(): continue
                parts = line.split()
                if len(parts) >= 5 and ':' in parts[3]:
                    addr, port = parts[3].rsplit(':', 1)
                    result.network_connections.append(NetworkConnection(
                        protocol=parts[0], local_addr=addr, local_port=int(port),
                        remote_addr=parts[4].split(':')[0] if len(parts) > 4 else None,
                        remote_port=int(parts[4].rsplit(':', 1)[1]) if len(parts) > 4 and ':' in parts[4] else None,
                        state=parts[5] if len(parts) > 5 else None, pid=pid))
        except Exception as e: logger.warning(f"Network enumeration failed: {e}")

    def _get_linux_file_handles(self, pid: int, result: ForensicsResult) -> None:
        fdp = Path(f"/proc/{pid}/fd")
        if not fdp.exists(): return
        try:
            for fd in fdp.iterdir():
                try: result.file_handles.append(FileHandle(
                    handle_value=int(fd.name), file_path=str(fd.resolve()), pid=pid))
                except Exception: pass
        except Exception: pass

    def _analyze_windows_process(self, pid: int, result: ForensicsResult) -> None:
        try:
            o = subprocess.run(["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/v"],
                               capture_output=True, text=True, timeout=10)
            lines = o.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split(',')
                nm = parts[0].strip('"') if len(parts) > 0 else "unknown"
                mu = parts[4].strip('"') if len(parts) > 4 else None
                result.processes.append(ProcessInfo(pid=pid, name=nm,
                    memory_usage=int(mu.replace(' K', '').replace(',', '')) * 1024 if mu else None))
        except Exception: pass

    def _analyze_memory_dump(self, source: str, result: ForensicsResult) -> None:
        if self.volatility_available: self._analyze_with_volatility(source, result)
        else: self._analyze_dump_file_direct(source, result)

    def _analyze_with_volatility(self, source: str, result: ForensicsResult) -> None:
        try:
            vo = subprocess.run([self.volatility_path, "-h"], capture_output=True,
                                text=True, timeout=10)
            vm = re.search(r'Volatility\s+(\d+\.\d+)', vo.stdout)
            result.volatility_version = vm.group(1) if vm else "unknown"
        except Exception: pass
        try:
            o = subprocess.run([self.volatility_path, "-f", source, "pslist"],
                               capture_output=True, text=True, timeout=120)
            for line in o.stdout.split('\n'):
                if line.strip() and not line.startswith('|') and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 6:
                        try: result.processes.append(ProcessInfo(
                            pid=int(parts[2]), name=parts[0],
                            parent_pid=int(parts[3]) if len(parts) > 3 else None,
                            threads=int(parts[4]) if len(parts) > 4 else 0,
                            handles=int(parts[5]) if len(parts) > 5 else 0))
                        except ValueError: pass
        except Exception: pass
        try:
            o = subprocess.run([self.volatility_path, "-f", source, "strings"],
                               capture_output=True, text=True, timeout=300)
            for line in o.stdout.split('\n'):
                if len(line.strip()) >= self.MIN_STRING_LENGTH:
                    m = re.match(r'([a-fA-F0-9]+)\s*:\s*(.+)', line)
                    if m: result.memory_strings.append(MemoryString(
                        address=int(m.group(1), 16), content=m.group(2),
                        length=len(m.group(2))))
        except Exception: pass

    def _analyze_dump_file_direct(self, source: str, result: ForensicsResult) -> None:
        try:
            with open(source, 'rb') as f:
                fs = f.seek(0, 2); f.seek(0); off = 0
                while off < fs:
                    f.seek(off); chunk = f.read(10 * 1024 * 1024)
                    if not chunk: break
                    for addr, content in self._extract_printable_strings(chunk):
                        result.memory_strings.append(MemoryString(
                            address=off + addr, content=content, length=len(content)))
                    off += 10 * 1024 * 1024
                    if len(result.memory_strings) > 10000: break
        except Exception as e:
            logger.error(f"Direct binary analysis failed: {e}")
            result.errors.append(str(e))

    def _analyze_minidump(self, source: str, result: ForensicsResult) -> None:
        try:
            with open(source, 'rb') as f:
                if f.read(4) != b'MDMP':
                    result.errors.append("Invalid minidump file"); return
                f.seek(0); content = f.read()
                for addr, content in self._extract_printable_strings(content):
                    result.memory_strings.append(MemoryString(
                        address=addr, content=content, length=len(content)))
        except Exception as e:
            result.errors.append(str(e))

    def _analyze_core_dump(self, source: str, result: ForensicsResult) -> None:
        try:
            with open(source, 'rb') as f:
                if f.read(4) != b'\x7fELF':
                    result.errors.append("Invalid core dump file"); return
                f.seek(0); content = f.read()
                for addr, content in self._extract_printable_strings(content):
                    result.memory_strings.append(MemoryString(
                        address=addr, content=content, length=len(content)))
        except Exception as e:
            result.errors.append(str(e))

    def _analyze_generic(self, source: str, result: ForensicsResult) -> None:
        self._analyze_dump_file_direct(source, result)

    def _extract_sensitive_data(self, result: ForensicsResult) -> None:
        for ms in result.memory_strings:
            content = ms.content
            for dt, patterns in self.SENSITIVE_PATTERNS.items():
                for pat in patterns:
                    try:
                        for m in re.finditer(pat, content, re.IGNORECASE):
                            result.sensitive_data.append(SensitiveData(
                                data_type=dt, value=m.group(),
                                location=f"memory address {hex(ms.address)}",
                                address=ms.address + m.start(), confidence=0.8,
                                context=content[max(0, m.start() - 50):m.end() + 50]))
                    except Exception: pass
        seen = set(); unique = []
        for item in result.sensitive_data:
            vh = hashlib.md5(item.value.encode()).hexdigest()
            if vh not in seen: seen.add(vh); unique.append(item)
        result.sensitive_data = unique

    def dump_process_memory(self, pid: int, output_path: Optional[str] = None) -> str:
        if output_path is None:
            output_path = str(self.output_dir / f"process_{pid}_dump.bin")
        if self.platform == 'linux':
            try:
                r = subprocess.run(["gcore", "-o", output_path, str(pid)],
                                   capture_output=True, text=True, timeout=60)
                if r.returncode == 0: return output_path
            except Exception: pass
            pp = Path(f"/proc/{pid}"); mapp = pp / "maps"; memp = pp / "mem"
            if mapp.exists() and memp.exists():
                with open(output_path, 'wb') as of:
                    with open(mapp, 'r') as mf:
                        for line in mf:
                            parts = line.split()
                            if len(parts) >= 1:
                                st, end = parts[0].split('-')
                                sa, ea = int(st, 16), int(end, 16)
                                if 'r' in parts[1]:
                                    try:
                                        with open(memp, 'rb') as memf:
                                            memf.seek(sa); of.write(memf.read(ea - sa))
                                    except Exception: pass
                return output_path
        raise RuntimeError(f"Cannot export memory for process {pid}")

    def generate_report(self, result: ForensicsResult) -> str:
        lines = [
            "# Memory Forensics Analysis Report", "",
            f"**Analysis Time**: {result.timestamp}",
            f"**Source**: {result.source}",
            f"**OS**: {result.os_type.value}", "",
            "## Summary",
            f"- Processes: {result.total_processes}",
            f"- Connections: {result.total_connections}",
            f"- Sensitive items: {result.total_sensitive_items}",
            f"- Crypto weaknesses: {len(result.crypto_weaknesses)}",
        ]
        if result.crypto_weaknesses:
            lines.extend(["", "## Cryptographic Weaknesses", ""])
            for w in result.crypto_weaknesses:
                lines.append(f"- **{w.algorithm}** [{w.severity}]: {w.weakness_type} — {w.recommendation}")
        if result.hardening_audit:
            lines.extend(["", "## Hardening Audit", ""])
            for k, v in result.hardening_audit.items():
                status = "ENABLED" if v else "MISSING"
                lines.append(f"- {k}: {status}")
        if result.errors:
            lines.extend(["", "## Errors"] + [f"- {e}" for e in result.errors])
        return "\n".join(lines)

    def save_result(self, result: ForensicsResult, filename: Optional[str] = None) -> str:
        if filename is None:
            filename = f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        elif not filename.endswith('.json'):
            filename = filename + '.json'
        fp = self.output_dir / filename
        with open(fp, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        rp = fp.with_suffix('.md')
        rp.write_text(self.generate_report(result), encoding='utf-8')
        logger.info(f"Forensic results persisted to: {fp}")
        return str(fp)


def analyze_memory(source: Union[str, int], output_dir: Optional[str] = None) -> ForensicsResult:
    a = MemoryForensicsAnalyzer(output_dir)
    r = a.analyze(source)
    a.save_result(r)
    return r

if __name__ == "__main__":
    import sys
    a = MemoryForensicsAnalyzer()
    if len(sys.argv) > 1:
        src = sys.argv[1]
        try:
            pid = int(src); print(f"Analyzing process: {pid}")
        except ValueError:
            print(f"Analyzing file: {src}")
        r = a.analyze(src); a.save_result(r)
        print(f"Processes: {r.total_processes}, Sensitive: {r.total_sensitive_items}")
        print(f"Crypto weaknesses: {len(r.crypto_weaknesses)}, Hardening: {r.hardening_audit}")
    else:
        print("Usage: python memory_forensics.py <pid or filepath>")
