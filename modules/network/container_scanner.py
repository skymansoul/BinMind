"""容器镜像扫描器——Dockerfile分析与CVE攻击面映射。"""
import hashlib
import json, logging, os, re, subprocess, tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

_VERSION_HINT = (2, 1, 4)

try:
    import docker  # noqa: F401
    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


_log = logging.getLogger(__name__)


BINARY_SIGNATURES = {
    'ELF': [b'\x7fELF'],
    'PE': [b'MZ'],
    'MACH_O': [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'],
}

# 常见危险库
DANGEROUS_LIBRARIES = {
    'openssl': {'cve_prefix': 'CVE-2022-', 'risk': 'High'},
    'libssl': {'cve_prefix': 'CVE-2022-', 'risk': 'High'},
    'glibc': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'libc': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'bash': {'cve_prefix': 'CVE-2019-', 'risk': 'Medium'},
    'curl': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'libcurl': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'ssh': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'openssh': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'sudo': {'cve_prefix': 'CVE-2021-', 'risk': 'Critical'},
    'nginx': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'apache': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'httpd': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
    'redis': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'mysql': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'postgres': {'cve_prefix': 'CVE-2023-', 'risk': 'High'},
    'python': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'java': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'node': {'cve_prefix': 'CVE-2023-', 'risk': 'Medium'},
    'php': {'cve_prefix': 'CVE-2024-', 'risk': 'High'},
}

# 路径遍历防护
PATH_TRAVERSAL_PATTERNS = [
    '..',
    '/../',
    '\\..\\',
    '/..',
    '..\\',
]

_DANGEROUS_INSTRUCTIONS = [
    re.compile(r"^\s*ADD\s+(https?://[^\s]+)\s", re.I),
    re.compile(r"^\s*COPY\s+--from=([^\s:]+)(?![^\s]*@sha256:)", re.I),
    re.compile(r"(curl|wget)\s+.*\|\s*(ba)?sh\b", re.I),
    re.compile(r"chmod\s+([0-7]*7[0-7]*7[0-7]*)\s", re.I),
    re.compile(r"^\s*ENV\s+\w*SECRET\w*\s*=", re.I),
    re.compile(r"^\s*ENV\s+\w*PASSWORD\w*\s*=", re.I),
    re.compile(r"^\s*ENV\s+\w*TOKEN\w*\s*=", re.I),
]

_DANGEROUS_RUN_FLAGS = {
    "--privileged": "Container runs with full host privileges",
    "--cap-add=SYS_ADMIN": "SYS_ADMIN capability added (near-root)",
    "--cap-add=SYS_PTRACE": "SYS_PTRACE capability added",
    "--cap-add=NET_RAW": "NET_RAW capability added",
    "--cap-add=ALL": "All capabilities added",
    "--pid=host": "Shares host PID namespace",
    "--network=host": "Shares host network namespace",
    "--ipc=host": "Shares host IPC namespace",
    "--security-opt=seccomp:unconfined": "Seccomp disabled",
    "--security-opt=apparmor:unconfined": "AppArmor disabled",
}

_BASE_IMAGE_CVE_PATTERNS = {
    "alpine:<3.15": {"CVE-2022-0778": 7.5, "CVE-2022-28391": 8.1},
    "alpine:<3.16": {"CVE-2022-37434": 9.8, "CVE-2023-0215": 7.5},
    "alpine:<3.17": {"CVE-2023-2650": 7.5, "CVE-2023-5363": 7.5},
    "ubuntu:<20.04": {"CVE-2023-38408": 9.8, "CVE-2023-4016": 7.8},
    "ubuntu:<22.04": {"CVE-2023-4911": 7.8, "CVE-2024-2961": 8.8},
    "debian:<11": {"CVE-2024-33599": 7.8, "CVE-2023-45871": 8.1},
    "python:<3.8": {"CVE-2023-27043": 6.5, "CVE-2023-40217": 7.5},
    "python:<3.9": {"CVE-2023-27043": 6.5},
    "node:<16": {"CVE-2023-30577": 7.8, "CVE-2024-22019": 8.2},
    "node:<18": {"CVE-2023-38552": 7.5, "CVE-2024-27980": 8.1},
}

# 供应链风险模式
# 检测非官方注册中心使用、curl|sh模式、拼写仿冒向量
_SUPPLY_CHAIN_RISK = [
    re.compile(r"(pip|pip3)\s+install\s+.*--extra-index-url", re.I),
    re.compile(r"(npm|yarn)\s+install\s+.*--registry\s+https?://(?!registry\.npmjs)", re.I),
    re.compile(r"(gem\s+install|bundle\s+install).*--source\s+https?://(?!rubygems)", re.I),
    re.compile(r"curl\s+.*\|\s*(?:python|perl|ruby)", re.I),
    re.compile(r"wget\s+.*-O\s*-\s*\|\s*(?:python|perl|ruby)", re.I),
]

@dataclass
class BinaryFileInfo:
    path: str = ''
    layer_id: str = ''
    file_type: str = ''
    size: int = 0
    sha256: str = ''
    hash_sha256: str = ''
    permissions: str = ''
    is_executable: bool = False
    setuid: bool = False
    capabilities: List[str] = field(default_factory=list)
    analysis_result: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class LayerInfo:
    layer_id: str = ''
    digest: str = ''
    size: int = 0
    command: str = ''
    author: str = ''
    created: str = ''
    index: int = 0
    instruction: str = ''
    files: List[str] = field(default_factory=list)
    binaries: List[Dict[str, Any]] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    libraries: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = 'Unknown'
    metadata: Dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0

@dataclass
class Finding:
    severity: str; category: str; title: str; description: str
    line: int = 0; cve_id: str = ""; cvss_score: float = 0.0

@dataclass
class ContainerSecurityReport:
    image_name: str = ''
    total_layers: int = 0
    total_binaries: int = 0
    total_vulnerabilities: int = 0
    critical_layers: List[str] = field(default_factory=list)
    high_risk_binaries: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    layers: List[LayerInfo] = field(default_factory=list)
    libraries_summary: Dict[str, Any] = field(default_factory=dict)
    analysis_time: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)
    image: str = ''
    base_image: str = ''
    findings: List[Finding] = field(default_factory=list)
    base_cves: List[Finding] = field(default_factory=list)

    def summary(self) -> Dict:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings + self.base_cves: counts[f.severity] += 1
        return {"image": self.image, "base_image": self.base_image,
                "total_findings": len(self.findings)+len(self.base_cves),
                "by_severity": dict(counts),
                "critical_cves": [f.cve_id for f in self.base_cves if f.severity == "CRITICAL"]}

class ContainerImageScanner:
    def __init__(self, trivy_path: Optional[str] = None, image_source: str = ''):
        self._trivy = trivy_path or "trivy"
        self.image_source = image_source

    def _is_safe_path(self, path: str) -> bool:
        """检查路径是否安全（防止路径遍历）。"""
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in path:
                return False
        return True

    def _identify_binary_file(self, full_path: str, rel_path: str, layer_id: str) -> Optional[BinaryFileInfo]:
        """识别单个二进制文件；无法匹配已知签名时返回 None。"""
        try:
            with open(full_path, 'rb') as f:
                header = f.read(16)

            if len(header) < 4:
                return None

            file_type = None
            for sig_type, signatures in BINARY_SIGNATURES.items():
                for sig in signatures:
                    if header.startswith(sig):
                        file_type = sig_type
                        break
                if file_type:
                    break

            if not file_type:
                return None

            size = os.path.getsize(full_path)
            sha256 = hashlib.sha256()
            with open(full_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)

            return BinaryFileInfo(
                path=rel_path,
                layer_id=layer_id,
                file_type=file_type,
                size=size,
                hash_sha256=sha256.hexdigest(),
            )
        except OSError:
            return None

    def scan(self, image: str) -> ContainerSecurityReport:
        report = ContainerSecurityReport(); report.image = image
        report.image_name = image
        if os.path.isfile(image): report = self._scan_dockerfile(image, report)
        report.base_cves = self._check_base_image_cves(report.base_image, image)
        return report

    def _scan_dockerfile(self, path: str, report: ContainerSecurityReport) -> ContainerSecurityReport:
        with open(path, "r", encoding="utf-8", errors="replace") as fh: lines = fh.readlines()
        for idx, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"): continue
            m = re.match(r"^\s*FROM\s+(\S+)", stripped, re.I)
            if m: report.base_image = m.group(1)
            # 危险指令模式
            for pat in _DANGEROUS_INSTRUCTIONS:
                if pat.search(stripped):
                    report.findings.append(Finding(severity="HIGH",
                        category="dangerous_instruction",
                        title=f"Dangerous pattern in line {idx}",
                        description=stripped[:120], line=idx)); break
            # docker run 标志
            for flag, desc in _DANGEROUS_RUN_FLAGS.items():
                if f" {flag}" in stripped or stripped.startswith(flag):
                    report.findings.append(Finding(severity="HIGH",
                        category="dangerous_flag", title=desc,
                        description=f"Flag `{flag}` in line {idx}", line=idx))
            # 供应链风险
            for pat in _SUPPLY_CHAIN_RISK:
                if pat.search(stripped):
                    report.findings.append(Finding(severity="CRITICAL",
                        category="supply_chain_risk",
                        title="Untrusted package source or pipe-to-interpreter",
                        description=stripped[:120], line=idx))
        return report

    def _check_base_image_cves(self, base: str, image_ref: str) -> List[Finding]:
        if not base: return []
        findings: List[Finding] = []; base_lower = base.lower()
        for pat_spec, cves in _BASE_IMAGE_CVE_PATTERNS.items():
            prefix, _, ver = pat_spec.partition(":")
            if prefix in base_lower and ver and ver.startswith("<"):
                desired = ver[1:]; parts = re.findall(r"\d+", base_lower)
                if parts and tuple(int(p) for p in parts) < tuple(int(d) for d in desired.split(".")):
                    for cve_id, cvss in cves.items():
                        findings.append(Finding(
                            severity="CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else "MEDIUM"),
                            category="base_image_cve", title=f"{cve_id} in {pat_spec}",
                            description=f"{cve_id} (CVSS {cvss}) affects {base}",
                            cve_id=cve_id, cvss_score=cvss))
        return findings

    def _run_trivy(self, image_ref: str) -> List[Dict]:
        try:
            proc = subprocess.run([self._trivy, "image", "--format", "json",
                "--severity", "HIGH,CRITICAL", image_ref],
                capture_output=True, text=True, timeout=120)
            if proc.returncode != 0: return []
            data = json.loads(proc.stdout); vulns = []
            for r in data.get("Results", []):
                for v in r.get("Vulnerabilities", []):
                    vulns.append({"id": v.get("VulnerabilityID"),
                        "severity": v.get("Severity"), "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion")})
            return vulns
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            _log.debug("Trivy scan skipped: %s", exc); return []

