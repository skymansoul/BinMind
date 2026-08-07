# 漏洞验证沙箱
# PoC生成 + 受控执行 + 崩溃分类，确认漏洞可复现性
# 增强项：信号映射表补全SIGBUS/SIGFPE/SIGPIPE + 沙箱后端自动fallback检测

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import subprocess
import tempfile
import os
import time
import re
import shutil


class SandboxBackend(str, Enum):
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    GVISOR = "gvisor"


@dataclass
class VerificationResult:
    """单次漏洞验证执行结果。"""
    vulnerable: bool
    cve_id: str = ""
    vuln_type: str = ""
    crash_detected: bool = False
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    runtime_seconds: float = 0.0
    crash_type: str = ""       # 崩溃信号类型（SIGSEGV/SIGABRT/SIGILL等）
    crash_address: str = ""    # 崩溃地址（若可解析）
    sanitizer_output: str = ""  # ASAN/UBSAN检测输出内容
    poc_payload: str = ""
    details: Dict = field(default_factory=dict)


# PoC模板引擎

class PoCGenerator:
    """按漏洞类型生成测试payload。

    各类型payload均为经验证的最小可触发输入。
    仅做脆弱性确认，不生成完整exploit。
    """

    _TEMPLATES = {
        "buffer_overflow": "A" * 2048,  # 长A串触发栈/堆溢出
        "stack_overflow": "A" * 4096,
        "heap_overflow": "B" * 1024,
        "format_string": "%x." * 100 + "%n",
        "format_string_short": "%x%x%x%x%s%s%n%n",
        "command_injection": ";id;uname -a;pwd;whoami",
        "sql_injection": "' OR '1'='1' -- ",
        "sql_injection_blind": "' AND SLEEP(2) -- ",
        "xss": "<script>alert(1)</script>",
        "xss_reflected": "\"><img src=x onerror=alert(1)>",
        "path_traversal": "../../../../etc/passwd",
        "path_traversal_win": "..\\..\\..\\Windows\\System32\\config\\SAM",
        "null_deref": "",
        "integer_overflow": "2147483648",  # INT_MAX + 1
        "use_after_free": "A" * 16 + "\x00" * 16,
        "race_condition": "",  # 需并发测试，静态payload不可用
        "deserialization": '{"__class__":"os.system","args":"id"}',
        "ssrf": "http://169.254.169.254/latest/meta-data/",
        "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    }

    @classmethod
    def generate(cls, vuln_type: str, size: int = 0) -> str:
        """按漏洞类型生成PoC payload。"""
        vtype = vuln_type.lower().replace("-", "_").replace(" ", "_")
        # 精确匹配优先于模糊匹配
        if vtype in cls._TEMPLATES:
            payload = cls._TEMPLATES[vtype]
        else:
            # 模糊匹配——子串包含判断
            for key, val in cls._TEMPLATES.items():
                if key in vtype or vtype in key:
                    payload = val
                    break
            else:
                payload = "A" * 256  # 通用fuzz回退payload
        if size > 0 and isinstance(payload, str) and size > len(payload):
            payload = payload * (size // len(payload) + 1)
        return payload[:size] if size > 0 and size < len(payload) else payload

    @classmethod
    def generate_env(cls, vuln_type: str) -> Dict[str, str]:
        """生成特定漏洞类型对应的环境变量注入。"""
        env = {}
        if "overflow" in vuln_type.lower():
            env["MALLOC_CHECK_"] = "3"
            env["MALLOC_PERTURB_"] = "69"
        if "format" in vuln_type.lower():
            env["FORTIFY_SOURCE"] = "0"
        return env


# 崩溃分类

_CRASH_PATTERNS = [
    (re.compile(r'SIGSEGV|segmentation\s+fault|Segmentation fault', re.IGNORECASE), "SIGSEGV"),
    (re.compile(r'SIGABRT|aborted|Aborted', re.IGNORECASE), "SIGABRT"),
    (re.compile(r'SIGILL|illegal\s+(instruction|hardware)', re.IGNORECASE), "SIGILL"),
    (re.compile(r'SIGBUS|bus\s+error', re.IGNORECASE), "SIGBUS"),
    (re.compile(r'SIGFPE|floating\s+point\s+exception|division by zero', re.IGNORECASE), "SIGFPE"),
    (re.compile(r'SIGPIPE|broken\s+pipe', re.IGNORECASE), "SIGPIPE"),
    (re.compile(r'stack\s+smashing|stack\s+buffer\s+overflow|__stack_chk_fail', re.IGNORECASE), "STACK_SMASHING"),
    (re.compile(r'double\s+free|invalid\s+pointer|corrupted\s+double-linked', re.IGNORECASE), "HEAP_CORRUPTION"),
    (re.compile(r'AddressSanitizer|ASAN|heap-buffer-overflow|stack-buffer-overflow|use-after-free', re.IGNORECASE), "ASAN_DETECTED"),
    (re.compile(r'UndefinedBehaviorSanitizer|UBSAN|signed integer overflow', re.IGNORECASE), "UBSAN_DETECTED"),
    (re.compile(r'Address Boundary Error', re.IGNORECASE), "ADDRESS_BOUNDARY"),
]

_CRASH_ADDR_RE = re.compile(r'(?:at|address)\s+(0x[0-9a-fA-F]+)', re.IGNORECASE)


def analyze_crash(stderr: str, exit_code: int) -> Tuple[str, str]:
    """从stderr与退出码推断崩溃类型。

    返回 (崩溃类型, 崩溃地址)。
    相比简单signum检查，可识别ASAN/UBSAN加固检测输出。
    """
    if exit_code == 0 and not stderr.strip():
        return "NO_CRASH", ""
    crash_type = "UNKNOWN"
    crash_addr = ""
    for pattern, ctype in _CRASH_PATTERNS:
        if pattern.search(stderr):
            crash_type = ctype
            break
    if crash_type == "UNKNOWN" and exit_code != 0:
        signum_map = {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL",
                      -7: "SIGBUS", -8: "SIGFPE", -13: "SIGPIPE"}
        crash_type = signum_map.get(exit_code, f"SIGNAL_{abs(exit_code)}")
    addr_match = _CRASH_ADDR_RE.search(stderr)
    if addr_match:
        crash_addr = addr_match.group(1)
    return crash_type, crash_addr


# 沙箱执行器

class SandboxRunner:
    """受控环境执行二进制+payload，捕获崩溃信息。

    支持subprocess/docker/gvisor三种后端。
    docker/gvisor需宿主机预装对应运行时。
    """

    def __init__(self, backend: SandboxBackend = SandboxBackend.SUBPROCESS,
                 timeout: int = 10):
        self.backend = backend
        self.timeout = timeout
        self._check_deps()

    def _check_deps(self):
        if self.backend == SandboxBackend.DOCKER:
            if not shutil.which("docker"):
                self.backend = SandboxBackend.SUBPROCESS
        elif self.backend == SandboxBackend.GVISOR:
            if not shutil.which("runsc"):
                self.backend = SandboxBackend.DOCKER if shutil.which("docker") else SandboxBackend.SUBPROCESS

    def run(self, binary_path: str, args: List[str] = None,
            stdin_input: str = "", env: Dict[str, str] = None) -> VerificationResult:
        """沙箱内执行二进制并收集执行结果。"""
        start_time = time.time()
        cmd = self._build_command(binary_path, args or [])
        result = VerificationResult(vulnerable=False)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout,
                input=stdin_input if stdin_input else None,
                env={**os.environ, **(env or {})} if env else None,
            )
            result.exit_code = proc.returncode
            result.stdout = proc.stdout or ""
            result.stderr = proc.stderr or ""
            result.runtime_seconds = round(time.time() - start_time, 3)
            result.crash_detected = proc.returncode != 0
            result.crash_type, result.crash_address = analyze_crash(
                result.stderr, result.exit_code)
            result.vulnerable = result.crash_detected or bool(
                result.crash_type != "NO_CRASH")
        except subprocess.TimeoutExpired:
            result.exit_code = -1
            result.stderr = "TIMEOUT"
            result.runtime_seconds = self.timeout
            result.crash_detected = False
        except FileNotFoundError:
            result.exit_code = -2
            result.stderr = "BINARY_NOT_FOUND"
        except Exception as e:
            result.exit_code = -3
            result.stderr = str(e)

        return result

    def _build_command(self, binary_path: str, args: List[str]) -> List[str]:
        if self.backend == SandboxBackend.DOCKER:
            return [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", "256m",
                "--cpus", "1",
                "--pids-limit", "50",
                "-v", f"{os.path.dirname(binary_path)}:/target:ro",
                "alpine:latest",
                f"/target/{os.path.basename(binary_path)}",
            ] + args
        elif self.backend == SandboxBackend.GVISOR:
            return [
                "runsc", "--network=none", "run",
                binary_path,
            ] + args
        else:
            return [binary_path] + args


# 验证流程

def verify_vulnerability(binary_path: str, cve_id: str = "",
                         vuln_type: str = "buffer_overflow",
                         backend: SandboxBackend = SandboxBackend.SUBPROCESS,
                         custom_payload: str = "",
                         timeout: int = 10) -> VerificationResult:
    """单次漏洞验证完整流程：

    1. 生成对应类型PoC payload
    2. 沙箱中执行二进制
    3. 分析stderr/exit_code进行崩溃分类
    4. 返回VerificationResult
    """
    runner = SandboxRunner(backend=backend, timeout=timeout)
    payload = custom_payload or PoCGenerator.generate(vuln_type)
    env = PoCGenerator.generate_env(vuln_type)

    result = runner.run(binary_path, stdin_input=payload, env=env)
    result.cve_id = cve_id
    result.vuln_type = vuln_type
    result.poc_payload = payload[:200]

    # 检测到崩溃即判定为脆弱
    if result.crash_detected:
        result.vulnerable = True

    return result


def batch_verify(binary_path: str, vuln_list: List[Dict],
                 backend: SandboxBackend = SandboxBackend.SUBPROCESS) -> List[VerificationResult]:
    """批量验证多个漏洞——每个漏洞尝试3种payload变体。"""
    results = []
    for v in vuln_list:
        cid = v.get("cve_id", v.get("id", ""))
        vtype = v.get("type", v.get("vuln_type", "buffer_overflow"))
        res = verify_vulnerability(binary_path, cve_id=cid, vuln_type=vtype,
                                   backend=backend, timeout=v.get("timeout", 10))
        if not res.vulnerable and vtype in ("buffer_overflow", "stack_overflow"):
            res = verify_vulnerability(binary_path, cve_id=cid, vuln_type="format_string",
                                       backend=backend)
        if not res.vulnerable:
            res = verify_vulnerability(binary_path, cve_id=cid, vuln_type=vtype,
                                       custom_payload=PoCGenerator.generate(vtype, 8192),
                                       backend=backend)
        results.append(res)
    return results


def crash_report(result: VerificationResult) -> str:
    """生成崩溃报告文本。"""
    lines = [
        f"=== Crash Report: {result.cve_id or 'unknown'} ===",
        f"  Type       : {result.crash_type}",
        f"  Exit Code  : {result.exit_code}",
        f"  Address    : {result.crash_address or 'N/A'}",
        f"  Runtime    : {result.runtime_seconds}s",
        f"  Payload    : {result.poc_payload[:80]}...",
    ]
    if result.sanitizer_output:
        lines.append(f"  Sanitizer  : {result.sanitizer_output[:200]}")
    return "\n".join(lines)
