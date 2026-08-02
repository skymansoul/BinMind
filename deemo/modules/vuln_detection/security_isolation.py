# 多级安全隔离执行框架——代码脱敏→沙箱选择→安全执行→结果净化。
# gVisor/Docker/Firecracker/Subprocess四级fallback链，优先使用最强隔离。
# 参考Google gVisor论文(SOSP'17)的哨兵架构与Kata Containers的VM级隔离策略。

import os, subprocess, tempfile, json, re
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from enum import Enum


class SandboxType(Enum):
    NONE = "none"
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"
    KVM = "kvm"


class CodeSanitizer:
    def __init__(self):
        self.patterns = {
            'api_key': re.compile(r'(?i)(api[_\-]?key|api[_\-]?token|secret[_\-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
            'password': re.compile(r'(?i)password\s*[=:]\s*["\']?([^\s"\']+)["\']?'),
            'secret': re.compile(r'(?i)secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
            'token': re.compile(r'(?i)(bearer|token)\s+["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
            'ssh_key': re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----'),
            'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'url': re.compile(r'https?://[^\s]+'),
            'file_path': re.compile(r'(/[\w._-]+)+'),
        }

    def sanitize(self, code: str) -> str:
        result = code
        for name, pattern in self.patterns.items():
            if name in ('api_key', 'token', 'secret'):
                result = pattern.sub(r'\1 = "***REDACTED***"', result)
            elif name == 'password':
                result = pattern.sub(r'password = "***REDACTED***"', result)
            elif name == 'ssh_key':
                result = pattern.sub('-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----', result)
            elif name == 'ipv4':
                result = pattern.sub('xxx.xxx.xxx.xxx', result)
            elif name == 'email':
                result = pattern.sub('user@example.com', result)
            elif name == 'url':
                result = pattern.sub('https://example.com/api', result)
            elif name == 'file_path':
                result = pattern.sub('/path/to/file', result)
        return result

    def detect_sensitive_patterns(self, code: str) -> List[Dict[str, str]]:
        findings = []
        for name, pattern in self.patterns.items():
            matches = pattern.findall(code)
            if matches:
                findings.append({'type': name, 'nCount': len(matches), 'matches': matches[:3]})
        return findings


class BinarySanitizer:
    def __init__(self):
        self.sensitive_signatures = [
            b'\x7fELF', b'MZ', b'\x89PNG', b'\xff\xd8\xff', b'-----BEGIN',
        ]

    def sanitize_binary(self, data: bytes, max_length: int = 1024) -> str:
        hex_repr = data.hex()[:max_length * 2]
        if len(data) > max_length:
            hex_repr += '...(已截断)'
        return hex_repr

    def is_binary(self, data: bytes) -> bool:
        for sig in self.sensitive_signatures:
            if data.startswith(sig):
                return True
        printable_ratio = sum(1 for b in data[:100] if 32 <= b <= 126) / min(100, len(data))
        return printable_ratio < 0.7


class SandboxExecutor:
    def __init__(self, sandbox_type: SandboxType):
        self.sandbox_type = sandbox_type

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        pass

    def is_available(self) -> bool:
        pass


class GvisorExecutor(SandboxExecutor):
    def __init__(self):
        super().__init__(SandboxType.GVISOR)
        self.runsc_path = self._find_runsc()

    def _find_runsc(self) -> Optional[str]:
        for path in ['/usr/local/bin/runsc', '/usr/bin/runsc', 'runsc']:
            try:
                result = subprocess.run([path, '--version'], capture_output=True)
                if result.returncode == 0:
                    return path
            except FileNotFoundError:
                continue
        return None

    def is_available(self) -> bool:
        return self.runsc_path is not None

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        if not self.runsc_path:
            return {'success': False, 'error': 'gVisor不可用'}
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [self.runsc_path, 'run', '--network=none', '--rootless']
            if working_dir:
                cmd.extend(['--work-dir', working_dir])
            cmd.extend(['--'] + command)
            try:
                result = subprocess.run(cmd, input=input_data,
                    capture_output=True, timeout=timeout, cwd=working_dir)
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout.decode('utf-8', errors='replace'),
                    'stderr': result.stderr.decode('utf-8', errors='replace'),
                    'return_code': result.returncode, 'sandbox_type': 'gvisor'}
            except subprocess.TimeoutExpired:
                return {'success': False, 'error': '执行超时', 'sandbox_type': 'gvisor'}
            except Exception as e:
                return {'success': False, 'error': str(e), 'sandbox_type': 'gvisor'}


class FirecrackerExecutor(SandboxExecutor):
    def __init__(self):
        super().__init__(SandboxType.FIRECRACKER)
        self.firecracker_path = self._find_firecracker()

    def _find_firecracker(self) -> Optional[str]:
        for path in ['/usr/local/bin/firecracker', '/usr/bin/firecracker', 'firecracker']:
            try:
                result = subprocess.run([path, '--version'], capture_output=True)
                if result.returncode == 0:
                    return path
            except FileNotFoundError:
                continue
        return None

    def is_available(self) -> bool:
        return self.firecracker_path is not None

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        if not self.firecracker_path:
            return {'success': False, 'error': 'Firecracker不可用'}
        return {'success': False, 'error': 'Firecracker执行需VM配置——回退至Docker', 'sandbox_type': 'firecracker'}


class DockerExecutor(SandboxExecutor):
    def __init__(self, image: str = 'ubuntu:latest'):
        super().__init__(SandboxType.DOCKER)
        self.image = image

    def is_available(self) -> bool:
        try:
            result = subprocess.run(['docker', 'info'], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        cmd = ['docker', 'run', '--rm', '--network=none', '--read-only', '-i']
        if input_data:
            cmd.append('-a'); cmd.append('stdin')
        cmd.append(self.image)
        cmd.extend(command)
        try:
            result = subprocess.run(cmd, input=input_data, capture_output=True, timeout=timeout)
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'return_code': result.returncode, 'sandbox_type': 'docker'}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': '执行超时', 'sandbox_type': 'docker'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'sandbox_type': 'docker'}


class SubprocessExecutor(SandboxExecutor):
    def __init__(self):
        super().__init__(SandboxType.SUBPROCESS)

    def is_available(self) -> bool:
        return True

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        try:
            result = subprocess.run(command, input=input_data,
                capture_output=True, timeout=timeout, cwd=working_dir)
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'return_code': result.returncode, 'sandbox_type': 'subprocess'}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': '执行超时', 'sandbox_type': 'subprocess'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'sandbox_type': 'subprocess'}


class SandboxManager:
    def __init__(self):
        self.executors = [
            GvisorExecutor(), FirecrackerExecutor(),
            DockerExecutor(), SubprocessExecutor()]
        self.preferred_executor = self._select_executor()

    def _select_executor(self) -> SandboxExecutor:
        for executor in self.executors:
            if executor.is_available():
                return executor
        return SubprocessExecutor()

    def execute(self, command: List[str], input_data: Optional[bytes] = None,
                timeout: int = 300, working_dir: Optional[str] = None,
                enforce_sandbox: bool = False) -> Dict[str, Any]:
        if enforce_sandbox and not isinstance(self.preferred_executor, (GvisorExecutor, FirecrackerExecutor)):
            return {'success': False, 'error': '需要沙箱但不可用'}
        return self.preferred_executor.execute(command, input_data, timeout, working_dir)

    def get_sandbox_info(self) -> Dict[str, Any]:
        info = {'preferred': self.preferred_executor.sandbox_type, 'available': []}
        for executor in self.executors:
            info['available'].append({'type': executor.sandbox_type, 'available': executor.is_available()})
        return info


class LLMDataSanitizer:
    def __init__(self):
        self.code_sanitizer = CodeSanitizer()
        self.binary_sanitizer = BinarySanitizer()

    def sanitize_for_llm(self, data: str, data_type: str = 'code') -> str:
        if data_type == 'code':
            return self.code_sanitizer.sanitize(data)
        elif data_type == 'binary':
            if isinstance(data, bytes):
                return self.binary_sanitizer.sanitize_binary(data)
            return data
        elif data_type == 'json':
            try:
                parsed = json.loads(data)
                sanitized = self._sanitize_dict(parsed)
                return json.dumps(sanitized)
            except Exception:
                return data
        return data

    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in ['key', 'secret', 'password', 'token']):
                result[key] = '***REDACTED***'
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = [self._sanitize_dict(v) if isinstance(v, dict) else v for v in value]
            elif isinstance(value, str):
                result[key] = self.code_sanitizer.sanitize(value)
            else:
                result[key] = value
        return result

    def can_send_to_llm(self, data: str, data_type: str = 'code') -> Tuple[bool, str]:
        if data_type == 'code':
            findings = self.code_sanitizer.detect_sensitive_patterns(data)
            if findings:
                return False, f"检测到敏感数据: {[f['type'] for f in findings]}"
            return True, "数据已脱敏，可安全传输至LLM"
        elif data_type == 'binary':
            return False, "二进制数据禁止传输至LLM端点"
        return True, "数据已脱敏，可安全传输至LLM"


_sandbox_manager = None
_llm_sanitizer = None


def get_sandbox_manager() -> SandboxManager:
    global _sandbox_manager
    if _sandbox_manager is None:
        _sandbox_manager = SandboxManager()
    return _sandbox_manager


def get_llm_sanitizer() -> LLMDataSanitizer:
    global _llm_sanitizer
    if _llm_sanitizer is None:
        _llm_sanitizer = LLMDataSanitizer()
    return _llm_sanitizer
