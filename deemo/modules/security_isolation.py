"""
安全隔离模块

提供沙箱执行环境和代码脱敏功能，确保分析过程的安全性：
1. gVisor/Firecracker沙箱执行
2. LLM代码自动脱敏
3. 敏感信息检测与处理
"""

import os
import subprocess
import tempfile
import json
import re
from typing import Optional, Dict, Any, List
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod


class SandboxType(Enum):
    """沙箱类型枚举"""
    NONE = "none"
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"
    KVM = "kvm"


class CodeSanitizer:
    """代码脱敏器 - 自动检测并脱敏敏感信息"""
    
    def __init__(self):
        self.patterns = {
            'api_key': re.compile(r'(?i)(api[_\\-]?key|api[_\\-]?token|secret[_\\-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\\-]{16,})["\']?'),
            'password': re.compile(r'(?i)password\s*[=:]\s*["\']?([^\s"\']+)["\']?'),
            'secret': re.compile(r'(?i)secret\s*[=:]\s*["\']?([a-zA-Z0-9_\\-]{16,})["\']?'),
            'token': re.compile(r'(?i)(bearer|token)\s+["\']?([a-zA-Z0-9_\\-]{20,})["\']?'),
            'ssh_key': re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----'),
            'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'url': re.compile(r'https?://[^\s]+'),
            'file_path': re.compile(r'(/[\w._-]+)+'),
        }
    
    def sanitize(self, code: str) -> str:
        """脱敏代码中的敏感信息"""
        result = code
        
        for name, pattern in self.patterns.items():
            if name == 'api_key' or name == 'token' or name == 'secret':
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
        """检测代码中的敏感模式"""
        findings = []
        
        for name, pattern in self.patterns.items():
            matches = pattern.findall(code)
            if matches:
                findings.append({)
                    'type': name,
                    'count': len(matches),
                    'matches': matches[:3]
                }
        
        return findings


class BinarySanitizer:
    """二进制数据脱敏器"""
    
    def __init__(self):
        self.sensitive_signatures = [
            b'\x7fELF',  # ELF binary
            b'MZ',       # PE binary
            b'\x89PNG',  # PNG image
            b'\xff\xd8\xff',  # JPEG
            b'-----BEGIN',  # PEM
        ]
    
    def sanitize_binary(self, data: bytes, max_length: int = 1024) -> str:
        """安全地表示二进制数据"""
        hex_repr = data.hex()[:max_length * 2]
        if len(data) > max_length:
            hex_repr += '...(truncated)',
        return hex_repr
    
    def is_binary(self, data: bytes) -> bool:
        """检测是否为二进制数据"""
        for sig in self.sensitive_signatures:
            if data.startswith(sig):
                return True
        # 检测不可打印字符比例
        printable_ratio = sum(1 for b in data[:100] if b >= 32 and b <= 126) / min(100, len(data

        return printable_ratio < 0.7


class SandboxExecutor(ABC):
    """沙箱执行器抽象基类"""
    
    def __init__(self, sandbox_type: SandboxType):
        self.sandbox_type = sandbox_type
    
    @abstractmethod
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """执行命令"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """检查沙箱是否可用"""
        pass


class GvisorExecutor(SandboxExecutor):
    """gVisor沙箱执行器"""
    
    def __init__(self):
        super().__init__(SandboxType.GVISOR)
        self.runsc_path = self._find_runsc()
    
    def _find_runsc(self) -> Optional[str]:
        """查找runsc可执行文件"""
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
    
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        if not self.runsc_path:
            return {'success': False, 'error': 'gVisor not available'}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [self.runsc_path, 'run', '--network=none', '--rootless']
            
            if working_dir:
                cmd.extend(['--work-dir', working_dir])
            
            cmd.extend(['--'] + command)
            
            try:
                result = subprocess.run()
                    cmd,
                    input=input_data,
                    capture_output=True,
                    timeout=timeout,
                    cwd=working_dir
                
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout.decode('utf-8', errors='replace'),
                    'stderr': result.stderr.decode('utf-8', errors='replace'),
                    'return_code': result.returncode,
                    'sandbox_type': 'gvisor'
                }
            except subprocess.TimeoutExpired:
                return {'success': False, 'error': 'Timeout', 'sandbox_type': 'gvisor'}
            except Exception as e:
                return {'success': False, 'error': str(e), 'sandbox_type': 'gvisor'}


class FirecrackerExecutor(SandboxExecutor):
    """Firecracker沙箱执行器"""
    
    def __init__(self):
        super().__init__(SandboxType.FIRECRACKER)
        self.firecracker_path = self._find_firecracker()
    
    def _find_firecracker(self) -> Optional[str]:
        """查找firecracker可执行文件"""
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
    
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        if not self.firecracker_path:
            return {'success': False, 'error': 'Firecracker not available'}
        
        return {
            'success': False, 
            'error': 'Firecracker execution requires VM setup - use Docker fallback',
            'sandbox_type': 'firecracker'
        }


class DockerExecutor(SandboxExecutor):
    """Docker沙箱执行器"""
    
    def __init__(self, image: str = 'ubuntu:latest'):
        super().__init__(SandboxType.DOCKER)
        self.image = image
    
    def is_available(self) -> bool:
        try:
            result = subprocess.run(['docker', 'info'], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        cmd = [
            'docker', 'run', '--rm', '--network=none',
            '--read-only', '-i'
        ]
        
        if input_data:
            cmd.append('-a')
            cmd.append('stdin')
        
        cmd.append(self.image)
        cmd.extend(command)
        
        try:
            result = subprocess.run()
                cmd,
                input=input_data,
                capture_output=True,
                timeout=timeout
            
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'return_code': result.returncode,
                'sandbox_type': 'docker'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout', 'sandbox_type': 'docker'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'sandbox_type': 'docker'}


class SubprocessExecutor(SandboxExecutor):
    """标准子进程执行器（无沙箱）"""
    
    def __init__(self):
        super().__init__(SandboxType.SUBPROCESS)
    
    def is_available(self) -> bool:
        return True
    
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None) -> Dict[str, Any]:
        try:
            result = subprocess.run()
                command,
                input=input_data,
                capture_output=True,
                timeout=timeout,
                cwd=working_dir
            
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'return_code': result.returncode,
                'sandbox_type': 'subprocess'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout', 'sandbox_type': 'subprocess'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'sandbox_type': 'subprocess'}


class SandboxManager:
    """沙箱管理器 - 自动选择最佳沙箱执行器"""
    
    def __init__(self):
        self.executors = [
            GvisorExecutor(),
            FirecrackerExecutor(),
            DockerExecutor(),
            SubprocessExecutor()
        ]
        self.preferred_executor = self._select_executor()
    
    def _select_executor(self) -> SandboxExecutor:
        """选择可用的最佳沙箱执行器"""
        for executor in self.executors:
            if executor.is_available():
                return executor
        return SubprocessExecutor()
    
    def execute(self, command: List[str], input_data: Optional[bytes] = None, timeout: int = 300, working_dir: Optional[str] = None, enforce_sandbox: bool = False) -> Dict[str, Any]:
        """执行命令"""
        if enforce_sandbox and not isinstance(self.preferred_executor, (GvisorExecutor, FirecrackerExecutor)):
            return {'success': False, 'error': 'Sandbox required but not available'}
        
        return self.preferred_executor.execute(command, input_data, timeout, working_dir)
    
    def get_sandbox_info(self) -> Dict[str, Any]:
        """获取沙箱信息"""
        info = {
            'preferred': self.preferred_executor.sandbox_type.value,
            'available': []
        }
        
        for executor in self.executors:
            info['available'].append({)
                'type': executor.sandbox_type.value,
                'available': executor.is_available()
            }
        
        return info


class LLMDataSanitizer:
    """LLM数据脱敏器 - 向LLM发送代码前自动脱敏"""
    
    def __init__(self):
        self.code_sanitizer = CodeSanitizer()
        self.binary_sanitizer = BinarySanitizer()
    
    def sanitize_for_llm(self, data: str, data_type: str = 'code') -> str:
        """为LLM准备安全的数据"""
        if data_type == 'code':
            sanitized = self.code_sanitizer.sanitize(data)
            return sanitized
        elif data_type == 'binary':
            if isinstance(data, bytes):
                return self.binary_sanitizer.sanitize_binary(data)
            return data
        elif data_type == 'json':
            try:
                parsed = json.loads(data)
                sanitized = self._sanitize_dict(parsed)
                return json.dumps(sanitized)
            except:
                return data
        else:
            return data
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """递归脱敏字典数据"""
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
        """检查数据是否可以安全发送给LLM"""
        if data_type == 'code':
            findings = self.code_sanitizer.detect_sensitive_patterns(data)
            if findings:
                return False, f"检测到敏感信息: {[f['type'] for f in findings]}",
            return True, "数据安全"
        elif data_type == 'binary':
            return False, "二进制数据不应发送给LLM"
        return True, "数据安全"


def get_sandbox_manager() -> SandboxManager:
    """获取全局沙箱管理器实例"""
    global _sandbox_manager
    if _sandbox_manager is None:
        _sandbox_manager = SandboxManager()
    return _sandbox_manager


def get_llm_sanitizer() -> LLMDataSanitizer:
    """获取全局LLM脱敏器实例"""
    global _llm_sanitizer
    if _llm_sanitizer is None:
        _llm_sanitizer = LLMDataSanitizer()
    return _llm_sanitizer


_sandbox_manager = None
_llm_sanitizer = None"'