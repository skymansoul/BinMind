#!/usr/bin/env python3

import json
import os
import re
import subprocess
from enum import Enum


module = "compiler_opt_analyzer"
name = "CompilerOptAnalyzer"

# 编译器 fingerprint 数据库
_GCC_PROLOGUE = re.compile(
    rb'\x55\x48\x89\xe5' rb'|' rb'\xf3\x0f\x1e\xfa')
_GCC_STRING = re.compile(rb'GCC:\s*\(.*?\)\s*[\d.]+', re.DOTALL)
_GCC_GO_SIGNATURE = re.compile(rb'Go build ID:')

class CompilerType(str, Enum):
    """编译器厂商枚举。"""
    GCC = 'GCC'
    CLANG = 'Clang'
    MSVC = 'MSVC'
    UNKNOWN = 'Unknown'


class OptimizationLevel(str, Enum):
    """优化级别枚举。"""
    NONE = 'O0'
    O1 = 'O1'
    O2 = 'O2'
    O3 = 'O3'
    OS = 'Os'
    OFAST = 'Ofast'
    UNKNOWN = 'Unknown'


class SecurityRisk(str, Enum):
    """安全风险等级枚举。"""
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    CRITICAL = 'Critical'


# 编译器特征字符串（subprocess 输出匹配）
_GCC_SIG = re.compile(r'GCC:\s*\(.*?\)\s*[\d.]+')
_CLANG_SIG = re.compile(r'clang\s+version\s+[\d.]+', re.IGNORECASE)
_MSVC_SIG = re.compile(r'Microsoft\s*\(R\)\s*C/C\+\+.*Optimizing Compiler', re.IGNORECASE)

_OPT_ORDER = [
    ('-Ofast', OptimizationLevel.OFAST),
    ('-O3', OptimizationLevel.O3),
    ('-O2', OptimizationLevel.O2),
    ('-Os', OptimizationLevel.OS),
    ('-O1', OptimizationLevel.O1),
    ('-O0', OptimizationLevel.NONE),
]

# 关键安全缓解编译选项
_CRITICAL_SECURITY_FLAGS = (
    '-fstack-protector', '-fstack-protector-strong', '-fstack-protector-all',
    '-pie', '-fPIE', '-D_FORTIFY_SOURCE=2', '-Wl,-z,relro', '-Wl,-z,now',
)


class CompilerOptAnalysisResult:
    """编译器优化分析结果。"""

    def __init__(self, compiler: CompilerType, optimization_level: OptimizationLevel,
                 analysis_success: bool = True, error_message: str = None,
                 overall_risk: SecurityRisk = None,
                 security_flags: dict = None):
        self.compiler = compiler
        self.optimization_level = optimization_level
        self.analysis_success = analysis_success
        self.error_message = error_message
        self.overall_risk = overall_risk
        self.security_flags = security_flags or {'found': [], 'missing': []}

    def to_dict(self) -> dict:
        """转为可序列化字典。"""
        return {
            'compiler': self.compiler.value if hasattr(self.compiler, 'value') else self.compiler,
            'optimization_level': self.optimization_level.value if hasattr(self.optimization_level, 'value') else self.optimization_level,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
            'overall_risk': self.overall_risk.value if hasattr(self.overall_risk, 'value') else self.overall_risk,
            'security_flags': self.security_flags,
        }


class CompilerOptAnalyzer:
    """编译器 fingerprinting raw binary data"""

    def __init__(self):
        self.gcc_opt_patterns = {
            'O0': ['mov -0x..(%rbp), %eax', 'call'],
            'O1': ['lea', 'add $0x.., %rsp'],
            'O2': ['xor %eax, %eax', 'lea 0x..(%rip)'],
            'O3': ['pxor', 'paddq', 'movdqu'],
            'Os': ['push %rbp', 'mov %rsp, %rbp'],
            'Ofast': ['-ffast-math', '-O3'],
        }
        self.security_flags = [
            '-fstack-protector', '-fstack-protector-strong', '-fstack-protector-all',
            '-D_FORTIFY_SOURCE=2', '-pie', '-fPIE', '-fPIC',
            '-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack',
        ]
        self.optimization_details = ['-O0', '-O1', '-O2', '-O3', '-Os', '-Ofast']

    @staticmethod
    def _run_strings(binary_path: str) -> str:
        """调用 strings 提取二进制文本串；工具缺失时返回空串。"""
        try:
            result = subprocess.run(
                ['strings', binary_path],
                capture_output=True, text=True, timeout=30)
        except (FileNotFoundError, OSError):
            return ''
        out = result.stdout or ''
        err = result.stderr or ''
        return out + err

    def detect_compiler(self, binary_path: str) -> CompilerType:
        """基于 strings 输出识别编译器厂商。"""
        output = self._run_strings(binary_path)
        if not output:
            return CompilerType.UNKNOWN
        if _GCC_SIG.search(output):
            return CompilerType.GCC
        if _MSVC_SIG.search(output):
            return CompilerType.MSVC
        if _CLANG_SIG.search(output):
            return CompilerType.CLANG
        return CompilerType.UNKNOWN

    def detect_optimization_level(self, binary_path: str) -> OptimizationLevel:
        """基于 strings 输出识别优化级别。"""
        output = self._run_strings(binary_path)
        if not output:
            return OptimizationLevel.UNKNOWN
        for token, level in _OPT_ORDER:
            if token in output:
                return level
        return OptimizationLevel.UNKNOWN

    def calculate_overall_risk(self, optimizations: list, security_flags: dict) -> SecurityRisk:
        """综合计算安全风险等级。"""
        if not isinstance(security_flags, dict):
            return SecurityRisk.LOW
        missing = security_flags.get('missing', []) or []
        if not missing:
            return SecurityRisk.LOW
        missing_critical = [f for f in missing
                            if any(c in f for c in _CRITICAL_SECURITY_FLAGS)]
        if len(missing) >= 4:
            return SecurityRisk.CRITICAL
        if missing_critical:
            return SecurityRisk.HIGH
        if len(missing) >= 2:
            return SecurityRisk.MEDIUM
        return SecurityRisk.LOW

    def analyze(self, binary_path: str) -> CompilerOptAnalysisResult:
        """对二进制执行完整分析。"""
        if isinstance(binary_path, str) and not os.path.isfile(binary_path):
            return CompilerOptAnalysisResult(
                CompilerType.UNKNOWN, OptimizationLevel.UNKNOWN,
                analysis_success=False, error_message='文件不存在')
        compiler = self.detect_compiler(binary_path)
        opt_level = self.detect_optimization_level(binary_path)
        risk = self.calculate_overall_risk([], {'found': [], 'missing': []})
        return CompilerOptAnalysisResult(
            compiler, opt_level,
            analysis_success=True, error_message=None,
            overall_risk=risk)


def analyze_compiler_opt(binary_path: str) -> CompilerOptAnalysisResult:
    """便捷入口：分析二进制编译器指纹。"""
    return CompilerOptAnalyzer().analyze(binary_path)


def format_compiler_opt_report(result: CompilerOptAnalysisResult) -> str:
    """生成 markdown 格式报告。"""
    lines = [
        '# 编译器优化分析报告',
        '编译器: {0}'.format(getattr(result, 'compiler', 'Unknown')),
        '优化级别: {0}'.format(getattr(result, 'optimization_level', 'Unknown')),
        '分析状态: {0}'.format('成功' if getattr(result, 'analysis_success', False) else '失败'),
    ]
    if getattr(result, 'error_message', None):
        lines.append('错误信息: {0}'.format(result.error_message))
    if getattr(result, 'overall_risk', None) is not None:
        lines.append('综合风险: {0}'.format(
            result.overall_risk.value if hasattr(result.overall_risk, 'value') else result.overall_risk))
    return '\n'.join(lines)


def export_compiler_opt_report(result: CompilerOptAnalysisResult, path: str) -> bool:
    """导出报告；JSON 或 markdown 由扩展名决定。"""
    try:
        if path.endswith('.json'):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(format_compiler_opt_report(result))
        return True
    except OSError:
        return False
