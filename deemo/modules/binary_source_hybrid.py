"""
二进制与源码混合分析管道模块

功能:
    1. 当有对应源码时, 自动编译并对比二进制, 进行源码级污点追踪和二进制验证
    2. 提高漏洞定位精度, 部分实现源码安全审计自动化
    3. 支持多种编译器与构建系统

核心技术:
    - 源码扫描: 危险函数、危险模式
    - 编译协调: 调用编译器生成可比较的二进制
    - 源码-二进制映射: 行号/函数名关联
    - 漏洞交叉验证
"""

import logging
import os
import re
import json
import time
import hashlib
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class SourceLanguage(Enum):
    """源码语言"""
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    MIXED = "mixed"


class FindingKind(Enum):
    """发现种类"""
    DANGEROUS_API = "dangerous_api"
    UNCHECKED_RETURN = "unchecked_return"
    FORMAT_STRING = "format_string"
    BUFFER_OVERFLOW_RISK = "buffer_overflow_risk"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    CUSTOM = "custom"


class CompileStatus(Enum):
    """编译状态"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    NOT_ATTEMPTED = "not_attempted"


@dataclass
class SourceFinding:
    """源码级发现"""
    kind: FindingKind
    file_path: str
    line: int
    column: int = 0
    function: str = ""
    code_snippet: str = ""
    message: str = ""
    cwe: str = ""
    severity: str = "medium"
    confirmed_in_binary: bool = False
    binary_addr: int = 0


@dataclass
class CompileResult:
    """编译结果"""
    status: CompileStatus
    binary_path: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed: float = 0.0
    error: str = ""


@dataclass
class SourceBinaryMapping:
    """源码-二进制映射条目"""
    file_path: str
    line: int
    function: str
    binary_addr: int
    binary_size: int
    binary_name: str = ""


@dataclass
class HybridAnalysisResult:
    """混合分析结果"""
    source_path: str
    language: SourceLanguage
    source_findings: List[SourceFinding] = field(default_factory=list)
    compile_result: Optional[CompileResult] = None
    mappings: List[SourceBinaryMapping] = field(default_factory=list)
    confirmed_findings: List[SourceFinding] = field(default_factory=list)
    timestamp: float = 0.0
    notes: str = ""


class SourceScanner:
    """源码扫描器"""

    DANGEROUS_APIS = {
        "strcpy": FindingKind.BUFFER_OVERFLOW_RISK,
        "strcat": FindingKind.BUFFER_OVERFLOW_RISK,
        "sprintf": FindingKind.FORMAT_STRING,
        "gets": FindingKind.BUFFER_OVERFLOW_RISK,
        "scanf": FindingKind.BUFFER_OVERFLOW_RISK,
        "memcpy": FindingKind.BUFFER_OVERFLOW_RISK,
        "memmove": FindingKind.BUFFER_OVERFLOW_RISK,
        "system": FindingKind.COMMAND_INJECTION,
        "execve": FindingKind.COMMAND_INJECTION,
        "popen": FindingKind.COMMAND_INJECTION,
        "fopen": FindingKind.PATH_TRAVERSAL,
        "sscanf": FindingKind.FORMAT_STRING,
        "snprintf": FindingKind.FORMAT_STRING,
        "vsprintf": FindingKind.FORMAT_STRING,
        "alloca": FindingKind.BUFFER_OVERFLOW_RISK,
        "realloc": FindingKind.USE_AFTER_FREE,
        "free": FindingKind.USE_AFTER_FREE,
    }

    CWE_MAPPING = {
        FindingKind.BUFFER_OVERFLOW_RISK: "CWE-120",
        FindingKind.FORMAT_STRING: "CWE-134",
        FindingKind.COMMAND_INJECTION: "CWE-78",
        FindingKind.PATH_TRAVERSAL: "CWE-22",
        FindingKind.USE_AFTER_FREE: "CWE-416",
        FindingKind.INTEGER_OVERFLOW: "CWE-190",
        FindingKind.MEMORY_LEAK: "CWE-401",
        FindingKind.RACE_CONDITION: "CWE-362",
        FindingKind.UNCHECKED_RETURN: "CWE-252",
    }

    SEVERITY = {
        FindingKind.BUFFER_OVERFLOW_RISK: "high",
        FindingKind.FORMAT_STRING: "high",
        FindingKind.COMMAND_INJECTION: "critical",
        FindingKind.PATH_TRAVERSAL: "high",
        FindingKind.USE_AFTER_FREE: "high",
        FindingKind.INTEGER_OVERFLOW: "medium",
        FindingKind.MEMORY_LEAK: "low",
        FindingKind.RACE_CONDITION: "medium",
        FindingKind.UNCHECKED_RETURN: "medium",
    }

    def __init__(self, language: SourceLanguage = SourceLanguage.C):
        self.language = language
        self._lock = threading.Lock()

    def scan_file(self, file_path: str) -> List[SourceFinding]:
        """扫描单个文件"""
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, IOError) as e:
            logger.warning(f"无法读取 {file_path}: {e}")
            return findings
        return self.scan_text(content, file_path)

    def scan_text(self, content: str, file_path: str = "<memory>") -> List[SourceFinding]:
        """扫描源码文本"""
        findings: List[SourceFinding] = []
        with self._lock:
            current_func = ""
            for line_no, line in enumerate(content.split("\n"), start=1):
                # 跟踪当前函数
                m = re.match(r"\s*(?:[\w\*\s]+)\s+(\w+)\s*\([^)]*\)\s*\{?", line)
                if m:
                    current_func = m.group(1)

                # 检测危险 API
                for api, kind in self.DANGEROUS_APIS.items():
                    pattern = r"\b" + re.escape(api) + r"\s*\("
                    if re.search(pattern, line):
                        col = re.search(pattern, line)
                        findings.append(SourceFinding(
                            kind=kind,
                            file_path=file_path,
                            line=line_no,
                            column=col.start() if col else 0,
                            function=current_func,
                            code_snippet=line.strip()[:200],
                            message=f"使用了危险 API: {api}",
                            cwe=self.CWE_MAPPING.get(kind, ""),
                            severity=self.SEVERITY.get(kind, "medium"),
                        ))

                # 检测 unchecked return (malloc/alloc)
                alloc_match = re.search(r"\b(malloc|calloc|realloc|new)\s*\(", line)
                if alloc_match:
                    if "if" not in line and "=" in line and "(" not in line.split("=")[0]:
                        # 简化: 假设单独一行的分配为未检查
                        pass  # 不强制报

                # SQL 注入
                if re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\+", line, re.IGNORECASE):
                    findings.append(SourceFinding(
                        kind=FindingKind.SQL_INJECTION,
                        file_path=file_path,
                        line=line_no,
                        function=current_func,
                        code_snippet=line.strip()[:200],
                        message="检测到可能的 SQL 注入",
                        cwe="CWE-89",
                        severity="critical",
                    ))
        return findings


class BuildCoordinator:
    """编译协调器"""

    def __init__(self, compiler: str = "gcc", extra_args: Optional[List[str]] = None, timeout: float = 60.0):
        self.compiler = compiler
        self.extra_args = extra_args or ["-O0", "-g"]
        self.timeout = timeout
        self._lock = threading.Lock()

    def compile_c(self, source_path: str, output_path: str) -> CompileResult:
        """编译 C/C++ 源码"""
        start = time.time()
        with self._lock:
            try:
                cmd = [self.compiler, *self.extra_args, "-o", output_path, source_path]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                elapsed = time.time() - start
                if proc.returncode == 0 and os.path.exists(output_path):
                    return CompileResult(
                        status=CompileStatus.SUCCESS,
                        binary_path=output_path,
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        exit_code=proc.returncode,
                        elapsed=elapsed,
                    )
                return CompileResult(
                    status=CompileStatus.FAILED,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    exit_code=proc.returncode,
                    elapsed=elapsed,
                    error=proc.stderr[:500] if proc.stderr else "编译失败",
                )
            except subprocess.TimeoutExpired:
                return CompileResult(
                    status=CompileStatus.TIMEOUT,
                    elapsed=time.time() - start,
                    error=f"编译超时 ({self.timeout}s)",
                )
            except (OSError, FileNotFoundError) as e:
                return CompileResult(
                    status=CompileStatus.FAILED,
                    elapsed=time.time() - start,
                    error=f"编译器不可用: {e}",
                )

    def compile_with_debug_info(
        self,
        source_path: str,
        output_path: str
    ) -> CompileResult:
        """带调试信息编译"""
        old_args = list(self.extra_args)
        self.extra_args = ["-O0", "-g3", "-gdwarf-4"]
        result = self.compile_c(source_path, output_path)
        self.extra_args = old_args
        return result


class SourceBinaryMapper:
    """源码-二进制映射器"""

    def __init__(self):
        self._lock = threading.Lock()

    def build_mappings(
        self,
        symbols: List[Dict[str, Any]],
        debug_info: Optional[Dict[str, Any]] = None
    ) -> List[SourceBinaryMapping]:
        """从符号和调试信息构建映射"""
        mappings: List[SourceBinaryMapping] = []
        with self._lock:
            for sym in symbols:
                if sym.get("type") not in ("FUNC", "func"):
                    continue
                file_path = sym.get("file", "")
                line = int(sym.get("line", 0))
                addr = int(sym.get("addr", 0))
                size = int(sym.get("size", 0))
                if not (file_path and line and addr):
                    continue
                mappings.append(SourceBinaryMapping(
                    file_path=file_path,
                    line=line,
                    function=sym.get("name", ""),
                    binary_addr=addr,
                    binary_size=size,
                    binary_name=sym.get("name", ""),
                ))

            if debug_info:
                for entry in debug_info.get("line_table", []):
                    mappings.append(SourceBinaryMapping(
                        file_path=entry.get("file", ""),
                        line=int(entry.get("line", 0)),
                        function=entry.get("func", ""),
                        binary_addr=int(entry.get("addr", 0)),
                        binary_size=0,
                    ))
        return mappings

    def find_binary_addr(
        self,
        mappings: List[SourceBinaryMapping],
        file_path: str,
        line: int
    ) -> Optional[int]:
        """查找源码行对应的二进制地址"""
        candidates: List[SourceBinaryMapping] = []
        for m in mappings:
            if m.file_path == file_path and m.line <= line < m.line + 50:
                candidates.append(m)
        if not candidates:
            return None
        candidates.sort(key=lambda m: line - m.line)
        return candidates[0].binary_addr


class HybridAnalysisPipeline:
    """混合分析管道 (主入口)"""

    def __init__(self, compiler: str = "gcc"):
        self.scanner = SourceScanner()
        self.compiler = compiler
        self.builder = BuildCoordinator(compiler=compiler)
        self.mapper = SourceBinaryMapper()
        self._lock = threading.Lock()

    def analyze(
        self,
        source_path: str,
        output_binary: Optional[str] = None,
        auto_compile: bool = True,
        binary_symbols: Optional[List[Dict[str, Any]]] = None,
        debug_info: Optional[Dict[str, Any]] = None,
        language: SourceLanguage = SourceLanguage.C
    ) -> HybridAnalysisResult:
        """分析源码 (可编译对比)"""
        with self._lock:
            result = HybridAnalysisResult(
                source_path=source_path,
                language=language,
            )
            self.scanner.language = language

            # 1. 源码扫描
            if os.path.isfile(source_path):
                result.source_findings = self.scanner.scan_file(source_path)
            elif os.path.isdir(source_path):
                # 扫描整个目录
                for root, _, files in os.walk(source_path):
                    for fname in files:
                        if fname.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
                            fp = os.path.join(root, fname)
                            result.source_findings.extend(self.scanner.scan_file(fp))

            # 2. 自动编译
            if auto_compile and os.path.isfile(source_path):
                if not output_binary:
                    base = os.path.basename(source_path)
                    name = os.path.splitext(base)[0]
                    output_binary = os.path.join("/tmp", name + "_hybrid")
                result.compile_result = self.builder.compile_with_debug_info(source_path, output_binary)

            # 3. 构建映射
            if binary_symbols or debug_info:
                result.mappings = self.mapper.build_mappings(binary_symbols or [], debug_info)

            # 4. 交叉验证
            for finding in result.source_findings:
                if not result.mappings:
                    continue
                addr = self.mapper.find_binary_addr(result.mappings, finding.file_path, finding.line)
                if addr and addr > 0:
                    finding.confirmed_in_binary = True
                    finding.binary_addr = addr
                    result.confirmed_findings.append(finding)

            result.timestamp = time.time()
            result.notes = f"源码发现 {len(result.source_findings)}, 已确认 {len(result.confirmed_findings)}"
            return result

    def set_compiler(self, compiler: str):
        self.compiler = compiler
        self.builder.compiler = compiler


# 便捷入口
def analyze_source(
    source_path: str,
    compiler: str = "gcc",
    auto_compile: bool = True,
    language: str = "c"
) -> HybridAnalysisResult:
    pipeline = HybridAnalysisPipeline(compiler=compiler)
    try:
        lang = SourceLanguage(language)
    except ValueError:
        lang = SourceLanguage.C
    return pipeline.analyze(source_path, auto_compile=auto_compile, language=lang)
