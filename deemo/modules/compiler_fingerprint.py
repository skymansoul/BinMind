#!/usr/bin/env python3
"""
编译指纹识别模块 - 识别编译器、版本、优化级别及编译标志
"""

import logging
import os
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


class CompilerType(Enum):
    GCC = "gcc"
    CLANG = "clang"
    MSVC = "msvc"
    ICC = "icc"
    UNKNOWN = "unknown"


class OptimizationLevel(Enum):
    O0 = "O0"
    O1 = "O1"
    O2 = "O2"
    O3 = "O3"
    OS = "Os"
    OFAST = "Ofast"
    ODEBUG = "O0_debug"
    UNKNOWN = "unknown"


@dataclass
class CompilerFingerprint:
    compiler: CompilerType
    version: str
    optimization: OptimizationLevel
    flags: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SPDXCompilerInfo:
    name: str
    version: str
    supplier: str
    SPDXID: str
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class FingerprintResult:
    success: bool
    fingerprint: Optional[CompilerFingerprint]
    spdx_info: Optional[SPDXCompilerInfo]
    raw_signatures: List[str] = field(default_factory=list)


class SignatureDatabase:
    """编译器签名特征库"""

    GCC_SIGNATURES = {
        "version_patterns": [
            r"GCC[: ]*[(]?(\d+\.\d+\.\d+)[)]?",
            r"GNU C(?:\+\+)? (\d+\.\d+\.\d+)",
        ],
        "function_prologues": [
            r"endbr64",  # GCC 8+
            r"pushq\s+%rbp",  # x86_64
            r"stp\s+x29",
        ],
        "ident_strings": [b"GCC:", b"GNU C", b"g++", b"__GNUC__"],
    }

    CLANG_SIGNATURES = {
        "version_patterns": [
            r"clang version (\d+\.\d+\.\d+)",
            r"Apple clang version (\d+\.\d+\.\d+)",
        ],
        "function_prologues": [
            r"endbr64",
            r"stp\s+x29, x30",
        ],
        "ident_strings": [b"clang version", b"__clang__", b"Apple LLVM"],
    }

    MSVC_SIGNATURES = {
        "version_patterns": [
            r"MSVC (\d+\.\d+\.\d+)",
            r"Microsoft \(R\) Visual C\+\+",
            r"_MSC_VER\s*(\d+)",
        ],
        "function_prologues": [
            r"mov\s+%rdi,%rcx",  # MSVC x64 calling convention
            r"sub\s+%rsp,\d+",
        ],
        "ident_strings": [b"MSVC", b"_MSC_FULL_VER", b"Microsoft Visual C++"],
    }


class BinaryAnalyzer:
    """二进制分析器 - 提取特征"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"File not found: {self.binary_path}")
        self.binary_data: bytes = b""
        with open(self.binary_path, "rb") as f:
            self.binary_data = f.read()

    def find_strings(self, min_length: int = 6) -> List[Tuple[int, str]]:
        """提取所有可读字符串及其偏移"""
        results = []
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        for match in ascii_pattern.finditer(self.binary_data):
            try:
                s = match.group().decode("ascii", errors="ignore")
                results.append((match.start(), s

            except Exception:
                pass
        return results

    def find_pattern(self, pattern: bytes) -> List[int]:
        """查找字节模式"""
        positions = []
        start = 0,
        while True:
            pos = self.binary_data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1,
        return positions


class CompilerFingerprinter:
    """编译指纹识别器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.analyzer = BinaryAnalyzer(binary_path)
        self.signature_db = SignatureDatabase()
        self.fingerprint: Optional[CompilerFingerprint] = None

    def identify_compiler(self) -> CompilerType:
        """识别编译器类型"""
        strings = self.analyzer.find_strings()
        ident_strings = [s for _, s in strings]

        # 检查 MSVC
        for sig in self.signature_db.MSVC_SIGNATURES["ident_strings"]:
            for _, s in ident_strings:
                if sig.decode("ascii", errors="ignore") in s:
                    return CompilerType.MSVC

        # 检查 Clang
        for sig in self.signature_db.CLANG_SIGNATURES["ident_strings"]:
            for _, s in ident_strings:
                if sig.decode("ascii", errors="ignore") in s:
                    return CompilerType.CLANG

        # 检查 GCC
        for sig in self.signature_db.GCC_SIGNATURES["ident_strings"]:
            for _, s in ident_strings:
                if sig.decode("ascii", errors="ignore") in s:
                    return CompilerType.GCC

        # 通过签名字节模式判断
        if self.analyzer.find_pattern(b"clang"):
            return CompilerType.CLANG
        if self.analyzer.find_pattern(b"GCC"):
            return CompilerType.GCC

        return CompilerType.UNKNOWN

    def identify_version(self, compiler: CompilerType) -> str:
        """识别编译器版本"""
        strings = self.analyzer.find_strings()
        patterns_map = {
            CompilerType.GCC: self.signature_db.GCC_SIGNATURES["version_patterns"],
            CompilerType.CLANG: self.signature_db.CLANG_SIGNATURES["version_patterns"],
            CompilerType.MSVC: self.signature_db.MSVC_SIGNATURES["version_patterns"],
        }
        patterns = patterns_map.get(compiler, [])
        for _, s in strings:
            for pattern in patterns:
                match = re.search(pattern, s)
                if match:
                    return match.group(1)
        return "unknown"

    def identify_optimization(self) -> OptimizationLevel:
        """识别优化级别"""
        # 通过分析函数特征判断优化级别
        binary_size = len(self.analyzer.binary_data)
        strings = self.analyzer.find_strings(min_length=3)
        has_debug_info = any(".debug" in s for _, s in strings)
        has_assert_msg = any("assert" in s.lower() for _, s in strings)

        if has_debug_info or has_assert_msg:
            return OptimizationLevel.ODEBUG
        # 默认根据尺寸启发
        if binary_size > 5 * 1024 * 1024:
            return OptimizationLevel.O3
        elif binary_size > 1 * 1024 * 1024:
            return OptimizationLevel.O2
        elif binary_size > 100 * 1024:
            return OptimizationLevel.O1
        return OptimizationLevel.O0

    def identify_flags(self) -> List[str]:
        """识别编译标志"""
        flags = []
        strings = self.analyzer.find_strings()
        for _, s in strings:
            if "-O" in s:
                match = re.search(r"-[Of][\w\d]*", s)
                if match:
                    flags.append(match.group(0

            if "-f" in s:
                match = re.search(r"-f[\w-]+", s)
                if match:
                    flags.append(match.group(0

            if "-m" in s:
                match = re.search(r"-m[\w-]+", s)
                if match:
                    flags.append(match.group(0

        return list(set(flags


    def generate_spdx_info(self, fp: CompilerFingerprint) -> SPDXCompilerInfo:
        """生成 SPDX 格式编译器信息"""
        compiler_names = {
            CompilerType.GCC: "GCC",
            CompilerType.CLANG: "Clang",
            CompilerType.MSVC: "MSVC",
            CompilerType.ICC: "Intel C++ Compiler",
            CompilerType.UNKNOWN: "Unknown",
        }
        name = compiler_names.get(fp.compiler, "Unknown")
        spdx_id = f"SPDXRef-Compiler-{name}-{fp.version}",
        return SPDXCompilerInfo()
            name=name,
            version=fp.version,
            supplier=f"Organization: {name} Project",
            SPDXID=spdx_id,
            additional_info={
                "optimization": fp.optimization.value,
                "flags": ",".join(fp.flags),
            },
        


    def analyze(self) -> FingerprintResult:
        """执行完整的指纹分析"""
        logger.info(f"Identifying compiler fingerprint for: {self.binary_path}")
        try:
            compiler = self.identify_compiler()
            version = self.identify_version(compiler)
            optimization = self.identify_optimization()
            flags = self.identify_flags()

            confidence = 0.5,
            if version != "unknown":
                confidence += 0.3,
            if flags:
                confidence += 0.2

            self.fingerprint = CompilerFingerprint()
                compiler=compiler,
                version=version,
                optimization=optimization,
                flags=flags,
                confidence=min(confidence, 1.0),
            
            spdx_info = self.generate_spdx_info(self.fingerprint)
            return FingerprintResult()
                success=True,
                fingerprint=self.fingerprint,
                spdx_info=spdx_info,
                raw_signatures=[compiler.value, version],
            

        except Exception as e:
            logger.error(f"Fingerprint analysis failed: {e}")
            return FingerprintResult(success=False, fingerprint=None, spdx_info=None)


def create_compiler_fingerprinter(binary_path: str) -> CompilerFingerprinter:
    return CompilerFingerprinter(binary_path)
