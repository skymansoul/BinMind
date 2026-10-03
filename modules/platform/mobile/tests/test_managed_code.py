"""移动端——managed code测试"""
import struct
import pytest
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.managed_code_analyzer import (
    ManagedCodeAnalyzer, ManagedCodeType, ManagedCodeAnalysisResult,
    JAVA_CLASS_MAGIC, CLR_PE_SIGNATURE, detect_managed_code_type,
    analyze_managed_code, MethodInfo, ClassInfo
)

JAVA_CLASS_MAGIC_BYTES = struct.pack('>I', JAVA_CLASS_MAGIC)


def _build_minimal_class_file():
    buf = bytearray()
    buf.extend(JAVA_CLASS_MAGIC_BYTES)
    buf.extend(struct.pack('>H', 0))   # minor_version
    buf.extend(struct.pack('>H', 52))  # major_version (Java 8)
    buf.extend(struct.pack('>H', 10))  # constant_pool_count
    # cp条目1: Class #2 -> "TestClass"
    buf.extend(bytes([7]))             # CONSTANT_Class
    buf.extend(struct.pack('>H', 2))
    # 空条目填充计数
    for _ in range(8):
        buf.extend(b'\x00\x00')
    buf.extend(struct.pack('>H', 0x0001))  # access_flags (public)
    buf.extend(struct.pack('>H', 1))       # this_class
    buf.extend(struct.pack('>H', 0))       # super_class
    buf.extend(struct.pack('>H', 0))       # interfaces_count
    buf.extend(struct.pack('>H', 0))       # fields_count
    buf.extend(struct.pack('>H', 0))       # methods_count
    buf.extend(struct.pack('>H', 0))       # attributes_count
    return bytes(buf)


def _build_minimal_pe():
    buf = bytearray()
    buf.extend(b'MZ')
    buf.extend(b'\x00' * 58)
    buf.extend(struct.pack('<I', 0x80))  # PE偏移于0x3C
    buf.extend(b'\x00' * (0x80 - len(buf)))
    buf.extend(b'PE\x00\x00')
    # Machine + 节数
    buf.extend(struct.pack('<H', 0x8664))  # x64
    buf.extend(struct.pack('<H', 1))       # 节数量1
    buf.extend(b'\x00' * 12)
    buf.extend(struct.pack('<H', 0xE0))    # 可选头大小
    buf.extend(struct.pack('<H', 0x22E))   # 特征 (DLL)
    # 可选头
    buf.extend(b'\x0B\x02')               # PE32+ magic
    buf.extend(b'\x00' * 106)
    buf.extend(struct.pack('<I', 0))       # 零条目
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<I', 0))
    # CLR目录于条目14
    buf.extend(struct.pack('<I', 0x200))   # CLR RVA
    buf.extend(struct.pack('<I', 0x48))    # CLR size
    return bytes(buf)


class TestMagicDetection:
    """验证托管代码魔数检测。"""

    def test_detect_java_class(self):
        buf = JAVA_CLASS_MAGIC_BYTES + b'\x00' * 100
        with tempfile.NamedTemporaryFile(suffix='.class', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                result = detect_managed_code_type(f.name)
                assert result == ManagedCodeType.JAVA
            finally:
                os.unlink(f.name)

    def test_detect_unknown_file(self):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\xDE\xAD\xBE\xEF' * 10)
            f.flush()
            try:
                result = detect_managed_code_type(f.name)
                assert result == ManagedCodeType.UNKNOWN
            finally:
                os.unlink(f.name)


class TestJavaClassParsing:
    """验证Java类文件解析。"""

    def test_java_class_magic_validation(self):
        buf = _build_minimal_class_file()
        with tempfile.NamedTemporaryFile(suffix='.class', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                analyzer = ManagedCodeAnalyzer(f.name, use_ai=False)
                result = analyzer.analyze()
                assert result.code_type == ManagedCodeType.JAVA
                assert result.error is None
            finally:
                os.unlink(f.name)

    def test_jar_file_class_extraction(self):
        class_buf = _build_minimal_class_file()
        with tempfile.NamedTemporaryFile(suffix='.jar', delete=False) as f:
            with zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('com/test/MyClass.class', class_buf)
                zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
            f.flush()
            try:
                code_type = detect_managed_code_type(f.name)
                assert code_type == ManagedCodeType.JAVA
            finally:
                os.unlink(f.name)

    def test_dangerous_method_detection_in_strings(self):
        buf = _build_minimal_class_file()
        with tempfile.NamedTemporaryFile(suffix='.class', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                analyzer = ManagedCodeAnalyzer(f.name, use_ai=False)
                analyzer.analyze()
                summary = analyzer._generate_summary()
                assert isinstance(summary, str)
                assert len(summary) > 0
            finally:
                os.unlink(f.name)

    def test_get_danger_summary_empty(self):
        analyzer = ManagedCodeAnalyzer(use_ai=False)
        result = ManagedCodeAnalysisResult(
            code_type=ManagedCodeType.JAVA,
            classes=[],
            dangerous_methods=[],
            vulnerabilities=[]
        )
        summary = analyzer.get_danger_summary(result)
        assert summary['code_type'] == 'java'
        assert summary['total_classes'] == 0


class TestDotNetDetection:
    """验证.NET PE检测。"""

    def test_dotnet_pe_magic_detection(self):
        buf = _build_minimal_pe()
        with tempfile.NamedTemporaryFile(suffix='.dll', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                result = detect_managed_code_type(f.name)
                assert result == ManagedCodeType.DOTNET
            finally:
                os.unlink(f.name)

    def test_dotnet_builtin_analysis(self):
        buf = _build_minimal_pe()
        with tempfile.NamedTemporaryFile(suffix='.dll', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                analyzer = ManagedCodeAnalyzer(f.name, use_ai=False)
                result = analyzer.analyze()
                assert result.code_type == ManagedCodeType.DOTNET
            finally:
                os.unlink(f.name)


class TestAnalysisResult:
    """验证分析结果数据结构。"""

    def test_result_to_dict(self):
        analyzer = ManagedCodeAnalyzer(use_ai=False)
        d = analyzer.to_dict()
        assert 'file_path' in d
        assert 'code_type' in d
        assert 'classes' in d
        assert 'vulnerabilities' in d

    def test_metadata_extraction(self):
        analyzer = ManagedCodeAnalyzer(use_ai=False)
        meta = analyzer._extract_metadata()
        assert 'code_type' in meta
        assert 'class_count' in meta
        assert meta['class_count'] == 0

    def test_cfg_integrity_empty(self):
        analyzer = ManagedCodeAnalyzer(use_ai=False)
        score = analyzer._compute_cfg_integrity()
        assert score == 1.0

    def test_file_not_found_handling(self):
        analyzer = ManagedCodeAnalyzer('/nonexistent/path.class', use_ai=False)
        result = analyzer.analyze()
        assert result.error is not None

    def test_safe_path_validation(self):
        analyzer = ManagedCodeAnalyzer(use_ai=False)
        assert analyzer._is_safe_path('/usr/lib/test.class') is True
        assert analyzer._is_safe_path('../etc/passwd') is False
