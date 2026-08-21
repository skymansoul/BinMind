"""移动端: 平台分析器测试"""
import struct
import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mobile_analysis import (
    AndroidRTAnalyzer, IOSRuntimeAnalyzer,
    analyze_mobile_binary, RuntimeType, MobilePlatform,
    ART_MAGIC, OAT_MAGIC, MACHO_MAGICS,
    ArtMethod, ArtClass, OatFile, MachORuntimeClass,
    MobileBinaryAnalyzer, MobileVulnerability
)

MACHO_64 = b'\xcf\xfa\xed\xfe'
MACHO_64_BE = b'\xfe\xed\xfa\xcf'
MACHO_32 = b'\xce\xfa\xed\xfe'
MACHO_32_BE = b'\xfe\xed\xfa\xce'


def _build_minimal_oat():
    buf = bytearray()
    buf.extend(OAT_MAGIC)
    buf.extend(b'\x00' * 256)
    data_begin = struct.pack('<Q', 0x1000)
    exec_offset = struct.pack('<Q', 0x2000)
    image_base = struct.pack('<Q', 0x7000000000)
    dex_count = struct.pack('<I', 2)
    buf[16:24] = data_begin
    buf[24:32] = exec_offset
    buf[32:40] = image_base
    buf[48:52] = dex_count
    return bytes(buf)


def _build_minimal_macho():
    buf = bytearray()
    buf.extend(MACHO_64)
    buf.extend(b'\x00' * 2048)
    return bytes(buf)


class TestPlatformDetection:
    """确认平台自动检测逻辑。"""

    def test_detect_android_oat_by_magic(self):
        buf = _build_minimal_oat()
        with tempfile.NamedTemporaryFile(suffix='.oat', delete=False) as f:
            f.write(buf); f.flush()
            try:
                result = analyze_mobile_binary(f.name, platform='auto')
                assert result['platform'] == 'android'
            finally:
                os.unlink(f.name)

    def test_detect_ios_macho_by_magic(self):
        buf = _build_minimal_macho()
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                result = analyze_mobile_binary(f.name, platform='auto')
                assert result['platform'] == 'ios'
            finally:
                os.unlink(f.name)

    def test_explicit_android_platform(self):
        buf = b'\x00' * 256
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(buf); f.flush()
            try:
                result = analyze_mobile_binary(f.name, platform='android')
                assert result['platform'] == 'android'
            finally:
                os.unlink(f.name)

    def test_file_not_found(self):
        result = analyze_mobile_binary('/nonexistent/file.bin')
        assert 'error' in result


class TestAndroidRT:
    """Android运行时分析器测试。"""

    def test_oat_magic_detection(self):
        buf = _build_minimal_oat()
        with tempfile.NamedTemporaryFile(suffix='.oat', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = AndroidRTAnalyzer(f.name)
                rt = analyzer.detect_runtime_type()
                assert rt == RuntimeType.ART
            finally:
                os.unlink(f.name)

    def test_oat_parsing(self):
        buf = _build_minimal_oat()
        with tempfile.NamedTemporaryFile(suffix='.oat', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = AndroidRTAnalyzer(f.name)
                info = analyzer.parse_oat_file()
                assert info is not None
                assert info.dex_file_count == 2
                assert info.compiler_filter == 'verify-at-runtime'
            finally:
                os.unlink(f.name)

    def test_analyze_returns_classes(self):
        buf = _build_minimal_oat() + b'Lcom/example/Test;' * 5
        with tempfile.NamedTemporaryFile(suffix='.oat', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = AndroidRTAnalyzer(f.name)
                result = analyzer.analyze()
                assert 'runtime_type' in result
                assert 'classes' in result
                assert 'vulnerabilities' in result
            finally:
                os.unlink(f.name)

    def test_anti_tracing_detection(self):
        buf = b'/sys/kernel/debug/tracing\x00' + b'\x00' * 256
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = AndroidRTAnalyzer(f.name)
                findings = analyzer.detect_anti_tracing()
                assert len(findings) >= 1
            finally:
                os.unlink(f.name)

    def test_binder_syscall_detection(self):
        buf = b'__arm64_sys_ioctl\x00' + b'\x00' * 256
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = AndroidRTAnalyzer(f.name)
                findings = analyzer.detect_binder_syscall_tracepoints()
                assert len(findings) >= 1
            finally:
                os.unlink(f.name)


class TestIOSRT:
    """iOS运行时分析器测试。"""

    def test_macho_verification(self):
        buf = _build_minimal_macho()
        analyzer = IOSRuntimeAnalyzer.__new__(IOSRuntimeAnalyzer)
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer.binary_path = f.name
                analyzer.data = buf
                assert analyzer._verify_is_macho() is True
            finally:
                os.unlink(f.name)

    def test_objc_classlist_parsing(self):
        buf = b'_OBJC_CLASS_$_MyViewController\x00' + b'\x00' * 256
        buf = MACHO_64 + b'\x00' * 256 + buf
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = IOSRuntimeAnalyzer(f.name)
                classes = analyzer.parse_objc_classlist()
                assert len(classes) >= 1
                assert any('MyViewController' in c.name for c in classes)
            finally:
                os.unlink(f.name)

    def test_selector_references(self):
        buf = b'_objc_msgSend\x00' + b'\x00' * 256
        buf = MACHO_64 + b'\x00' * 256 + buf
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = IOSRuntimeAnalyzer(f.name)
                refs = analyzer.find_selector_references()
                assert len(refs) >= 1
            finally:
                os.unlink(f.name)

    def test_swift_metadata_extraction(self):
        buf = b'_TtC12MyApp14ViewController\x00' + b'\x00' * 256
        buf = MACHO_64 + b'\x00' * 256 + buf
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = IOSRuntimeAnalyzer(f.name)
                swift_info = analyzer.find_swift_metadata()
                assert swift_info is not None
                assert len(swift_info.mangled_names) >= 1
            finally:
                os.unlink(f.name)

    def test_ios_vulnerability_detection(self):
        buf = b'_objc_methname_dlopen\x00' + b'\x00' * 256
        buf = MACHO_64 + b'\x00' * 256 + buf
        with tempfile.NamedTemporaryFile(suffix='.macho', delete=False) as f:
            f.write(buf); f.flush()
            try:
                analyzer = IOSRuntimeAnalyzer(f.name)
                analyzer.analyze()
                assert len(analyzer._detect_ios_vulnerabilities()) >= 1
            finally:
                os.unlink(f.name)


class TestMobileBinaryAnalyzer:
    """移动端二进制分析器构造测试。"""

    def test_constructor_with_platform(self):
        analyzer = MobileBinaryAnalyzer('/tmp/test.so', 'android')
        assert analyzer.platform == MobilePlatform.ANDROID

    def test_constructor_auto_defaults_to_android(self):
        analyzer = MobileBinaryAnalyzer('/tmp/test.so', 'auto')
        assert analyzer.platform == MobilePlatform.ANDROID

    def test_macho_magic_list(self):
        assert len(MACHO_MAGICS) == 4

    @pytest.mark.parametrize('magic', MACHO_MAGICS)
    def test_all_macho_magics_recognized(self, magic):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(magic + b'\x00' * 256)
            f.flush()
            try:
                result = analyze_mobile_binary(f.name, platform='auto')
                assert result['platform'] == 'ios'
            finally:
                os.unlink(f.name)
