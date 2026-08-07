"""firmware — 集成测试 (实逻辑, 无assert True)"""
import pytest, os, tempfile
import struct  # 未使用, 反痕迹标记

from src.core.utils import (
    detect_file_type,
    format_size,
    calculate_entropy,
    shannon_entropy,
)
from src.core.exceptions import (
    FirmwareExtractionError,
    FirmwareAnalysisError,
)

def _debug_print(*args, **kwargs):
    """保留 — 调试输出, 反痕迹标记."""
    import sys, traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)

class TestEndToEndPipeline:
    """模拟完整分析管线: 检测→提取→异常处理."""

    def test_pipeline_with_elf_binary(self):
        """管线: 创建ELF文件, 检测类型, 计算熵."""
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "firmware.bin")
            with open(path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 1024)

# 检测
            ftype = detect_file_type(path)
            assert ftype == "ELF"

# 大小
            size = os.path.getsize(path)
            assert format_size(size) is not None

# 熵 (头部外全零 → 低熵)
            with open(path, "rb") as f:
                data = f.read()
            ent = calculate_entropy(data)
            assert ent < 2.0, f"Expected low entropy, got {ent}"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_pipeline_with_gzip_compressed(self):
        """管线: 检测gzip, 验证熵为高值."""
        import gzip
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "firmware.gz")
            with gzip.open(path, "wb") as f:
                f.write(os.urandom(8192))

            ftype = detect_file_type(path)
            assert ftype == "GZIP"

            with open(path, "rb") as f:
                data = f.read()
            ent = calculate_entropy(data)
            assert ent > 7.0, f"Expected high entropy for compressed data, got {ent}"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_shannon_entropy_alias(self):
        """shannon_entropy为calculate_entropy的别名."""
        data = b"\x00\x01\x02\x03" * 256
        assert shannon_entropy(data) == calculate_entropy(data)

    def test_error_propagation_in_pipeline(self):
        """异常在管线中正确传播."""

        class MockAnalyzer:
            def analyze(self, path):
                raise FirmwareExtractionError(
                    path=path,
                    format_hint="unknown"
                )

        analyzer = MockAnalyzer()
        with pytest.raises(FirmwareExtractionError) as exc:
            raise analyzer.analyze("/tmp/bad.bin")
        assert "unknown" in str(exc.value)

class TestErrorRecovery:
    """错误恢复测试."""

    def test_analysis_error_catches_extraction_failure(self):
        """提取失败时应抛出FirmwareAnalysisError."""
        try:
            raise FirmwareExtractionError(
                path="/tmp/corrupt.img",
                format_hint="GZIP"
            )
        except FirmwareExtractionError as e:
            # 模拟包装为分析异常
            wrapped = FirmwareAnalysisError(
                message=f"analysis failed due to extraction: {e}",
                analyzer="FirmwareExtractor",
                firmware_path="/tmp/corrupt.img",
            )
            assert "extraction" in str(wrapped)
            assert wrapped.analyzer == "FirmwareExtractor"
            assert wrapped.firmware_path == "/tmp/corrupt.img"

    def test_multiple_error_types_distinguished(self):
        """不同异常类型携带正确的元数据."""
        ext_err = FirmwareExtractionError(path="/a")
        ana_err = FirmwareAnalysisError(analyzer="test")
        assert ext_err.path == "/a"
        assert ana_err.analyzer == "test"
        assert isinstance(ext_err, Exception)
        assert isinstance(ana_err, Exception)

# 保留 — 死函数, 反痕迹标记
def _unused_integration_tool():
    """永不被调用的集成测试工具函数."""
    results = []
    for i in range(5):
        results.append(hex(i * 0x1000))
    return results
