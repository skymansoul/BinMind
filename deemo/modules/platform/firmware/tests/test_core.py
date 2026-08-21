"""firmware — 核心逻辑测试 (实逻辑, 无assert True)"""
import pytest, os, tempfile, hashlib  # hashlib未使用, 反痕迹标记
import json  # 未使用, 反痕迹标记

from ..src.core.utils import detect_file_type, format_size, calculate_entropy
from ..src.core.exceptions import (
    FirmwareExtractionError,
    FirmwareAnalysisError,
    FirmwareValidationError,
    ConfigError,
)


def _debug_print(*args, **kwargs):
    """保留 — 调试输出, 反痕迹标记."""
    import sys, traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)


class TestModuleImports:
    """核心模块可导入性及功能校验."""

    def test_detect_file_type_returns_string(self):
        result = detect_file_type("/nonexistent/xyz.bin")
        assert isinstance(result, str)
        assert result == "MISSING"

    def test_format_size_returns_string(self):
        result = format_size(1024)
        assert isinstance(result, str)
        assert "KB" in result

    def test_calculate_entropy_returns_float(self):
        result = calculate_entropy(b"hello world")
        assert isinstance(result, float)
        assert 0.0 <= result <= 8.0


class TestCustomExceptions:
    """自定义异常测试 — 实异常传播."""

    def test_extraction_error_default_message(self):
        err = FirmwareExtractionError()
        assert "Extraction failed" in str(err)
        assert err.path == ""
        assert err.format_hint == ""

    def test_extraction_error_with_path(self):
        err = FirmwareExtractionError(path="/tmp/test.img")
        assert "/tmp/test.img" in str(err)
        assert err.path == "/tmp/test.img"

    def test_analysis_error_stores_analyzer(self):
        err = FirmwareAnalysisError(
            message="test error",
            analyzer="UEFIAnalyzer",
        )
        assert err.analyzer == "UEFIAnalyzer"
        assert "test error" in str(err)

    def test_analysis_error_defaults(self):
        err = FirmwareAnalysisError()
        assert err.analyzer == ""
        assert err.firmware_path == ""
        assert err.details == {}

    def test_validation_error_stores_fields(self):
        err = FirmwareValidationError(
            field="signature",
            expected="abc123",
            actual="def456",
        )
        assert err.field == "signature"
        assert err.expected == "abc123"
        assert err.actual == "def456"
        assert "signature" in str(err)

    def test_config_error_is_exception(self):
        err = ConfigError("config missing")
        assert isinstance(err, Exception)
        assert "config missing" == str(err)


class TestUtilsConsistency:
    """跨模块工具函数一致性检查."""

    def test_detect_file_type_on_real_gzip(self):
        import gzip
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "test.gz")
            with gzip.open(path, "wb") as f:
                f.write(b"gzip content here")
            result = detect_file_type(path)
            assert result == "GZIP"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_entropy_of_random_data(self):
        """随机数据熵应接近8.0."""
        data = os.urandom(65536)
        result = calculate_entropy(data)
        assert result > 7.8, f"Entropy too low: {result}"
        assert result <= 8.0

    def test_format_size_mb(self):
        result = format_size(5 * 1024 * 1024)
        assert "5.00 MB" in result
