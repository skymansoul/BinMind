"""dynamic - utility function tests"""

import math
import os
import tempfile

import pytest

from modules.analysis.dynamic.src.utils import (
    compute_entropy,
    compute_region_entropy,
    find_high_entropy_regions,
    setup_logging,
    load_yaml_config,
    format_api_trace,
    format_api_trace_compact,
    hash_file,
    is_pe_file,
    is_elf_file,
    DynamicError,
    SandboxError,
    InstrumentationError,
    VMIAccessError,
    EmulationError,
    TraceError,
)


class TestComputeEntropy:
    """Test Shannon entropy computation"""

    def test_empty_data_raises(self):
        """Empty data raise ValueError"""
        with pytest.raises(ValueError):
            compute_entropy(b"")

    def test_uniform_data_zero_entropy(self):
        """same bytes entropy 0"""
        assert compute_entropy(b"\x00" * 256) == 0.0
        assert compute_entropy(b"\xFF" * 256) == 0.0

    def test_random_data_high_entropy(self):
        """Random data high entropy"""
        data = os.urandom(1024)
        ent = compute_entropy(data)
        assert ent > 5.0

    def test_entropy_range(self):
        """Entropy always [0, 8.0] for base 2"""
        for length in [1, 16, 256, 1024]:
            data = os.urandom(length)
            ent = compute_entropy(data)
            assert 0.0 <= ent <= 8.0

    def test_alternating_pattern(self):
        """Alternating pattern entropy 1"""
        data = b"\x00\xFF" * 128
        ent = compute_entropy(data)
        assert 0.9 <= ent <= 1.1

    def test_invalid_base_raises(self):
        """Invalid 记录 base raise ValueError"""
        with pytest.raises(ValueError):
            compute_entropy(b"\x00", base=-1)


class TestRegionEntropy:
    """Test region-based entropy computation"""

    def test_single_region(self):
        """Single window 返回 one value"""
        data = os.urandom(128)
        result = compute_region_entropy(data, window_size=256)
        assert len(result) == 1

    def test_multiple_regions(self):
        """Multiple windows 返回 multiple values"""
        data = os.urandom(1024)
        result = compute_region_entropy(data, window_size=256)
        assert len(result) == 4

    def test_empty_data(self):
        """Empty data 返回 empty list"""
        assert compute_region_entropy(b"") == []

    def test_high_entropy_regions(self):
        """查找 high-entropy regions"""
        data = b"\x00" * 256 + os.urandom(256) + b"\x00" * 256
        regions = find_high_entropy_regions(data, threshold=6.0)
        assert len(regions) >= 1


class TestLoggingUtils:
    """Test 日志 setup"""

    def test_basic_setup(self):
        """Basic 日志 setup 返回 a 日志器"""
        logger = setup_logging(level="WARNING")
        assert logger is not None

    def test_custom_format(self):
        """Custom 格式化 accepted"""
        logger = setup_logging(level="ERROR", log_format="%(message)s")
        assert logger is not None

    def test_file_logging(self):
        """File 日志 创建 a 记录 file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            logger = setup_logging(level="DEBUG", log_file=log_file)
            logger.info("test message")
            assert os.path.isfile(log_file)
            # 释放文件 handler，避免 Windows 下句柄占用导致临时目录无法删除
            import logging as _logging
            for _h in list(logger.handlers):
                if isinstance(_h, _logging.FileHandler):
                    _h.close()
                    logger.removeHandler(_h)


class TestYamlConfig:
    """Test YAML 配置 loading"""

    def test_load_simple_yaml(self):
        """解析 a simple YAML file"""
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False
        ) as f:
            f.write("key1: value1\nkey2: 42\n")
            tmp_name = f.name

        try:
            cfg = load_yaml_config(tmp_name)
            assert cfg["key1"] == "value1"
            assert cfg["key2"] == 42
        finally:
            os.unlink(tmp_name)

    def test_load_nonexistent_file(self):
        """raise nonexistent file"""
        with pytest.raises(DynamicError):
            load_yaml_config("/nonexistent/config.yaml")

    def test_load_nested_yaml(self):
        """解析 nested YAML"""
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False
        ) as f:
            f.write("outer:\n  inner: 100\n")
            tmp_name = f.name

        try:
            cfg = load_yaml_config(tmp_name)
            assert "outer" in cfg
        finally:
            os.unlink(tmp_name)


class TestFormatApiTrace:
    """Test API trace formatting"""

    def test_simple_trace(self):
        """Basic trace 格式化 correctly"""
        result = format_api_trace("CreateFile", {"path": "C:\\test.txt"})
        assert "CreateFile" in result
        assert "test.txt" in result

    def test_trace_with_return(self):
        """Trace 返回 value 显示"""
        result = format_api_trace("VirtualAlloc", {"size": 4096}, return_value=0x7FFA0000)
        assert "0x7FFA0000" in result

    def test_compact_format(self):
        """Compact 格式化 single line"""
        result = format_api_trace_compact("malloc", {"size": 1024})
        assert "\n" not in result
        assert "malloc" in result

    def test_large_hex_argument(self):
        """Large integers formatted hex"""
        result = format_api_trace_compact("MapView", {"addr": 0x7FFA12340000})
        assert "0x" in result


class TestFileUtilities:
    """Test file-related 工具集"""

    def test_hash_file(self):
        """计算 file hash"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world")
            tmp_name = f.name

        try:
            h = hash_file(tmp_name)
            assert len(h) == 64  # SHA256 produces 64 hex chars
        finally:
            os.unlink(tmp_name)

    def test_hash_nonexistent_file(self):
        """raise nonexistent file"""
        with pytest.raises(DynamicError):
            hash_file("/nonexistent/hash_me.txt")

    def test_is_pe_file(self):
        """检测 PE文件s"""
        pe_header = b"MZ\x90\x00" + b"\x00" * 56 + b"\x40\x00\x00\x00" + b"PE\x00\x00"
        assert is_pe_file(pe_header)
        assert not is_pe_file(b"not a PE file")
        assert not is_pe_file(b"")

    def test_is_elf_file(self):
        """检测 ELF文件s"""
        elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        assert is_elf_file(elf_header)
        assert not is_elf_file(b"not elf")
        assert not is_elf_file(b"")


class TestErrorHierarchy:
    """Test error class hierarchy"""

    def test_sandbox_error_is_dynamic_error(self):
        """沙箱Error a subclass DynamicError"""
        err = SandboxError("test")
        assert isinstance(err, DynamicError)
        assert isinstance(err, Exception)

    def test_instrumentation_error(self):
        """插桩Error catchable DynamicError"""
        with pytest.raises(DynamicError):
            raise InstrumentationError("hook failed")

    def test_vmi_error(self):
        """VMIAccessError catchable"""
        with pytest.raises(VMIAccessError):
            raise VMIAccessError("access denied")

    def test_emulation_error(self):
        """仿真Error catchable"""
        with pytest.raises(DynamicError):
            raise EmulationError("unicorn fault")

    def test_trace_error(self):
        """TraceError catchable"""
        with pytest.raises(DynamicError):
            raise TraceError("trace decode failed")
