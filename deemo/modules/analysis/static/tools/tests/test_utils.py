"""Tests for shared 工具集: entropy, sliding window, 配置 loading, 日志
error hierarchy"""

import logging
import math
import os
import tempfile

import pytest


# =============================================================================
# Entropy Tests
# =============================================================================

class TestEntropy:
    """Tests for compute_entropy"""

    @pytest.fixture
    def entropy_fn(self):
        from src.utils import compute_entropy
        return compute_entropy

    def test_entropy_uniform(self, entropy_fn):
        """Uniform distribution near-max entropy (~8 bits)"""
        # 256 bytes, unique
        data = bytes(range(256))
        ent = entropy_fn(data)
        # LaPlace smoothing -uniform data, entropy = 8.0 exactly
        assert abs(ent - 8.0) < 0.01, f"Expected ~8 bits, got {ent}"

    def test_entropy_single_value(self, entropy_fn):
        """A large number repeated bytes low entropy"""
        data = b"\x41" * 10000
        ent = entropy_fn(data)
        # LaPlace smoothing large sample, single-value data low entropy
        assert ent < 2.0, f"Expected < 2.0 bits, got {ent}"

    def test_entropy_laplace_smoothing(self, entropy_fn):
        """Empty data 返回 0.0 entropy"""
        assert entropy_fn(b"") == 0.0


# =============================================================================
# Sliding Window Tests
# =============================================================================

class TestSlidingWindow:
    """Tests for sliding_window generator"""

    @pytest.fixture
    def window_fn(self):
        from src.utils import sliding_window
        return sliding_window

    def test_sliding_window_basic(self, window_fn):
        """构造 correct n-grams"""
        items = [1, 2, 3, 4, 5]
        windows = list(window_fn(items, 3))
        assert len(windows) == 3
        assert windows[0] == (1, 2, 3)
        assert windows[1] == (2, 3, 4)
        assert windows[2] == (3, 4, 5)

    def test_sliding_window_n_larger_than_list(self, window_fn):
        """n > len(items), 返回 empty iterator"""
        items = [1, 2, 3]
        windows = list(window_fn(items, 5))
        assert windows == []

    def test_sliding_window_n_equals_len(self, window_fn):
        """n == len(items), 返回 one window"""
        items = [1, 2, 3]
        windows = list(window_fn(items, 3))
        assert len(windows) == 1
        assert windows[0] == (1, 2, 3)


# =============================================================================
# YAML 配置 Tests
# =============================================================================

class TestYamlConfig:
    """Tests for load_yaml_配置"""

    @pytest.fixture
    def yaml_loader(self):
        from src.utils import load_yaml_config
        return load_yaml_config

    @staticmethod
    def _write_yaml(content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml", prefix="test_utils_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_load_yaml_config_basic(self, yaml_loader):
        """加载 a basic YAML file"""
        content = "key: value\nnested:\n  sub: 42\n"
        path = self._write_yaml(content)
        try:
            config = yaml_loader(path)
            assert config["key"] == "value"
            assert config["nested"]["sub"] == 42
        finally:
            os.unlink(path)

    def test_load_yaml_env_substitution(self, yaml_loader):
        """${VAR} patterns replaced env var values"""
        content = "database: ${DB_NAME}\n"
        path = self._write_yaml(content)
        os.environ["DB_NAME"] = "testdb"
        try:
            config = yaml_loader(path)
            assert config["database"] == "testdb"
        finally:
            os.unlink(path)
            del os.environ["DB_NAME"]


# =============================================================================
# 日志 Setup Tests
# =============================================================================

class TestLoggingSetup:
    """Tests for setup_日志"""

    def test_setup_logging_creates_logger(self):
        """setup_日志 返回 a properly 配置ured 日志器"""
        from src.utils import setup_logging

        config = {
            "logging": {
                "level": "WARNING",
                "format": "%(levelname)s: %(message)s",
            }
        }
        logger = setup_logging(config)
        assert isinstance(logger, logging.Logger)
        assert logger.level == logging.WARNING


# =============================================================================
# Error Hierarchy Tests
# =============================================================================

class TestErrorHierarchy:
    """Tests for 异常 class hierarchy"""

    def test_error_hierarchy(self):
        """StaticAnalysisError a subclass ToolsError"""
        from src.utils import ToolsError, StaticAnalysisError

        assert issubclass(StaticAnalysisError, ToolsError)
        assert issubclass(StaticAnalysisError, Exception)

    def test_error_hierarchy_fuzz(self):
        """模糊测试器ror a subclass ToolsError"""
        from src.utils import ToolsError, FuzzError

        assert issubclass(FuzzError, ToolsError)
        assert issubclass(FuzzError, Exception)

    def test_exception_instantiation(self):
        """Errors instantiable a message"""
        from src.utils import ToolsError, StaticAnalysisError, FuzzError

        e1 = ToolsError("base error")
        e2 = StaticAnalysisError("analysis failed")
        e3 = FuzzError("fuzz crashed")

        assert str(e1) == "base error"
        assert str(e2) == "analysis failed"
        assert str(e3) == "fuzz crashed"
