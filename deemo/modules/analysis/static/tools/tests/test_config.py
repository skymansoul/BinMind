"""Tests for 配置 加载器 env var override 校验"""

import os
import tempfile

import pytest


# =============================================================================
# 辅助函数
# =============================================================================

def _write_temp_yaml(content: str) -> str:
    """写入 a temporary yaml file 返回 path"""
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="test_config_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# =============================================================================
# Tests
# =============================================================================

class TestLoadConfig:
    """Tests for load_配置"""

    @pytest.fixture
    def config_loader(self):
        from src.config import load_config
        return load_config

    def test_load_config_defaults(self, config_loader):
        """Loading a basic 配置 返回 parsed YAML dict"""
        yaml_content = """
logging:
  level: INFO
analysis:
  timeout_seconds: 300
"""
        path = _write_temp_yaml(yaml_content)
        try:
            config = config_loader(path)
            assert config["logging"]["level"] == "INFO"
            assert config["analysis"]["timeout_seconds"] == 300
        finally:
            os.unlink(path)

    def test_env_override_basic(self, config_loader):
        """Environment variable override a basic 配置 value"""
        yaml_content = """
logging:
  level: INFO
analysis:
  timeout_seconds: 300
"""
        path = _write_temp_yaml(yaml_content)
        os.environ["ATOOLS_ANALYSIS__TIMEOUT_SECONDS"] = "600"
        try:
            config = config_loader(path)
            assert config["analysis"]["timeout_seconds"] == 600
        finally:
            os.unlink(path)
            del os.environ["ATOOLS_ANALYSIS__TIMEOUT_SECONDS"]

    def test_env_override_nested(self, config_loader):
        """Double-underscore syntax override nested keys"""
        yaml_content = """
logging:
  level: INFO
  format: "%(message)s"
analysis:
  timeout_seconds: 300
"""
        path = _write_temp_yaml(yaml_content)
        os.environ["ATOOLS_LOGGING__LEVEL"] = "DEBUG"
        try:
            config = config_loader(path)
            assert config["logging"]["level"] == "DEBUG"
        finally:
            os.unlink(path)
            del os.environ["ATOOLS_LOGGING__LEVEL"]


class TestValidateConfig:
    """Tests for 校验_配置"""

    @pytest.fixture
    def validator(self):
        from src.config import validate_config
        return validate_config

    def test_validate_config_valid(self, validator):
        """A valid 配置 pass 校验"""
        config = {
            "logging": {"level": "INFO", "format": "%(message)s"},
            "analysis": {"timeout_seconds": 300, "max_memory_mb": 2048},
        }
        result = validator(config)
        assert result == config

    def test_validate_config_missing_key(self, validator):
        """Missing required key raise ValueError"""
        config = {
            "logging": {"level": "INFO"},
            # Missing 'analysis' key
        }
        with pytest.raises(ValueError, match="Missing required"):
            validator(config)

    def test_validate_config_bad_type(self, validator):
        """Wrong type for a constrained key raise ValueError"""
        config = {
            "logging": {"level": "INFO"},
            "analysis": {"timeout_seconds": "not_a_number", "max_memory_mb": 2048},
        }
        with pytest.raises(ValueError, match="type"):
            validator(config)
