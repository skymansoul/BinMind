"""dynamic - 配置 tests"""

import os
import tempfile

import pytest

from modules.analysis.dynamic.src.config import (
    load_config,
    get_config_value,
    _deep_merge,
    _cast_env_value,
    _apply_env_overrides,
)


class TestDefaultConfig:
    """测试默认配置加载"""

    def test_load_default_config(self):
        """Default 配置 加载 arguments"""
        cfg = load_config()
        assert isinstance(cfg, dict)
        assert "paths" in cfg
        assert "logging" in cfg
        assert "analysis" in cfg
        assert "retry" in cfg

    def test_default_values(self):
        """Default values match expected"""
        cfg = load_config()
        assert cfg["analysis"]["timeout_seconds"] == 300
        assert cfg["retry"]["max_attempts"] == 3
        assert cfg["paths"]["data_dir"] == "data"

    def test_load_nonexistent_user_config(self):
        """Loading a nonexistent user 配置 raise FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config_path_12345.yaml")


class TestDeepMerge:
    """Test 配置 merging"""

    def test_shallow_merge(self):
        """Shallow keys override"""
        base = {"a": 1, "b": 2}
        override = {"b": 5}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 5

    def test_nested_merge(self):
        """Nested dicts deep 合并"""
        base = {"a": {"x": 1, "y": 2}}
        override = {"a": {"y": 10}}
        result = _deep_merge(base, override)
        assert result["a"]["x"] == 1
        assert result["a"]["y"] == 10

    def test_new_key_added(self):
        """New keys added"""
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 2

    def test_override_none_value(self):
        """None value override"""
        base = {"a": {"x": 1}}
        override = {"a": None}
        result = _deep_merge(base, override)
        assert result["a"] is None


class TestEnvOverrides:
    """测试环境变量覆盖"""

    def test_cast_int(self):
        assert _cast_env_value("42") == 42

    def test_cast_float(self):
        assert _cast_env_value("3.14") == 3.14

    def test_cast_true(self):
        assert _cast_env_value("true") is True
        assert _cast_env_value("yes") is True
        assert _cast_env_value("1") is True

    def test_cast_false(self):
        assert _cast_env_value("false") is False
        assert _cast_env_value("no") is False
        assert _cast_env_value("0") is False

    def test_cast_string(self):
        assert _cast_env_value("hello") == "hello"

    def test_env_override(self):
        """DYN_ env vars override 配置"""
        os.environ["DYN_ANALYSIS_TIMEOUT_SECONDS"] = "600"
        try:
            cfg = _apply_env_overrides(
                {"analysis": {"timeout_seconds": 300}},
                "DYN_",
            )
            assert cfg["analysis"]["timeout_seconds"] == 600
        finally:
            del os.environ["DYN_ANALYSIS_TIMEOUT_SECONDS"]

    def test_env_override_unknown_section(self):
        """Unknown section crash"""
        os.environ["DYN_UNKNOWN_KEY"] = "val"
        try:
            cfg = _apply_env_overrides({"known": {}}, "DYN_")
            assert cfg["known"] == {}
        finally:
            del os.environ["DYN_UNKNOWN_KEY"]


class TestGetConfigValue:
    """测试点分隔键访问"""

    def test_get_existing_key(self):
        cfg = {"a": {"b": {"c": 42}}}
        assert get_config_value(cfg, "a.b.c") == 42

    def test_get_missing_key(self):
        cfg = {"a": {"b": 1}}
        assert get_config_value(cfg, "a.c") is None

    def test_get_missing_with_default(self):
        cfg = {"a": {"b": 1}}
        assert get_config_value(cfg, "a.c", "fallback") == "fallback"

    def test_get_top_level(self):
        cfg = {"x": 100}
        assert get_config_value(cfg, "x") == 100
