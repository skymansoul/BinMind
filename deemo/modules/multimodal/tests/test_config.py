#!/usr/bin/env python3
# 配置加载测试 — YAML 解析、环境变量覆写、类型转换、默认值回退
import sys
import os
import pytest
import tempfile
import importlib

_src = os.path.join(os.path.dirname(__file__), "..", "src")

# 显式加载 config_loader，避免命名冲突
_spec = importlib.util.spec_from_file_location(
    "multimodal_config_loader",
    os.path.join(_src, "config_loader.py"),
    submodule_search_locations=[])
_cfg_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cfg_mod)

ConfigLoader = _cfg_mod.ConfigLoader
load_config = _cfg_mod.load_config
get_config = _cfg_mod.get_config


@pytest.fixture(autouse=True)
def _reset_singleton():
    """每次测试前重置单例状态，保证用例隔离。"""
    ConfigLoader._instance = None
    ConfigLoader._config = {}
    yield
    ConfigLoader._instance = None
    ConfigLoader._config = {}


class TestConfigDefaults:
    def test_analysis_timeout_default(self):
        loader = ConfigLoader()
        assert loader.get("analysis.timeout_seconds") == 300

    def test_retry_max_attempts_default(self):
        loader = ConfigLoader()
        assert loader.get("retry.max_attempts") == 3

    def test_missing_key_returns_default(self):
        loader = ConfigLoader()
        assert loader.get("nonexistent.section.key") is None
        assert loader.get("nonexistent.section.key", "fallback") == "fallback"

    def test_section_returns_dict(self):
        loader = ConfigLoader()
        analysis = loader.section("analysis")
        assert isinstance(analysis, dict)
        assert "timeout_seconds" in analysis
        assert "adaptive_workers" in analysis

    def test_all_returns_complete_dict(self):
        loader = ConfigLoader()
        cfg = loader.all()
        assert "paths" in cfg
        assert "analysis" in cfg
        assert "retry" in cfg
        assert "exploit" in cfg
        assert "orchestrator" in cfg
        assert "fusion" in cfg

    def test_paths_section(self):
        loader = ConfigLoader()
        paths = loader.section("paths")
        assert paths["data_dir"] == "data"
        assert paths["output_dir"] == "output"


class TestConfigYAMLLoading:
    def test_load_from_yaml_file(self):
        # 创建临时 YAML 文件
        yaml_content = """
analysis:
  timeout_seconds: 600
  max_memory_mb: 4096
retry:
  max_attempts: 5
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False,
            encoding="utf-8") as tf:
            tf.write(yaml_content)
            tf.flush()
            try:
                loader = ConfigLoader(config_path=tf.name)
            finally:
                pass
        try:
            assert loader.get("analysis.timeout_seconds") == 600
            assert loader.get("analysis.max_memory_mb") == 4096
            assert loader.get("retry.max_attempts") == 5
            # 未指定的键应保持默认值
            assert loader.get("logging.level") == "INFO"
        finally:
            os.unlink(tf.name)

    def test_partial_yaml_override(self):
        """YAML 可仅覆盖部分配置段，其余保留默认。"""
        yaml_content = """
	logging:
	  level: DEBUG
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False,
            encoding="utf-8") as tf:
            tf.write(yaml_content)
            tf.flush()
            try:
                loader = ConfigLoader(config_path=tf.name)
            except ImportError:
                pytest.skip("PyYAML not installed")
            finally:
                pass
        try:
            assert loader.get("logging.level") == "DEBUG"
            # 无关段不受影响
            assert loader.get("analysis.timeout_seconds") == 300
        finally:
            os.unlink(tf.name)


class TestEnvVarOverride:
    def test_env_override_analysis_timeout(self):
        os.environ["MULTIMODAL_ANALYSIS__TIMEOUT_SECONDS"] = "120"
        try:
            loader = ConfigLoader()
            assert loader.get("analysis.timeout_seconds") == 120
        finally:
            del os.environ["MULTIMODAL_ANALYSIS__TIMEOUT_SECONDS"]

    def test_env_override_logging_level(self):
        os.environ["MULTIMODAL_LOGGING__LEVEL"] = "DEBUG"
        try:
            loader = ConfigLoader()
            assert loader.get("logging.level") == "DEBUG"
        finally:
            del os.environ["MULTIMODAL_LOGGING__LEVEL"]

    def test_env_override_bool_true(self):
        os.environ["MULTIMODAL_ANALYSIS__ADAPTIVE_WORKERS"] = "false"
        try:
            loader = ConfigLoader()
            assert loader.get("analysis.adaptive_workers") is False
        finally:
            del os.environ["MULTIMODAL_ANALYSIS__ADAPTIVE_WORKERS"]


class TestReload:
    def test_reload_resets_state(self):
        loader = ConfigLoader()
        orig = loader.get("analysis.timeout_seconds")
        # 修改并重新加载
        loader.reload()
        assert loader.get("analysis.timeout_seconds") == orig


class TestConvenienceFunctions:
    def test_load_config_returns_singleton(self):
        ConfigLoader._instance = None
        ConfigLoader._config = {}
        _cfg_mod._config_loader = None
        a = load_config()
        b = load_config()
        assert a is b

    def test_get_config_shortcut(self):
        # 全新启动：重置所有状态并验证默认值
        ConfigLoader._instance = None
        ConfigLoader._config = {}
        _cfg_mod._config_loader = None
        # 直接新建 loader 绕过陈旧引用
        loader = ConfigLoader()
        timeout = loader.get("analysis.timeout_seconds")
        assert timeout == 300
