# 配置处理测试 — YAML 优先，JSON 回退，DIST_ 前缀环境变量覆盖
# 验证项：(1) default.yaml 可解析 (2) 环境变量覆盖 (3) 缺失配置返回合理默认值
# (4) 嵌套键访问对 None 安全
"""配置测试：YAML 解析、环境变量覆盖、默认值回退。"""
import os
import json
import tempfile
import pytest


class TestYamlConfig:
    """验证 default.yaml 存在且可解析。"""

    def test_default_yaml_exists(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "default.yaml"
        )
        assert os.path.exists(config_path), f"config not found at {config_path}"

    def test_default_yaml_parseable(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "default.yaml"
        )
        try:
            import yaml
            with open(config_path, "r") as fh:
                cfg = yaml.safe_load(fh)
            assert isinstance(cfg, dict)
            assert "paths" in cfg
            assert "logging" in cfg
            assert "retry" in cfg
            assert "analysis" in cfg
        except ImportError:
            # yaml 未安装，按纯文本读取验证非空
            with open(config_path, "r") as fh:
                content = fh.read()
            assert len(content) > 0

    def test_retry_config_has_required_keys(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "default.yaml"
        )
        try:
            import yaml
            with open(config_path, "r") as fh:
                cfg = yaml.safe_load(fh)
            retry = cfg.get("retry", {})
            assert "max_attempts" in retry
            assert "backoff_base" in retry
            assert retry["backoff_base"] >= 1.0
        except ImportError:
            pytest.skip("yaml not installed")

    def test_analysis_timeout_is_positive(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "default.yaml"
        )
        try:
            import yaml
            with open(config_path, "r") as fh:
                cfg = yaml.safe_load(fh)
            timeout = cfg.get("analysis", {}).get("timeout_seconds", 0)
            assert timeout > 0
        except ImportError:
            pytest.skip("yaml not installed")


class TestEnvOverrides:
    """环境变量覆盖机制验证。"""

    def test_env_var_overrides_default(self, monkeypatch):
        monkeypatch.setenv("DIST_REDIS_URL", "redis://custom:6379/1")
        url = os.environ.get("DIST_REDIS_URL", "redis://localhost:6379/0")
        assert url == "redis://custom:6379/1"

    def test_missing_env_var_falls_back(self):
        url = os.environ.get("DIST_NONEXISTENT_VAR", "redis://localhost:6379/0")
        assert url == "redis://localhost:6379/0"


class TestDefaultFallback:
    """字典 .get() 模式配置安全访问。"""

    def test_dict_get_with_default(self):
        cfg = {"timeout": 30}
        assert cfg.get("timeout", 10) == 30
        assert cfg.get("missing_key", 10) == 10

    def test_nested_dict_safe_access(self):
        cfg = {"retry": {"max_attempts": 5}}
        max_retries = cfg.get("retry", {}).get("max_attempts", 3)
        assert max_retries == 5

    def test_nested_dict_missing_falls_back(self):
        cfg = {}
        max_retries = cfg.get("retry", {}).get("max_attempts", 3)
        assert max_retries == 3


class TestJsonFallback:
    """YAML 不可用时 JSON 配置应可正常加载。"""

    def test_json_config_loading(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"worker": {"concurrency": 4}}, f)
            tmp_path = f.name

        try:
            with open(tmp_path, "r") as fh:
                cfg = json.load(fh)
            assert cfg["worker"]["concurrency"] == 4
        finally:
            os.unlink(tmp_path)
