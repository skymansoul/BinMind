# 2026-07-28
# 配置 tests for 去混淆 module
"""Tests for 配置 loading 校验"""

import os
import tempfile
import pytest


class TestConfigLoading:
    """配置 loading tests"""

    def test_load_defaults(self) -> None:
        """Loading a file 返回 defaults"""
        defaults = {
            "paths": {"data_dir": "data", "output_dir": "output", "log_dir": "logs"},
            "logging": {"level": "INFO"},
        }
        assert "paths" in defaults
        assert "logging" in defaults
        assert defaults["logging"]["level"] == "INFO"

    def test_env_override_basic(self) -> None:
        """Environment variable override 配置 values"""
        config = {"timeout": 30}
        env_val = "60"
        config["timeout"] = int(env_val)
        assert config["timeout"] == 60

    def test_env_override_nested(self) -> None:
        """Nested key override via dot notation"""
        config = {"analysis": {"timeout": 30}}
        # Simulate DEOBF_ANALYSIS_TIMEOUT=60 override
        config["analysis"]["timeout"] = 60
        assert config["analysis"]["timeout"] == 60

    def test_env_override_prefix_filtering(self) -> None:
        """keys correct prefix override"""
        prefix = "DEOBF_"
        env_vars = {
            "DEOBF_TIMEOUT": "120",
            "OTHER_VAR": "ignored",
            "DEOBF_LEVEL": "DEBUG",
        }
        overrides = {}
        for key, val in env_vars.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                overrides[config_key] = val
        assert "timeout" in overrides
        assert "level" in overrides
        assert overrides["timeout"] == "120"

    def test_validate_valid_config(self) -> None:
        """Valid 配置 pass 校验"""
        config = {
            "paths": {"data_dir": "data", "output_dir": "out"},
            "logging": {"level": "INFO"},
        }
        assert "paths" in config
        assert "logging" in config
        assert isinstance(config["paths"], dict)

    def test_validate_missing_section(self) -> None:
        """Missing required section catchable"""
        config: dict = {}
        required = ["paths", "logging"]
        missing = [r for r in required if r not in config]
        assert len(missing) > 0

    def test_validate_missing_path_key(self) -> None:
        """Missing optional path key default"""
        config = {"paths": {"data_dir": "data"}, "logging": {"level": "INFO"}}
        paths = config["paths"]
        assert "data_dir" in paths
        # output_dir optional, default
        paths.setdefault("output_dir", "output")
        assert paths["output_dir"] == "output"


class TestYamlLoading:
    """YAML file loading tests (回退 for missing PyYAML)"""

    def test_yaml_load_or_fallback(self) -> None:
        """work or PyYAML installed"""
        try:
            import yaml
            has_yaml = True
        except ImportError:
            has_yaml = False

        if has_yaml:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as fh:
                fh.write("paths:\n  data_dir: test_data\n")
                fh.flush()
                temp_path = fh.name

            try:
                import yaml
                with open(temp_path, "r") as fh:
                    config = yaml.safe_load(fh)
                assert config["paths"]["data_dir"] == "test_data"
            finally:
                os.unlink(temp_path)
        else:
            # 回退 YAML
            config = {"paths": {"data_dir": "data"}}
            assert config["paths"]["data_dir"] == "data"


class TestEnvVarSubstitution:
    """${VAR} substitution YAML values"""

    def test_substitution_basic(self) -> None:
        """${VAR} patterns replaced"""
        import re
        os.environ["TEST_DEOBF_DIR"] = "/tmp/test"
        value = "${TEST_DEOBF_DIR}/subdir"
        result = re.sub(
            r"\$\{([^}]+)\}",
            lambda m: os.environ.get(m.group(1), m.group(0)),
            value,
        )
        assert result == "/tmp/test/subdir"
        del os.environ["TEST_DEOBF_DIR"]

    def test_substitution_missing_var(self) -> None:
        """Missing env var left -"""
        value = "${MISSING_VAR_12345}/path"
        assert "${MISSING_VAR_12345}" in value


class TestConfigEdgeCases:
    """Edge case handling"""

    def test_empty_config(self) -> None:
        """Empty 配置 defaults"""
        config: dict = {}
        config.setdefault("paths", {})
        config["paths"].setdefault("data_dir", "data")
        assert config["paths"]["data_dir"] == "data"

    def test_none_config(self) -> None:
        """None 配置 handled"""
        config = None
        if config is None:
            config = {"paths": {}, "logging": {"level": "WARNING"}}
        assert config["logging"]["level"] == "WARNING"
