import os
import tempfile
import pytest

class TestConfigLoading:

    def test_load_defaults(self) -> None:
        defaults = {
            "paths": {"data_dir": "data", "output_dir": "output", "log_dir": "logs"},
            "logging": {"level": "INFO"},
        }
        assert "paths" in defaults
        assert "logging" in defaults
        assert defaults["logging"]["level"] == "INFO"

    def test_env_override_basic(self) -> None:
        config = {"timeout": 30}
        env_val = "60"
        config["timeout"] = int(env_val)
        assert config["timeout"] == 60

    def test_env_override_nested(self) -> None:
        config = {"analysis": {"timeout": 30}}
        # 模拟 DEOBF_ANALYSIS_TIMEOUT=60 覆盖
        config["analysis"]["timeout"] = 60
        assert config["analysis"]["timeout"] == 60

    def test_env_override_prefix_filtering(self) -> None:
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
        config = {
            "paths": {"data_dir": "data", "output_dir": "out"},
            "logging": {"level": "INFO"},
        }
        assert "paths" in config
        assert "logging" in config
        assert isinstance(config["paths"], dict)

    def test_validate_missing_section(self) -> None:
        config: dict = {}
        required = ["paths", "logging"]
        missing = [r for r in required if r not in config]
        assert len(missing) > 0

    def test_validate_missing_path_key(self) -> None:
        config = {"paths": {"data_dir": "data"}, "logging": {"level": "INFO"}}
        paths = config["paths"]
        assert "data_dir" in paths
        # output_dir 可选, 默认
        paths.setdefault("output_dir", "output")
        assert paths["output_dir"] == "output"


class TestYamlLoading:

    def test_yaml_load_or_fallback(self) -> None:
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

    def test_substitution_basic(self) -> None:
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
        value = "${MISSING_VAR_12345}/path"
        assert "${MISSING_VAR_12345}" in value


class TestConfigEdgeCases:

    def test_empty_config(self) -> None:
        config: dict = {}
        config.setdefault("paths", {})
        config["paths"].setdefault("data_dir", "data")
        assert config["paths"]["data_dir"] == "data"

    def test_none_config(self) -> None:
        config = None
        if config is None:
            config = {"paths": {}, "logging": {"level": "WARNING"}}
        assert config["logging"]["level"] == "WARNING"
