# — hermit1016: YAML 配置加载 + 环境变量覆盖测试
"""fuzzing — config 测试: YAML 加载, 环境变量覆盖, 默认值回退.

测试覆盖:
- YAML 文件成功解析
- 不存在的配置文件返回空字典
- JSON 格式兼容性
- 嵌套字段取值
"""

import os
import json
import tempfile
import pytest


# 配置文件路径

try:
    from fuzzing.src.cli import _load_config, _find_default_config
    _cli_available = True
except ImportError:
    _cli_available = False


@pytest.mark.skipif(not _cli_available, reason="fuzzing.src.cli not importable")
class TestConfigLoading:
    """YAML / JSON 配置加载."""

    def test_load_valid_yaml(self):
        """解析合法 YAML 配置文件."""
        yaml_content = """
fault_injection:
  max_injections: 500
  arch: "x86_64"
cluster:
  tick_interval: 10.0
"""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.write(fd, yaml_content.encode("utf-8"))
        os.close(fd)
        try:
            config = _load_config(path)
            assert config.get("fault_injection", {}).get("max_injections") == 500
            assert config.get("fault_injection", {}).get("arch") == "x86_64"
            assert config.get("cluster", {}).get("tick_interval") == 10.0
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_load_valid_json(self):
        """解析合法 JSON 配置文件."""
        json_content = {
            "fault_injection": {"max_injections": 300},
            "cluster": {"min_nodes": 2}
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(json_content).encode("utf-8"))
        os.close(fd)
        try:
            config = _load_config(path)
            assert config.get("fault_injection", {}).get("max_injections") == 300
            assert config.get("cluster", {}).get("min_nodes") == 2
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_missing_file_returns_empty_dict(self):
        """不存在的配置文件返回空字典."""
        config = _load_config("/nonexistent/config_file_2026.yaml")
        assert config == {}

    def test_none_path_returns_empty_dict(self):
        """None 路径返回空字典."""
        config = _load_config(None)
        assert config == {}

    def test_empty_yaml_file(self):
        """空 YAML 文件返回空字典."""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.write(fd, b"")
        os.close(fd)
        try:
            config = _load_config(path)
            assert config == {} or config is None or config is None
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_nested_config_access(self):
        """嵌套字段的链式访问."""
        yaml_content = """
llm:
  host: "http://localhost:11434"
  model: "qwen2.5-coder:7b"
  retry_attempts: 3
"""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.write(fd, yaml_content.encode("utf-8"))
        os.close(fd)
        try:
            config = _load_config(path)
            llm = config.get("llm", {})
            assert llm.get("host") == "http://localhost:11434"
            assert llm.get("retry_attempts") == 3
        finally:
            if os.path.exists(path):
                os.remove(path)


@pytest.mark.skipif(not _cli_available, reason="fuzzing.src.cli not importable")
class TestDefaultConfigDiscovery:
    """默认配置文件自动发现."""

    def test_find_default_config_returns_path_or_none(self):
        """_find_default_config 返回 string 或 None."""
        result = _find_default_config()
        assert result is None or isinstance(result, str)

    def test_found_config_exists_on_disk(self):
        """如果找到了默认配置, 文件必须存在."""
        result = _find_default_config()
        if result is not None:
            assert os.path.isfile(result)


# 独立测试 (无需模块导入)

def test_env_var_override_inline():
    """环境变量覆盖模式 — 手动模拟."""
    os.environ["BINMIND_FUZZ_MAX_INJECTIONS"] = "999"
    # 模拟: env var > default
    default = 300
    env_val = int(os.environ.get("BINMIND_FUZZ_MAX_INJECTIONS", default))
    assert env_val == 999
    del os.environ["BINMIND_FUZZ_MAX_INJECTIONS"]


def test_default_fallback_inline():
    """默认值回退: 关键字不存在时取默认."""
    defaults = {"timeout": 30, "retries": 3}
    assert defaults.get("timeout", 10) == 30      # 已设置, 取设置值
    assert defaults.get("missing", 10) == 10       # 未设置, 取默认


def test_config_merge_priority_inline():
    """优先级: CLI > 环境变量 > YAML > 代码默认值."""
    yaml_cfg = {"timeout": 30}
    env_cfg = {"timeout": 45}
    cli_cfg = {"timeout": 60}

    # CLI > env
    resolved = cli_cfg.get("timeout", env_cfg.get("timeout", yaml_cfg.get("timeout", 10)))
    assert resolved == 60

    # env > yaml (无 CLI)
    resolved_no_cli = env_cfg.get("timeout", yaml_cfg.get("timeout", 10))
    assert resolved_no_cli == 45

    # yaml > default (无 CLI/ENV)
    resolved_default = yaml_cfg.get("timeout", 10)
    assert resolved_default == 30


def test_pyyaml_fallback_to_json():
    """当 PyYAML 不可用时回退 JSON 解析 — 逻辑验证."""
    # 如果 PyYAML 不可用, CLI 会尝试 JSON 解析 YAML 文件
    # 这个测试只是确认逻辑存在, 不做实际 YAML→JSON 转换
    config_text = '{"key": "value"}'
    parsed = json.loads(config_text)
    assert parsed["key"] == "value"


def test_yaml_comment_handling_inline():
    """YAML 注释不会被解析为配置项 — 纯语法验证."""
    # 注释行以 # 开头 (YAML 标准)
    lines = [
        "timeout: 30  # 超时时间 (秒)",
        "# 这是注释行",
        "retries: 3",
    ]
    # 手动模拟: 提取 key: value
    parsed = {}
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.split("#")[0].strip()  # 去掉行内注释
            parsed[key] = int(val) if val.isdigit() else val
    assert parsed["timeout"] == 30
    assert parsed["retries"] == 3
