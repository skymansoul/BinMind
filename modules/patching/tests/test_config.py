"""Config 测试。

覆盖：ConfigDict 属性访问、YAML 解析、load_config 合并、
reset_config、PatchConfig 数据类、环境变量覆盖。
"""

import sys, os, json, pytest, tempfile

_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
_src = os.path.join(_patch, 'src')
_modules = os.path.dirname(_patch)
if _modules not in sys.path:
    sys.path.insert(0, _modules)
if _patch not in sys.path:
    sys.path.insert(0, _patch)

from src.config import (
    ConfigDict, config, load_config, reset_config,
    PatchConfig, save_config, _parse_yaml_simple,
    _load_yaml_file, _DEFAULTS,
)


class TestConfigDict:
    """ConfigDict —— 带属性访问的 dict，统一两种 API。"""

    def test_attribute_access(self):
        cd = ConfigDict({'KEY': 'value'})
        assert cd.KEY == 'value'

    def test_dict_get(self):
        cd = ConfigDict({'KEY': 'value'})
        assert cd.get('KEY') == 'value'
        assert cd.get('MISSING', 'default') == 'default'

    def test_setattr(self):
        cd = ConfigDict()
        cd.NEW_KEY = 'new_value'
        assert cd['NEW_KEY'] == 'new_value'

    def test_delattr(self):
        cd = ConfigDict({'KEY': 'value'})
        del cd.KEY
        assert 'KEY' not in cd

    def test_missing_attr_returns_none(self):
        """缺失属性返回 None 而非 AttributeError。

        这是有意为之 —— 旧代码用 getattr(config, 'KEY', 'fallback')。
        """
        cd = ConfigDict()
        assert cd.NONEXISTENT is None

    def test_copy_is_independent(self):
        cd = ConfigDict({'A': 1})
        cd2 = cd.copy()
        cd2.A = 99
        assert cd.A == 1  # 原对象未变
        assert cd2.A == 99


class TestYamlParsing:
    """_parse_yaml_simple —— 内置 YAML 子集解析器。"""

    def test_basic_key_value(self):
        r = _parse_yaml_simple("key: value")
        assert r['KEY'] == 'value'

    def test_boolean_true(self):
        r = _parse_yaml_simple("enabled: true")
        assert r['ENABLED'] is True

    def test_boolean_false(self):
        r = _parse_yaml_simple("enabled: false")
        assert r['ENABLED'] is False

    def test_integer(self):
        r = _parse_yaml_simple("timeout: 120")
        assert r['TIMEOUT'] == 120

    def test_float(self):
        r = _parse_yaml_simple("threshold: 10.5")
        assert r['THRESHOLD'] == 10.5

    def test_quoted_string(self):
        r = _parse_yaml_simple('model: "gpt-4"')
        assert r['MODEL'] == 'gpt-4'

    def test_null_value(self):
        r = _parse_yaml_simple("api_key: null")
        assert r['API_KEY'] is None

    def test_comment_line_ignored(self):
        r = _parse_yaml_simple("# this is a comment\nkey: value")
        assert 'KEY' in r
        assert r['KEY'] == 'value'

    def test_empty_string(self):
        r = _parse_yaml_simple("")
        assert r == {}

    def test_tilde_expansion(self):
        r = _parse_yaml_simple("log_file: ~/logs/patching.log")
        assert r['LOG_FILE'].startswith(os.path.expanduser('~'))


class TestYamlFileLoading:
    """_load_yaml_file —— 完整 YAML 文件加载。"""

    def test_load_from_temp_file(self):
        yaml_content = "ai_provider: \"anthropic\"\nlog_level: \"DEBUG\"\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            tmp = f.name
        try:
            data = _load_yaml_file(tmp)
            assert data.get('AI_PROVIDER') == 'anthropic' or data.get('AI_PROVIDER') == 'anthropic'
        finally:
            os.unlink(tmp)

    def test_missing_file(self):
        data = _load_yaml_file("/nonexistent/path/config.yaml")
        assert data == {}


class TestLoadConfig:
    """load_config —— YAML 加载、环境覆盖、默认合并。"""

    def test_defaults_present(self):
        """重置并验证默认值存在。"""
        reset_config()
        c = config
        assert c.AI_PROVIDER == 'openai'
        assert c.SUBPROCESS_TIMEOUT == 120
        assert c.LOG_LEVEL == 'INFO'

    def test_reset_restores_defaults(self):
        # 用模块引用追踪 reset_config() 中的重赋值
        import src.config as _cfg
        _cfg.config.TEST_RESET = 'modified'
        _cfg.reset_config()
        assert _cfg.config.get('TEST_RESET') is None

    def test_env_override_bool(self):
        import src.config as _cfg
        _cfg.reset_config()
        os.environ['BINMIND_PATCH_SANDBOX_ENABLED'] = 'false'
        try:
            _cfg.load_config()
            assert _cfg.config.SANDBOX_ENABLED is False
        finally:
            del os.environ['BINMIND_PATCH_SANDBOX_ENABLED']
            _cfg.reset_config()

    def test_env_override_int(self):
        import src.config as _cfg
        _cfg.reset_config()
        os.environ['BINMIND_PATCH_SUBPROCESS_TIMEOUT'] = '300'
        try:
            _cfg.load_config()
            assert _cfg.config.SUBPROCESS_TIMEOUT == 300
        finally:
            del os.environ['BINMIND_PATCH_SUBPROCESS_TIMEOUT']
            _cfg.reset_config()

    def test_load_custom_yaml(self):
        import src.config as _cfg
        yaml_content = "ai_provider: \"anthropic\"\nlog_level: \"ERROR\"\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            tmp = f.name
        try:
            _cfg.reset_config()
            _cfg.load_config(tmp)
            assert _cfg.config.AI_PROVIDER == 'anthropic'
        finally:
            os.unlink(tmp)
            _cfg.reset_config()


class TestPatchConfig:
    """PatchConfig 数据类 —— 向后兼容。"""

    def test_default_construction(self):
        pc = PatchConfig()
        assert pc.r2_timeout == 30
        assert pc.subprocess_timeout == 120

    def test_custom_values(self):
        pc = PatchConfig(r2_timeout=60, arch="arm64")
        assert pc.r2_timeout == 60
        assert pc.arch == "arm64"

    def test_save_config(self):
        pc = PatchConfig(r2_timeout=45)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp = f.name
        try:
            save_config(pc, tmp)
            with open(tmp, 'r') as f2:
                data = json.load(f2)
            assert data['r2_timeout'] == 45
        finally:
            os.unlink(tmp)
