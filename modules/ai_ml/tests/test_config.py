# tests/test_config.py — config loader + env override tests
import sys
import os
import json
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


class TestConfigLoader:
    """配置加载器"""

    def test_load_config_returns_dict(self):
        """加载配置返回字典"""
        # 旧代码: from src.config import load_config, reload_config
        # reload_config()
        from src.config import load_config, reload_config
        reload_config()
        cfg = load_config()
        assert isinstance(cfg, dict), f"expected dict, got {type(cfg)}"
        assert 'paths' in cfg
        assert 'logging' in cfg

    def test_get_dotted_key(self):
        """点分键查找"""
        from src.config import get, reload_config
        reload_config()
        level = get('logging.level')
        assert level is not None
        assert isinstance(level, str)

    def test_get_missing_key_returns_default(self):
        """缺失键返回默认值"""
        from src.config import get, reload_config
        reload_config()
        result = get('nonexistent.deep.key', 'fallback_42')
        assert result == 'fallback_42'

    def test_retry_config_present(self):
        """重试配置存在"""
        from src.config import get, reload_config
        reload_config()
        max_attempts = get('retry.max_attempts')
        assert max_attempts is not None
        assert max_attempts >= 1


class TestEnvOverride:
    """环境变量覆写"""

    def test_env_override_respected(self):
        """AIML_RETRY_MAX_ATTEMPTS覆写生效"""
        os.environ['AIML_RETRY_MAX_ATTEMPTS'] = '7'
        try:
            from src.config import load_config, reload_config
            reload_config()
            cfg = load_config()
            assert cfg['retry']['max_attempts'] == 7
        finally:
            del os.environ['AIML_RETRY_MAX_ATTEMPTS']

    def test_coerce_int(self):
        """_coerce转换整数"""
        from src.config import _coerce
        assert _coerce('42') == 42
        assert isinstance(_coerce('42'), int)

    def test_coerce_bool(self):
        """_coerce转换布尔"""
        from src.config import _coerce
        assert _coerce('true') is True
        assert _coerce('False') is False
        assert _coerce('NO') is False
