"""移动端——配置系统测试"""
import pytest
import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from config_fallback import Config, get_config


class TestConfigDefaults:
    """确认Config类的默认值及基础读写操作。"""

    def test_singleton_returns_same_instance(self):
        Config.reset()
        c1 = Config.instance()
        c2 = Config.instance()
        assert c1 is c2

    def test_default_values_present(self):
        Config.reset()
        c = Config.instance()
        assert c.get('SUBPROCESS_TIMEOUT') == 300
        assert c.get('MAX_RETRIES') == 3
        assert c.get('LOG_LEVEL') == 'INFO'
        assert c.get('OUTPUT_FORMAT') == 'json'

    def test_get_returns_default_for_missing(self):
        Config.reset()
        c = Config.instance()
        assert c.get('NONEXISTENT_KEY') is None
        assert c.get('NONEXISTENT_KEY', 'fallback') == 'fallback'

    def test_set_and_get(self):
        Config.reset()
        c = Config.instance()
        c.set('TEST_KEY', 'test_value')
        assert c.get('TEST_KEY') == 'test_value'

    def test_update_bulk(self):
        Config.reset()
        c = Config.instance()
        c.update({'KEY_A': 1, 'KEY_B': 2})
        assert c.get('KEY_A') == 1
        assert c.get('KEY_B') == 2

    def test_to_dict_returns_copy(self):
        Config.reset()
        c = Config.instance()
        d = c.to_dict()
        assert isinstance(d, dict)
        assert 'LOG_LEVEL' in d
        # 修改返回dict不影响原Config
        d['LOG_LEVEL'] = 'DEBUG'
        assert c.get('LOG_LEVEL') == 'INFO'


class TestConfigEnvLoading:
    """确认从环境变量加载覆盖配置。"""

    def test_env_var_override_int(self):
        Config.reset()
        os.environ['BINMIND_MAX_RETRIES'] = '5'
        try:
            c = Config.instance()
            c.load_from_env()
            assert c.get('MAX_RETRIES') == 5
        finally:
            del os.environ['BINMIND_MAX_RETRIES']

    def test_env_var_override_float(self):
        Config.reset()
        os.environ['BINMIND_RETRY_DELAY'] = '2.5'
        try:
            c = Config.instance()
            c.load_from_env()
            assert c.get('RETRY_DELAY') == 2.5
        finally:
            del os.environ['BINMIND_RETRY_DELAY']

    def test_env_var_override_str(self):
        Config.reset()
        os.environ['BINMIND_LOG_LEVEL'] = 'DEBUG'
        try:
            c = Config.instance()
            c.load_from_env()
            assert c.get('LOG_LEVEL') == 'DEBUG'
        finally:
            del os.environ['BINMIND_LOG_LEVEL']

    def test_env_var_override_invalid_int(self):
        Config.reset()
        os.environ['BINMIND_MAX_RETRIES'] = 'not_a_number'
        try:
            c = Config.instance()
            c.load_from_env()
            # 解析失败保持默认值
            assert c.get('MAX_RETRIES') == 3
        finally:
            del os.environ['BINMIND_MAX_RETRIES']


class TestConfigFileIO:
    """确认JSON文件读写配置。"""

    def test_load_from_json_file(self):
        Config.reset()
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False) as f:
            json.dump({'TEST_KEY': 'from_file', 'MAX_RETRIES': 10}, f)
            f.flush()
            try:
                c = Config.instance()
                c.load_from_file(f.name)
                assert c.get('TEST_KEY') == 'from_file'
                assert c.get('MAX_RETRIES') == 10
            finally:
                os.unlink(f.name)

    def test_load_nonexistent_file_does_not_crash(self):
        Config.reset()
        c = Config.instance()
        result = c.load_from_file('/nonexistent/path/config.json')
        assert result is c  # 返回自身

    def test_save_to_file(self):
        Config.reset()
        c = Config.instance()
        c.set('SAVE_TEST', 'saved_value')
        with tempfile.NamedTemporaryFile(suffix='.json', mode='r', delete=False) as f:
            f.close()
            try:
                c.save_to_file(f.name)
                with open(f.name, 'r') as rf:
                    data = json.load(rf)
                assert data.get('SAVE_TEST') == 'saved_value'
            finally:
                os.unlink(f.name)


class TestGetConfig:
    """确认便捷函数get_config()。"""

    def test_get_config_returns_config_instance(self):
        Config.reset()
        c = get_config()
        assert isinstance(c, Config)

    def test_reset_creates_new_instance(self):
        Config.reset()
        c1 = Config.instance()
        Config.reset()
        c2 = Config.instance()
        assert c1 is not c2

    def test_debug_print_exists(self):
        """config_fallback含_debug_print空操作桩。"""
        from config_fallback import _debug_print
        assert callable(_debug_print)
        assert _debug_print("test") is None
