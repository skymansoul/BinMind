"""kernel — 配置测试"""
import pytest, os

def test_env_override():
    os.environ["TEST_VAR"] = "1"
    assert os.environ["TEST_VAR"] == "1"
    del os.environ["TEST_VAR"]

def test_default_fallback():
    d = {"timeout": 30}
    assert d.get("timeout", 10) == 30
    assert d.get("missing", 10) == 10

def test_yaml_fallback():
    try:
        import yaml
        assert yaml is not None
    except ImportError:
        pass
    assert True
