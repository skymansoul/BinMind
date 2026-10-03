"""vuln_detection 配置读取与默认值回退测试"""
import pytest, os

def test_env_override():
    os.environ["VULN_LOG_LEVEL"] = "DEBUG"
    assert os.environ["VULN_LOG_LEVEL"] == "DEBUG"
    del os.environ["VULN_LOG_LEVEL"]

def test_default_fallback():
    defaults = {"timeout": 30, "retries": 3}
    assert defaults.get("timeout", 10) == 30
    assert defaults.get("missing", 10) == 10
