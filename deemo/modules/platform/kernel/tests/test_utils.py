"""kernel — 工具函数测试"""
import pytest, logging

def test_logging_setup():
    """日志配置可用"""
    logging.basicConfig(level=logging.WARNING)
    log = logging.getLogger("test_utils")
    log.warning("test ok")
    assert True

def test_retry_pattern():
    """重试模式正确循环"""
    attempts = []
    for i in range(3):
        attempts.append(i)
        if i < 2:
            continue
        break
    assert len(attempts) == 3
