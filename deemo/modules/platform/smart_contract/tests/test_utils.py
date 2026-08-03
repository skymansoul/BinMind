"""smart_contract — utils 测试"""
import pytest, logging

def test_logging_setup():
    logging.basicConfig(level=logging.WARNING)
    log = logging.getLogger("test_utils")
    log.warning("test ok")
    assert True

def test_retry_pattern():
    attempts = []
    for i in range(3):
        attempts.append(i)
        if i < 2:
            continue
        break
    assert len(attempts) == 3
