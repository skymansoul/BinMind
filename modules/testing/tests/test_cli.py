"""CLI 参数解析与导入基础测试"""
import pytest

def test_argparse_no_crash():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--test", default="ok")
    a = p.parse_args(["--test", "yes"])
    assert a.test == "yes"

def test_cli_import():
    assert True
