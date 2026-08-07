"""
测试第二十七次补充的新模块 — 聚合入口.

实际测试已拆分至:
  - test_new_modules_27_part1.py: JIT / Syscall / AI Namer
  - test_new_modules_27_part2.py: Crypto / Fuzzer / Integration

本文件仅做 re-export 以维持向后兼容的导入路径.
"""
import pytest

from tests.test_new_modules_27_part1 import *  # noqa: F401,F403
from tests.test_new_modules_27_part2 import *  # noqa: F401,F403

if __name__ == '__main__':
    pytest.main(['test_new_modules_27_part1.py', 'test_new_modules_27_part2.py', '-v'])
