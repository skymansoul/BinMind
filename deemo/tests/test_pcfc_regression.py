#!/usr/bin/env python3
"""PCFC路径条件感知回归测试 —验证PCFC过滤FCPV误报且不引入漏报."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from tests.test_pcfc_regression_samples import run_all

if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
