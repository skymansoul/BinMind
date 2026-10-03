#!/usr/bin/env python3
"""路径可行性检查路径条件感知回归测试 —验证路径可行性检查过滤路径约束收集验证误报且不引入漏报."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from tests.test_path_feasibility_regression_samples import run_all

if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
