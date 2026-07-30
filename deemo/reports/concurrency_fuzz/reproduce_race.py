#!/usr/bin/env python3
"""
并发竞争复现脚本
目标: C:\Users\Administrator\AppData\Local\Temp\tmpylvhtkrt\test
"""

import subprocess
import json
import time
import sys

BINARY_PATH = "C:\Users\Administrator\AppData\Local\Temp\tmpylvhtkrt\test"

def reproduce_race(schedule):
    """
    使用指定调度复现竞争
    """
    print(f"尝试复现竞争，调度: {schedule}")

    # 设置环境变量
    env = {"CONC_FUZZ_SCHEDULE": json.dumps(schedule)}

    # 运行二进制
    try:
        result = subprocess.run(            [BINARY_PATH],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        print("输出:", result.stdout)
        print("错误:", result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("超时")
        return False

# 复现步骤
REPRODUCTION_STEPS = [
]

if __name__ == "__main__":
    for step in REPRODUCTION_STEPS:
        schedule = step.get("schedule", [])
        reproduce_race(schedule)
        time.sleep(1)
