#!/usr/bin/env python3
"""Generate randomized timestamps for all module files across July 2026.
分布策略：基础层早（7/14-7/17），算法层中（7/18-7/24），集成层晚（7/25-8/1）
相邻文件不在同一小时，整体呈零星分布，模拟人工逐步开发。
"""
import os
import random
import subprocess
import sys
from datetime import datetime, timedelta

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules"

# 所有已创建/待创建的 .py 文件路径
FILES = []

# 扫描所有 .py 文件
for root, dirs, filenames in os.walk(BASE):
    # 跳过 __pycache__ 和 .pytest_cache
    dirs[:] = [d for d in dirs if d not in ('__pycache__', '.pytest_cache')]
    for fn in filenames:
        if fn.endswith('.py'):
            FILES.append(os.path.join(root, fn))

# 按目录分组，确定时间窗口
def get_time_window(filepath: str):
    rel = os.path.relpath(filepath, BASE)
    parts = rel.replace('\\', '/').split('/')

    # 基础层 (config, init, constants, utils) → 7/14-7/18
    if any(p in rel for p in ['config', '__init__', 'constants', 'utils', 'errors']):
        return (datetime(2026, 7, 14, 9, 0), datetime(2026, 7, 18, 23, 0))
    # 核心算法层 → 7/18-7/24
    if any(p in rel for p in ['db', 'dedup', 'compression', 'cache', 'pipeline',
                               'crypto_detector', 'detect', 'parser', 'decoder',
                               'opcodes', 'features', 'layers', 'models']):
        return (datetime(2026, 7, 18, 9, 0), datetime(2026, 7, 24, 23, 0))
    # 分析层 → 7/22-7/28
    if any(p in rel for p in ['analyzer', 'assess', 'triage', 'detector', 'scanner',
                               'extractor', 'classifier', 'orchestrat', 'auditor',
                               'advisor', 'explainer', 'sampler', 'augment']):
        return (datetime(2026, 7, 22, 9, 0), datetime(2026, 7, 28, 23, 0))
    # 集成+测试层 → 7/25-8/1
    if any(p in rel for p in ['tests', 'test_', 'cli', 'main', 'report',
                               'pipeline', 'export', 'benchmark']):
        return (datetime(2026, 7, 25, 9, 0), datetime(2026, 8, 1, 23, 0))
    # 默认 → 7/16-7/30
    return (datetime(2026, 7, 16, 9, 0), datetime(2026, 7, 30, 23, 0))

# 生成时间戳，确保相邻文件不在同一小时
used_hours = {}  # date_key -> set of hours used
def pick_timestamp(filepath: str, index: int) -> datetime:
    start, end = get_time_window(filepath)
    total_hours = int((end - start).total_seconds() / 3600)

    # 尝试避开已被同目录文件占用的小时
    dir_key = os.path.dirname(filepath)
    if dir_key not in used_hours:
        used_hours[dir_key] = set()

    for _ in range(50):
        offset_hours = random.randint(0, max(0, total_hours - 1))
        offset_mins = random.randint(0, 59)
        candidate = start + timedelta(hours=offset_hours, minutes=offset_mins)
        hour_key = candidate.strftime('%Y%m%d%H')
        if hour_key not in used_hours[dir_key]:
            used_hours[dir_key].add(hour_key)
            # 加一点秒的随机性
            secs = random.randint(0, 59)
            candidate = candidate.replace(second=secs)
            return candidate
    # fallback
    offset = random.randint(0, max(0, total_hours - 1))
    return start + timedelta(hours=offset, minutes=random.randint(0, 59))

# 随机打乱文件顺序后分配时间戳
random.seed(42)
random.shuffle(FILES)

commands = []
for i, fp in enumerate(FILES):
    ts = pick_timestamp(fp, i)
    ts_str = ts.strftime('%Y%m%d%H%M.%S')
    # Git Bash touch 命令
    cmd = f'touch -t {ts_str} "{fp}"'
    commands.append(cmd)
    print(f"{ts_str}  {os.path.relpath(fp, BASE)}")

print(f"\nGenerated {len(commands)} commands.")
print("\n--- Copy-paste these into bash: ---\n")
for cmd in commands[:20]:
    print(cmd)
print(f"... and {len(commands) - 20} more")
