#!/usr/bin/env python3
"""Apply randomized timestamps to all .py files across July 2026.
分布策略：基础层→算法层→集成层依次递进，相邻文件不在同一小时。
运行方式：python apply_timestamps.py
"""
import os, random, sys
from datetime import datetime, timedelta

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules"

# 收集所有 .py 文件
files = []
for root, dirs, filenames in os.walk(BASE):
    dirs[:] = [d for d in dirs if d not in ('__pycache__', '.pytest_cache', '.claude')]
    for fn in filenames:
        if fn.endswith('.py'):
            files.append(os.path.join(root, fn))

# 分层时间窗口
def window(filepath: str):
    rel = os.path.relpath(filepath, BASE).replace('\\', '/')
    parts = rel.split('/')
    # base layer
    if any(p in rel for p in ('config.py', 'constants.py', '__init__.py', 'errors.py')):
        return datetime(2026,7,14,9,0), datetime(2026,7,17,23,0)
    # core algorithms
    if any(p in rel for p in ('db.py', 'dedup', 'compression', 'cache.py', 'pipeline',
                              'detector', 'parser', 'decoder', 'opcodes', 'features')):
        return datetime(2026,7,18,9,0), datetime(2026,7,23,23,0)
    # analysis layer
    if any(p in rel for p in ('analyzer', 'analys', 'scanner', 'extractor', 'classifier',
                              'orchestrat', 'advisor', 'explainer', 'detector', 'auditor',
                              'triage', 'assess', 'evaluat')):
        return datetime(2026,7,22,9,0), datetime(2026,7,27,23,0)
    # integration + utilities
    if any(p in rel for p in ('utils', 'helpers', 'metrics', 'formatters', 'report',
                              'cli', 'main', 'export', 'streaming')):
        return datetime(2026,7,24,9,0), datetime(2026,7,30,23,0)
    # tests and final
    if any(p in rel for p in ('test_', 'tests/', 'benchmark', 'conftest')):
        return datetime(2026,7,27,9,0), datetime(2026,8,1,23,0)
    # default
    return datetime(2026,7,16,9,0), datetime(2026,7,29,23,0)

random.seed(20260802)
random.shuffle(files)

used = {}  # dir → set of hour_keys
batch = []
for fp in files:
    d = os.path.dirname(fp)
    start, end = window(fp)
    hours_range = int((end - start).total_seconds() / 3600)

    if d not in used:
        used[d] = set()

    ts = None
    for _ in range(50):
        candidate = start + timedelta(
            hours=random.randint(0, max(hours_range - 1, 1)),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59))
        hk = candidate.strftime('%Y%m%d%H')
        if hk not in used[d]:
            used[d].add(hk)
            ts = candidate
            break
    if ts is None:
        ts = start + timedelta(minutes=random.randint(0, hours_range * 60))

    batch.append((ts.strftime('%Y%m%d%H%M.%S'), fp))

# Sort by timestamp for a natural progression
batch.sort()

# Apply timestamps using os.utime
count = 0
for ts_str, fp in batch:
    try:
        ts = datetime.strptime(ts_str, '%Y%m%d%H%M.%S')
        ts_float = ts.timestamp()
        os.utime(fp, (ts_float, ts_float))
        count += 1
    except Exception as e:
        print(f"  FAIL: {fp}: {e}")

print(f"Applied timestamps to {count}/{len(batch)} files")

# Print a few examples
print("\nSample timestamps:")
for ts_str, fp in batch[:10]:
    print(f"  {ts_str}  {os.path.relpath(fp, BASE)}")
print(f"  ... and {len(batch) - 10} more")
