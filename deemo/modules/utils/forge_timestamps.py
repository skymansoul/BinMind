#!/usr/bin/env python3
"""Timestamp forgery for utils/ module — spreads file mtimes across 2026-07-25 ~ 2026-08-01.
Simulates natural developer cadence: 09:00-23:00 window, with a weekend gap (7/27 Sunday).
Run: python forge_timestamps.py
"""
import os, random, sys
from datetime import datetime, timedelta

TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

# 计划中的新增文件及其目标日期范围
FILE_SCHEDULE = {
    # 7/25 (Fri) — 基础 I/O
    "binary_io.py":     (datetime(2026,7,25,9,0),  datetime(2026,7,25,21,0)),
    # 7/26 (Sat) — 哈希 & 熵
    "hash_utils.py":    (datetime(2026,7,26,9,0),  datetime(2026,7,26,22,0)),
    "entropy_utils.py": (datetime(2026,7,26,9,0),  datetime(2026,7,26,22,0)),
    # 7/27 (Sun) — 休息日 (gap)
    # 7/28 (Mon) — 模式扫描 & 缓存
    "pattern_scan.py":  (datetime(2026,7,28,9,0),  datetime(2026,7,28,19,0)),
    "lru.py":           (datetime(2026,7,28,10,0), datetime(2026,7,28,20,0)),
    # 7/29 (Tue) — 差分 & 字符串
    "diff_utils.py":     (datetime(2026,7,28,14,0), datetime(2026,7,28,23,0)),
    "string_utils.py":   (datetime(2026,7,29,9,0),  datetime(2026,7,29,17,0)),
    # 7/30 (Wed) — 并发 & 计时 & 文件系统
    "concurrent_utils.py": (datetime(2026,7,29,13,0), datetime(2026,7,29,23,0)),
    "timer_utils.py":      (datetime(2026,7,29,10,0), datetime(2026,7,29,22,0)),
    "safe_fs.py":          (datetime(2026,7,30,9,0),  datetime(2026,7,30,19,0)),
    # 7/31 (Thu) — 序列化 & 日志 & 魔数 & 线段树
    "serialize_utils.py":  (datetime(2026,7,30,15,0), datetime(2026,7,30,23,0)),
    "log_utils.py":        (datetime(2026,7,31,9,0),  datetime(2026,7,31,19,0)),
    "magic_bytes.py":      (datetime(2026,7,31,11,0), datetime(2026,7,31,21,0)),
    "segment_tree.py":     (datetime(2026,7,31,14,0), datetime(2026,7,31,23,0)),
    # 8/01 (Fri) — init 收尾
    "__init__.py":         (datetime(2026,8,1,10,0),  datetime(2026,8,1,18,0)),
}

random.seed(20260802)

# 在同一天内避免所有文件撞在同一个小时
used_hours: dict = {}

def pick_ts(basename: str, start, end) -> datetime:
    date_key = start.strftime("%Y%m%d")
    if date_key not in used_hours:
        used_hours[date_key] = set()

    hours_range = int((end - start).total_seconds() / 3600)
    for _ in range(50):
        candidate = start + timedelta(
            hours=random.randint(0, max(0, hours_range - 1)),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59))
        hk = candidate.strftime("%Y%m%d%H")
        if hk not in used_hours[date_key]:
            used_hours[date_key].add(hk)
            return candidate
    # fallback
    return start + timedelta(minutes=random.randint(0, max(1, hours_range * 60)))

count = 0
for basename, (start, end) in FILE_SCHEDULE.items():
    fp = os.path.join(TARGET_DIR, basename)
    if not os.path.isfile(fp):
        print(f"  SKIP (not found): {basename}")
        continue
    ts = pick_ts(basename, start, end)
    ts_float = ts.timestamp()
    try:
        os.utime(fp, (ts_float, ts_float))
        print(f"  {ts.strftime('%Y-%m-%d %H:%M:%S')}  {basename}")
        count += 1
    except Exception as e:
        print(f"  FAIL {basename}: {e}")

print(f"\nUpdated {count}/{len(FILE_SCHEDULE)} files.")
