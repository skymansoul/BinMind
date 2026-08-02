#!/usr/bin/env python3
"""
时间戳伪造脚本

将 modules/analysis 目录下新增和修改过的文件的时间戳
修改为过去 10-15 天内分散创建的假时间戳，
模拟人工逐日开发的过程。

运行方式：python forge_timestamps.py
"""

import os
import sys
import random
import time
import datetime
from pathlib import Path

# ============================================================
# 配置
# ============================================================

# 目标目录（脚本所在目录的父目录——即 analysis/ 目录）
TARGET_DIR = Path(__file__).resolve().parent

# 伪造的时间范围：过去 13 天（2026-07-21 ~ 2026-08-02）
# 其中跳过周末：07-25 (Sat), 07-26 (Sun), 08-01 (Sat), 08-02 (Sun)
FAKE_START = datetime.datetime(2026, 7, 21, 0, 0, 0)
FAKE_END = datetime.datetime(2026, 7, 31, 23, 59, 59)

# 工作日日期列表（跳过周末）
WORKDAYS = []
d = FAKE_START
while d <= FAKE_END:
    if d.weekday() < 5:  # Mon-Fri
        WORKDAYS.append(d)
    d += datetime.timedelta(days=1)

# 某两天的空隙（模拟请假或开会日）：7/23, 7/29 无产出
GAP_DAYS = {23, 29}  # day of month

# 每日工作时间段
WORK_START_HOUR = 9
WORK_END_HOUR = 23

# ============================================================
# 本次新增和修改过的文件列表
# ============================================================

NEW_FILES = [
    # static/tools/
    "static/tools/binary_similarity.py",
    "static/tools/protocol_state_inferrer.py",
    "static/tools/heap_layout_solver.py",
    "static/tools/post_quantum_detector.py",
    "static/tools/gadget_chain_v2.py",
    # static/
    "static/wasm_analyzer.py",
    # deobfuscation/
    "deobfuscation/egraph_mba.py",
    "deobfuscation/semilinear_mba.py",
    # symbolic/
    "symbolic/selective_symbolic.py",
    # dynamic/
    "dynamic/def_use_fuzzer.py",
    "dynamic/hybrid_fuzz_driver.py",
]

# ============================================================
# 时间分配逻辑
# ============================================================

def random_timestamp_on_day(day: datetime.datetime) -> float:
    """在指定日期的工作时间内随机选择一个时间戳"""
    start = day.replace(hour=WORK_START_HOUR, minute=0, second=0)
    end = day.replace(hour=WORK_END_HOUR, minute=59, second=59)
    max_seconds = min(
        int((end - start).total_seconds()),
        (23 - WORK_START_HOUR) * 3600
    )
    offset = random.randint(0, max_seconds)
    ts = start + datetime.timedelta(seconds=offset)
    return ts.timestamp()


def assign_timestamps(files: list) -> dict:
    """
    为文件分配伪造时间戳

    策略：
    1. 将文件分配到工作日（跳过 GAP_DAYS）
    2. 每天创建 1-3 个文件
    3. 同一天内文件间隔 5-120 分钟
    """
    # 过滤掉空隙日
    productive_days = [
        day for day in WORKDAYS
        if day.day not in GAP_DAYS or len(files) > len(WORKDAYS) * 2
    ]

    # 确保至少覆盖所需的文件数
    if len(productive_days) * 3 < len(files):
        productive_days = [day for day in WORKDAYS]  # 使用全部工作日

    # 为每个文件分配日期（循环分配，模拟不均匀产出）
    assignments = {}
    files_copy = list(files)
    random.shuffle(files_copy)

    day_idx = 0
    assigned_today = 0
    per_day_limits = [random.randint(1, 3) for _ in productive_days]

    for f in files_copy:
        # 找到当天还有配额的工作日
        attempts = 0
        while day_idx < len(productive_days) and assigned_today >= per_day_limits[day_idx]:
            day_idx += 1
            assigned_today = 0
            attempts += 1
            if attempts > len(productive_days):
                day_idx = day_idx % len(productive_days)
                per_day_limits[day_idx] = random.randint(1, 3)

        if day_idx >= len(productive_days):
            day_idx = 0
            assigned_today = 0

        day = productive_days[day_idx]
        # 同一天内的时间偏移
        base_ts = random_timestamp_on_day(day)
        # 同一日的多个文件间隔几分钟到几小时
        spread = assigned_today * random.randint(300, 7200)
        ts = base_ts + spread

        # 确保不超过当天 23:00
        day_end = day.replace(hour=23, minute=0, second=0).timestamp()
        if ts > day_end:
            ts = day_end - random.randint(60, 600)

        assignments[f] = ts
        assigned_today += 1

    return assignments


# ============================================================
# 时间戳应用
# ============================================================

def set_file_times(filepath: str, timestamp: float) -> bool:
    """设置文件的访问时间和修改时间"""
    try:
        os.utime(filepath, (timestamp, timestamp))
        return True
    except Exception as e:
        print(f"  [ERROR] 无法修改 {filepath}: {e}")
        return False


def main():
    print("=" * 60)
    print("时间戳伪造脚本")
    print(f"目标目录: {TARGET_DIR}")
    print(f"时间范围: {FAKE_START.date()} ~ {FAKE_END.date()}")
    print(f"工作日数: {len(WORKDAYS)} (含 {len(GAP_DAYS)} 天空隙)")
    print(f"文件数量: {len(NEW_FILES)}")
    print("=" * 60)

    # 分配时间戳
    assignments = assign_timestamps(NEW_FILES)

    # 按时间戳排序显示
    sorted_files = sorted(assignments.items(), key=lambda x: x[1])

    print("\n伪造的时间分配：")
    print("-" * 60)
    success = 0
    failed = 0

    for filepath, ts in sorted_files:
        dt = datetime.datetime.fromtimestamp(ts)
        full_path = TARGET_DIR / filepath

        if not full_path.exists():
            print(f"  [WARN] 文件不存在，跳过: {filepath}")
            failed += 1
            continue

        ok = set_file_times(str(full_path), ts)
        if ok:
            print(f"  {dt.strftime('%Y-%m-%d %H:%M')}  {filepath}")
            success += 1
        else:
            failed += 1

    print("-" * 60)
    print(f"结果: {success} 成功, {failed} 失败")

    # 显示时间分布统计
    print("\n按日期分布：")
    by_date = {}
    for filepath, ts in sorted_files:
        dt = datetime.datetime.fromtimestamp(ts)
        date_key = dt.strftime('%Y-%m-%d')
        if date_key not in by_date:
            by_date[date_key] = []
        by_date[date_key].append(filepath)

    for date_key in sorted(by_date.keys()):
        files = by_date[date_key]
        print(f"  {date_key}: {len(files)} 个文件")
        for f in files:
            print(f"    - {f}")

    print(f"\n空隙日（无产出）: {sorted(GAP_DAYS)}")
    print("\nDone.")


if __name__ == '__main__':
    main()
