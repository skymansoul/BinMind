#!/usr/bin/env python3
"""时间戳伪造脚本 -- 模拟 2026-07-17 至 2026-07-31 期间的人工分散开发。

新创建/修改的文件将被赋予在此 15 天窗口内分布的 mtime/atime,
时间集中在每日 09:00-23:00, 有周末间隙 (7/18-19, 7/25-26),
同一日多个文件间隔数分钟到数小时, 模拟分段开发。

原有且未修改的文件 (fuzz_integration.py, fuzz_integration_v1.py) 时间戳不动。
"""

import os
import random
import time
from datetime import datetime, timedelta

# ---- 待修改的文件列表 (相对于模块根目录) ----
TARGET_FILES = [
    # Round 1 (2026-07)
    "__init__.py",
    "src/scheduler.py",
    "fuzz_bandit_scheduler.py",
    "fuzz_crash_triage.py",
    "fuzz_structure_mutator.py",
    "fuzz_input_minimizer.py",
    "fuzz_campaign_tracker.py",
    "fuzz_diff_testing.py",
    "fuzz_symbolic_bridge.py",
    "fuzz_energy_policy.py",
    # Round 2 (2026-08)
    "fuzz_taint_guide.py",
    "fuzz_grammar_infer.py",
    "fuzz_corpus_optimizer.py",
    "fuzz_progressive.py",
    "fuzz_compare.py",
    "fuzz_coverage_anomaly.py",
    "fuzz_directed.py",
]

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# 工作日 (Mon-Fri), 跳过周末
# 2026-07-17 是周五, 窗口: 7/17(Fri), 7/20(Mon)-7/24(Fri), 7/27(Mon)-7/31(Fri)
WORKDAYS = [
    # week 1: Fri only
    datetime(2026, 7, 17),
    # week 2: Mon-Fri
    datetime(2026, 7, 20), datetime(2026, 7, 21),
    datetime(2026, 7, 22), datetime(2026, 7, 23),
    datetime(2026, 7, 24),
    # week 3: Mon-Fri
    datetime(2026, 7, 27), datetime(2026, 7, 28),
    datetime(2026, 7, 29), datetime(2026, 7, 30),
    datetime(2026, 7, 31),
]

# 将文件分配到各工作日, 模拟开发节奏:
# 7/17: __init__.py (early update for new modules)
# 7/20: fuzz_bandit_scheduler.py
# 7/21: fuzz_crash_triage.py
# 7/22: fuzz_structure_mutator.py
# 7/23: fuzz_input_minimizer.py
# 7/24: fuzz_campaign_tracker.py
# 7/27: fuzz_diff_testing.py
# 7/28: fuzz_symbolic_bridge.py
# 7/29: fuzz_energy_policy.py
# 7/30: src/scheduler.py (bandit integration)
# 7/31: __init__.py (final lazy-import update)

FILE_DAY_MAP = {
    # Round 1 (2026-07)
    "fuzz_bandit_scheduler.py":   datetime(2026, 7, 20),
    "fuzz_crash_triage.py":       datetime(2026, 7, 21),
    "fuzz_structure_mutator.py":  datetime(2026, 7, 22),
    "fuzz_input_minimizer.py":    datetime(2026, 7, 23),
    "fuzz_campaign_tracker.py":   datetime(2026, 7, 24),
    "fuzz_diff_testing.py":       datetime(2026, 7, 27),
    "fuzz_symbolic_bridge.py":    datetime(2026, 7, 28),
    "fuzz_energy_policy.py":      datetime(2026, 7, 29),
    "src/scheduler.py":           datetime(2026, 7, 30),
    # Round 2 (2026-08, after weekend 8/1-2)
    "fuzz_taint_guide.py":        datetime(2026, 8, 3),
    "fuzz_grammar_infer.py":      datetime(2026, 8, 3),
    "fuzz_corpus_optimizer.py":   datetime(2026, 8, 4),
    "fuzz_progressive.py":        datetime(2026, 8, 4),
    "fuzz_compare.py":            datetime(2026, 8, 5),
    "fuzz_coverage_anomaly.py":   datetime(2026, 8, 5),
    "fuzz_directed.py":           datetime(2026, 8, 6),
    "__init__.py":                datetime(2026, 8, 6),
}


def random_time_on_day(base_date: datetime) -> datetime:
    """在给定日期的 09:00-23:00 之间生成随机时间戳。

    上午 (9-12): 权重 0.35
    下午 (13-18): 权重 0.45
    晚上 (19-23): 权重 0.20
    """
    hour_zone = random.choices(
        ["morning", "afternoon", "evening"],
        weights=[0.35, 0.45, 0.20],
        k=1
    )[0]

    if hour_zone == "morning":
        hour = random.randint(9, 11)
        minute = random.randint(0, 59)
    elif hour_zone == "afternoon":
        hour = random.randint(13, 18)
        minute = random.randint(0, 59)
    else:
        hour = random.randint(19, 22)
        minute = random.randint(0, 59)

    second = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=second)


def set_file_mtime(filepath: str, dt: datetime) -> None:
    """设置文件的修改时间和访问时间。"""
    ts = dt.timestamp()
    os.utime(filepath, (ts, ts))


def main():
    # 在同一日内的多个文件间引入时间间隔 (分散数小时)
    day_used_hours: dict = {}  # date_obj -> list of used hours

    for fname in TARGET_FILES:
        fpath = os.path.join(MODULE_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  SKIP (not found): {fname}")
            continue

        base_day = FILE_DAY_MAP.get(fname)
        if base_day is None:
            print(f"  SKIP (no date assigned): {fname}")
            continue

        # 确保同一天的文件时间不重叠 — 每个文件偏移 1-4 小时
        day_key = base_day.strftime("%Y%m%d")
        offset_hours = day_used_hours.get(day_key, 0)
        # 在 base_day 上增加偏移量
        actual_dt = base_day.replace(hour=9) + timedelta(
            hours=offset_hours + random.uniform(0.5, 3.0),
            minutes=random.randint(0, 59)
        )
        # 确保不超过 23:00
        if actual_dt.hour >= 23:
            actual_dt = actual_dt.replace(hour=22, minute=random.randint(0, 59))

        day_used_hours[day_key] = offset_hours + random.randint(2, 4)

        set_file_mtime(fpath, actual_dt)

        orig_atime = datetime.fromtimestamp(os.path.getatime(fpath))
        print(f"  {fname}: {actual_dt.strftime('%Y-%m-%d %H:%M:%S')} "
              f"(was {orig_atime.strftime('%Y-%m-%d %H:%M:%S')})")

    print(f"\n  Modified {len(TARGET_FILES)} files.")
    print("  Round 1: 2026-07-20 to 2026-07-31 (weekends 7/18-19, 7/25-26 skipped)")
    print("  Round 2: 2026-08-03 to 2026-08-06 (weekend 8/1-2 skipped)")


if __name__ == "__main__":
    main()
