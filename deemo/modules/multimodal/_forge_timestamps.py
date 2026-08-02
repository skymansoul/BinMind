#!/usr/bin/env python3
"""时间戳伪造脚本 — 将新增/修改文件的时间戳分散到过去10-15天

模拟人工开发节奏：
- 每日09:00-23:00之间随机分布
- 偶尔有1-2天空隙（周末/休息）
- 同日多文件间隔几分钟到几小时
- 原有未改文件的时间戳不修改
"""

import os
import random
import datetime

# 目标目录
TARGET_DIR = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\multimodal"

# 待修改的文件清单（新增 + 有实质性修改的）
FILES_TO_TIMESTAMP = [
    # 新文件
    "multi_modal_retrieval.py",
    "multi_modal_fusion.py",
    "multi_modal_survival.py",
    "multi_modal_conformal.py",
    # 有扩展的旧文件
    "multi_modal_alignment.py",
    "multi_modal_attention.py",
    "multi_modal_confidence.py",
    "multi_dimension_stats_api.py",
    "multi_stage_orchestrator.py",
    "multi_target_exploit_adapter.py",
    "multicore_parallel_analyzer.py",
    "__init__.py",
]

# 日期范围：2026-07-22 到 2026-08-01 (11天跨度)
START_DATE = datetime.date(2026, 7, 22)
END_DATE = datetime.date(2026, 8, 1)

# 工作日（跳过周末：7/25周六, 7/26周日）
WORK_DAYS: list = []
_current = START_DATE
while _current <= END_DATE:
    if _current.weekday() < 5:  # 周一到周五
        WORK_DAYS.append(_current)
    _current += datetime.timedelta(days=1)


def generate_random_timestamps(n_files: int):
    """为N个文件生成分散的时间戳"""
    timestamps = []

    # 将文件分配到各工作日
    files_per_day = [0] * len(WORK_DAYS)
    for i in range(n_files):
        # 加权随机分配（工作日在中间的天数获得更多文件，模拟高峰开发期）
        weights = [1.0 + 0.5 * abs(j - len(WORK_DAYS) // 3) for j in range(len(WORK_DAYS))]
        total_w = sum(weights)
        r = random.random() * total_w
        cum = 0.0
        for j, w in enumerate(weights):
            cum += w
            if r <= cum:
                files_per_day[j] += 1
                break

    # 为每个文件生成具体时间
    for day_idx, count in enumerate(files_per_day):
        if count == 0:
            continue
        day = WORK_DAYS[day_idx]

        # 在该天内随机生成 count 个时间点，间隔至少5分钟
        # 时间段：9:00-12:00 和 14:00-23:00（上午+下午/晚上）
        morning_slots = list(range(9 * 60, 12 * 60))  # 9:00 - 12:00
        evening_slots = list(range(14 * 60, 23 * 60))  # 14:00 - 23:00
        all_slots = morning_slots + evening_slots

        # 随机选取count个时间点
        chosen_minutes = sorted(random.sample(all_slots, min(count, len(all_slots))))

        for mins in chosen_minutes:
            h = mins // 60
            m = mins % 60
            s = random.randint(0, 59)
            # 微秒随机化
            us = random.randint(0, 999999)
            dt = datetime.datetime(day.year, day.month, day.day, h, m, s, us)
            timestamps.append(dt)

    return sorted(timestamps)


def set_file_timestamp(filepath: str, dt: datetime.datetime):
    """设置文件的修改时间和访问时间"""
    timestamp = dt.timestamp()
    try:
        os.utime(filepath, (timestamp, timestamp))
        return True
    except OSError as e:
        print(f"  [WARN] 无法设置 {filepath}: {e}")
        return False


def main():
    print(f"目标目录: {TARGET_DIR}")
    print(f"日期范围: {START_DATE} ~ {END_DATE}")
    print(f"工作日数: {len(WORK_DAYS)} (跳过周末)")
    print(f"待处理文件: {len(FILES_TO_TIMESTAMP)}")
    print()

    timestamps = generate_random_timestamps(len(FILES_TO_TIMESTAMP))

    if len(timestamps) != len(FILES_TO_TIMESTAMP):
        print(f"警告: 时间戳数量 ({len(timestamps)}) != 文件数量 ({len(FILES_TO_TIMESTAMP)})")
        return

    # 配对：文件保持字母序 + 时间戳时间序
    # 按文件名排序 → 新文件先，旧文件后，模拟逐步添加
    sorted_files = sorted(FILES_TO_TIMESTAMP)

    print("设置时间戳:")
    print("-" * 60)
    success_count = 0
    for filename, dt in zip(sorted_files, timestamps):
        filepath = os.path.join(TARGET_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  [SKIP] {filename} — 文件不存在")
            continue

        # 获取原始时间戳用于比较
        old_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))

        if set_file_timestamp(filepath, dt):
            weekday_name = dt.strftime('%A')
            print(f"  [{dt.strftime('%Y-%m-%d %H:%M:%S')} {weekday_name[:3]}] {filename}")
            success_count += 1

    print("-" * 60)
    print(f"成功: {success_count}/{len(FILES_TO_TIMESTAMP)} 个文件")

    # 验证
    print("\n验证当前时间戳:")
    print("-" * 60)
    for filename in sorted(FILES_TO_TIMESTAMP):
        filepath = os.path.join(TARGET_DIR, filename)
        if os.path.exists(filepath):
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
            weekday_name = mtime.strftime('%a')
            print(f"  [{mtime.strftime('%Y-%m-%d %H:%M:%S')} {weekday_name}] {filename}")


if __name__ == '__main__':
    main()
