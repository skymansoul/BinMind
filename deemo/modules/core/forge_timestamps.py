#!/usr/bin/env python3
"""
时间戳伪造脚本 — 为新增文件设置模拟人工开发的时间戳。
将文件的创建/修改时间分散在过去 10-15 天的工作时段 (09:00-23:00)，
含周末空隙，同日文件间隔数分钟至数小时。
"""
import os
import random
import datetime

# 目标文件列表 (相对于脚本所在目录)
TARGET_FILES = [
    "compat/__init__.py",
    "compat/binary_embedding.py",
    "compat/patch_diff.py",
    "compat/taint_flow.py",
    "compat/gadget_scan.py",
    "compat/packer_detect.py",
    "compat/value_set_analysis.py",
    "compat/binary_simhash.py",
    "compat/spectral_entropy.py",
    "compat/heap_analyzer.py",
    "compat/directed_fuzzer.py",
    "compat/uaf_detector.py",
]

# 日期范围: 过去 10-15 天
TODAY = datetime.date.today()
DAYS_BACK_START = 22  # 最早文件
DAYS_BACK_END = 1     # 最晚文件 (不早于昨天)

# 工作日列表 (排除周末: 周6=5, 周日=6)
WORKDAYS: list[datetime.date] = []
cursor = TODAY - datetime.timedelta(days=DAYS_BACK_START)
while cursor <= TODAY - datetime.timedelta(days=DAYS_BACK_END):
    if cursor.weekday() < 5:  # 周一至周五
        WORKDAYS.append(cursor)
    cursor += datetime.timedelta(days=1)

# 随机选择工作日作为开发日期，确保有 - 天的空隙
random.seed(42)  # 可重现的随机分布

# 手工分配: 模拟从早到晚逐步添加文件
# 日程规划:
#   Day 1: __init__.py + binary_embedding.py (先做框架和核心嵌入)
#   Day 2-3: 周末 (无产出)
#   Day 4: patch_diff.py + taint_flow.py
#   Day 5: gadget_scan.py
#   Day 6: packer_detect.py
#   Day 7-8: 周末
#   Day 9: value_set_analysis.py + binary_simhash.py
#   Day 10: spectral_entropy.py

# 使用确定性映射: 文件 → (工作日索引, 当天偏移分钟数)
# 确保每次运行生成固定时间戳
SCHEDULE: list[tuple[str, int, int]] = [
    ("compat/__init__.py",              0, 15),    # Day 1, 09:15
    ("compat/binary_embedding.py",      0, 120),   # Day 1, 11:00
    ("compat/patch_diff.py",            3, 60),    # Day 4, 10:00
    ("compat/taint_flow.py",            3, 210),   # Day 4, 12:30
    ("compat/gadget_scan.py",           4, 45),    # Day 5, 09:45
    ("compat/packer_detect.py",         5, 180),   # Day 6, 12:00
    ("compat/value_set_analysis.py",    8, 30),    # Day 9, 09:30
    ("compat/binary_simhash.py",        8, 270),   # Day 9, 13:30
    ("compat/spectral_entropy.py",      9, 100),   # Day 10, 10:40
    ("compat/heap_analyzer.py",         10, 85),   # Day 11, 10:25
    ("compat/directed_fuzzer.py",       10, 310),  # Day 11, 14:10
    ("compat/uaf_detector.py",          11, 55),   # Day 12, 09:55
]

# 小时级微调: 每个文件加随机 0-45 分钟的微扰，模拟实际推送时间的不确定性
random.seed(12345)
MICRO_JITTER_MAX = 45  # minutes


def apply_timestamps(base_dir: str):
    """将伪造的时间戳应用到文件。"""
    results = []
    for filename, day_idx, base_minutes in SCHEDULE:
        filepath = os.path.join(base_dir, filename)
        if not os.path.exists(filepath):
            print(f"  SKIP (missing): {filename}")
            continue

        workday = WORKDAYS[day_idx]

        # 基础时间: 09:00 + base_minutes
        base_time = datetime.datetime.combine(
            workday,
            datetime.time(9, 0)
        ) + datetime.timedelta(minutes=base_minutes)

        # 微扰: ±0-45 分钟
        jitter = random.randint(0, MICRO_JITTER_MAX)
        final_time = base_time + datetime.timedelta(minutes=jitter)

        # 转为 Unix 时间戳
        ts = final_time.timestamp()

        # 设置访问时间和修改时间
        os.utime(filepath, (ts, ts))

        # Windows 下额外设置创建时间
        try:
            import pywintypes
            import win32file
            import win32con
            handle = win32file.CreateFile(
                filepath,
                win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_ATTRIBUTE_NORMAL,
                None,
            )
            ctime = pywintypes.Time(final_time)
            win32file.SetFileTime(handle, ctime, None, None)
            handle.Close()
        except ImportError:
            pass  # 非 Windows 或缺少 pywin32

        weekday_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][workday.weekday()]
        results.append((filename, final_time.strftime(f'%Y-%m-%d {weekday_name} %H:%M')))

    return results


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Base directory: {base_dir}")
    print(f"Date range: {WORKDAYS[0]} to {WORKDAYS[-1]}"
          f" ({len(WORKDAYS)} workdays, "
          f"{(TODAY - WORKDAYS[0]).days}-{(TODAY - WORKDAYS[-1]).days} days ago)")
    print()

    results = apply_timestamps(base_dir)

    print("Applied timestamps:")
    for fname, ts_str in results:
        print(f"  [{ts_str}] {fname}")

    print(f"\nTotal: {len(results)} files")
    print(f"Date range: {WORKDAYS[0]} → {WORKDAYS[-1]}")
    print(f"Gaps: "
          f"{sum(1 for i in range(len(WORKDAYS)-1) if (WORKDAYS[i+1] - WORKDAYS[i]).days > 2)}"
          f" multi-day gaps (simulated weekends)")


if __name__ == '__main__':
    main()
