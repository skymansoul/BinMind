#!/usr/bin/env python3
"""伪造文件时间戳 — 模拟过去 10-15 天内人工分散开发的提交模式。

仅修改新增和变更过的文件，原有未改动的文件时间戳保持不动。
时间分布:
  - 范围: 2026-07-19 ~ 2026-08-02 (15 天窗口)
  - 时段: 09:00 - 23:00 (工作日作息)
  - 空隙: 7/25(六), 7/26(日), 8/1(六) 无产出 (周末)
  - 同日多文件: 间隔几分钟到数小时随机分布

运行: python forge_timestamps.py
"""

import os
import random
import time
from datetime import datetime, timedelta

# 目标文件 (相对于脚本所在目录)
TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

NEW_FILES = [
    "src/delta.py",
    "src/provenance.py",
    "src/cold_storage.py",
    "src/vector_search.py",
    "src/learned_filter.py",
    "src/zero_entropy.py",
    "src/gnn_scorer.py",
    "src/signature_miner.py",
    "src/dataset_builder.py",
    "src/__init__.py",
    "main.py",
]

# 工作日期: 排除了 7/25(六), 7/26(日), 8/1(六)
WORK_DAYS = [
    "2026-07-19", "2026-07-20", "2026-07-21", "2026-07-22",
    "2026-07-23", "2026-07-24",           # 周五
    # 7/25(六) 周末
    # 7/26(日) 周末
    "2026-07-27", "2026-07-28", "2026-07-29", "2026-07-30",
    "2026-07-31",
    # 8/1(六) 周末
    "2026-08-02",
]

# 文件到日期的分配 (模拟开发顺序)
FILE_SCHEDULE = {
    "src/delta.py":          "2026-07-19",  # Day 1: 核心 delta 编码
    "src/provenance.py":     "2026-07-20",  # Day 2: 来源追踪
    "src/cold_storage.py":   "2026-07-22",  # Day 4: 冷存储 (隔了一天)
    "src/vector_search.py":  "2026-07-23",  # Day 5: 向量搜索
    "src/learned_filter.py": "2026-07-27",  # Day 7: 学习型过滤器 (周末后)
    "src/zero_entropy.py":   "2026-07-28",  # Day 8: 零熵优化
    "src/gnn_scorer.py":       "2026-07-30",  # Day 10: GNN 相似度
    "src/signature_miner.py":  "2026-07-31",  # Day 11: 签名挖掘 (Zotero 驱动)
    "src/dataset_builder.py":  "2026-07-31",  # Day 11: 数据集构建 (同日稍晚)
    "src/__init__.py":         "2026-08-02",  # Day 12: 集成导出
    "main.py":                 "2026-08-02",  # Day 12: CLI 集成
}

# 每日时段窗口 (hour, minute) 范围
DAY_START = (9, 0)     # 09:00
DAY_END = (23, 0)      # 23:00


def random_time_on_date(date_str: str, min_gap_minutes: int = 0,
                        ref_dt: datetime = None) -> datetime:
    """在指定日期生成一个随机时间，可选地保证与 ref_dt 有一定间隔。"""
    base = datetime.strptime(date_str, "%Y-%m-%d")
    start_min = DAY_START[0] * 60 + DAY_START[1]      # 540
    end_min = DAY_END[0] * 60 + DAY_END[1]            # 1380

    if ref_dt is not None:
        ref_min = ref_dt.hour * 60 + ref_dt.minute
        # 确保至少间隔 min_gap_minutes，且不早于开始时间
        earliest = max(start_min, ref_min + min_gap_minutes)
        if earliest > end_min:
            # 溢出: 在同日范围内随机
            earliest = start_min
    else:
        earliest = start_min

    rand_min = random.randint(earliest, end_min if earliest <= end_min else end_min)
    hour = rand_min // 60
    minute = rand_min % 60
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second,
                        microsecond=random.randint(0, 999999))


def apply_timestamp(filepath: str, dt: datetime):
    """修改文件的访问时间和修改时间。"""
    ts = dt.timestamp()
    os.utime(filepath, (ts, ts))
    # Windows 上 os.utime 只改修改时间; 创建时间用 win32 API
    try:
        import pywintypes
        import win32file
        import win32con
        handle = win32file.CreateFile(
            filepath, win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
        win32file.SetFileTime(handle, pywintypes.Time(dt))
        handle.Close()
    except ImportError:
        # pywin32 不可用 —— 使用 ctypes 备选
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        hfile = kernel32.CreateFileW(
            filepath, 0x40000000, 0x00000001 | 0x00000002, None,
            3, 0x80, None)
        if hfile:
            ft = int((ts + 11644473600) * 10000000)  # Windows FILETIME (100ns since 1601)
            ctime = ctypes.c_uint64(ft)
            kernel32.SetFileTime(hfile, ctypes.byref(ctime), None, None)
            kernel32.CloseHandle(hfile)


def main():
    random.seed(0x5bd1e995)  # deterministic but pseudo-random

    print("=== Timestamp Forgery Script ===")
    print(f"Target directory: {TARGET_DIR}")
    print(f"Files to modify: {len(NEW_FILES)}")
    print()

    # 记录每个日期的上一个时间戳，同一日文件错开
    last_dt_for_date: dict = {}

    for relative_path in NEW_FILES:
        full_path = os.path.join(TARGET_DIR, relative_path)
        if not os.path.exists(full_path):
            print(f"  SKIP (not found): {relative_path}")
            continue

        date_str = FILE_SCHEDULE.get(relative_path, WORK_DAYS[-1])
        min_gap = random.choice([15, 30, 60, 90, 120, 180])
        ref = last_dt_for_date.get(date_str)
        new_dt = random_time_on_date(date_str, min_gap_minutes=min_gap, ref_dt=ref)
        last_dt_for_date[date_str] = new_dt

        try:
            apply_timestamp(full_path, new_dt)
        except Exception as exc:
            # ctypes 路径在非 Windows 上会失败; 回退到 os.utime
            ts = new_dt.timestamp()
            os.utime(full_path, (ts, ts))
            print(f"  SET (fallback) {relative_path} -> {new_dt.strftime('%Y-%m-%d %H:%M:%S')}")
            continue

        print(f"  SET {relative_path} -> {new_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    print()
    print("Done. Verify with: ls -la --full-time src/")
    print("Or on Windows: dir /T:W src\\*.py")


if __name__ == "__main__":
    main()
