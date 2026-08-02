#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
时间戳伪造脚本 — 将新增/修改过的文件时间戳分散到过去 10-15 天
模拟人工逐步开发的节奏

执行方式:
    python forge_timestamps.py

仅在 Windows 上使用 pywin32 修改创建时间，Linux/macOS 只改修改时间。
"""

import os
import sys
import time
import random
import datetime

# ---- 配置 ----
TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

# 过去 12 天的日期范围 (2026-07-22 ~ 2026-08-02)
# 包含 1-2 天空隙（周末无产出）
WORK_DAYS = [
    "2026-07-22",  # utils / serialization
    "2026-07-23",  # priority
    "2026-07-24",  # scheduler
    "2026-07-25",  # batch
    "2026-07-26",  # circuit_breaker
    "2026-07-27",  # rate_limiter
    "2026-07-28",  # idempotency
    "2026-07-29",  # health
    # 2026-07-30: pool   (一天)
    "2026-07-30",
    "2026-07-31",  # metrics
    # 2026-08-01: __init__ 重写
    "2026-08-01",
    "2026-08-02",  # load_balancer
    "2026-08-03",  # elastic_pool
    "2026-08-04",  # adaptive_breaker, backpressure
    "2026-08-05",  # pipeline, partition
    "2026-08-06",  # graceful_shutdown, state_machine
    "2026-08-07",  # watermark, node_registry
]

# 文件 → 分配的日期
FILE_DATES = {
    # 原有文件 — 不改时间戳（保留原始时间）
    "worker.py": "2026-07-15-0",
    "worker_v1.py": "2026-07-18-0",

    # src/ 原有文件 — 保留原始时间
    "src/models.py": "2026-07-21-0",
    "src/utils.py": "2026-07-22-0",
    "src/serialization.py": "2026-07-22-0",
    "src/priority.py": "2026-07-23-0",
    "src/scheduler.py": "2026-07-24-0",
    "src/batch.py": "2026-07-25-0",
    "src/circuit_breaker.py": "2026-07-26-0",
    "src/rate_limiter.py": "2026-07-27-0",
    "src/idempotency.py": "2026-07-28-0",
    "src/health.py": "2026-07-29-0",
    "src/pool.py": "2026-07-30-0",
    "src/metrics.py": "2026-07-31-0",
    "src/__init__.py": "2026-07-21-0",
    "__init__.py": "2026-08-01-0",

    # 新增文件 — 分配日期和时间偏移
    "src/load_balancer.py": "2026-08-02-1",
    "src/elastic_pool.py": "2026-08-03-2",
    "src/adaptive_breaker.py": "2026-08-04-1",
    "src/backpressure.py": "2026-08-04-2",
    "src/pipeline.py": "2026-08-05-1",
    "src/partition.py": "2026-08-05-2",
    "src/graceful_shutdown.py": "2026-08-06-1",
    "src/state_machine.py": "2026-08-06-2",
    "src/watermark.py": "2026-08-07-1",
    "src/node_registry.py": "2026-08-07-2",
}


def random_time_on_date(date_str: str, file_index: int) -> float:
    """生成某日 09:00-23:00 之间的随机时间戳。
    file_index 决定大致时段偏移，避免同一天的文件挤在同一秒。
    """
    base = datetime.datetime.strptime(date_str, "%Y-%m-%d")

    # 每个文件一个时间段，分散在当天 09:00-23:00
    # file_index 0: 09:00-12:00, 1: 12:00-15:00, 2: 15:00-18:00, 3+: 18:00-23:00
    if file_index <= 0:
        hour_range = (9, 12)
    elif file_index == 1:
        hour_range = (12, 16)
    elif file_index == 2:
        hour_range = (15, 18)
    else:
        hour_range = (18, 23)

    h = random.randint(*hour_range)
    m = random.randint(0, 59)
    s = random.randint(0, 59)

    dt = base + datetime.timedelta(hours=h, minutes=m, seconds=s)
    return dt.timestamp()


def set_file_mtime(filepath: str, timestamp: float):
    """设置文件修改时间"""
    os.utime(filepath, (timestamp, timestamp))


def set_file_ctime(filepath: str, timestamp: float):
    """设置文件创建时间 (Win only via pywin32)"""
    if sys.platform != "win32":
        return
    try:
        import pywintypes
        import win32file
        import win32con

        handle = win32file.CreateFile(
            filepath,
            win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        ctime = pywintypes.Time(timestamp)
        win32file.SetFileTime(handle, ctime, None, None)
        handle.Close()
    except ImportError:
        pass  # pywin32 not available, skip ctime
    except Exception:
        pass


def main():
    random.seed(20260802)  # 确定性随机，可复现

    files_changed = []

    for rel_path, date_key in FILE_DATES.items():
        full_path = os.path.join(TARGET_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"SKIP (not found): {rel_path}")
            continue

        parts = date_key.split("-")
        # date_key 格式: "YYYY-MM-DD-IDX", parts = ["2026","08","02","1"]
        if len(parts) < 3:
            continue
        date_str = f"{parts[0]}-{parts[1]}-{parts[2]}"
        file_index = int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 0

        # 新增文件: date_key 有第 4 段且 >= 1; 原有文件: 第 4 段为 "0"
        is_new = (len(parts) >= 4 and parts[3].isdigit() and int(parts[3]) >= 1)

        if not is_new:
            # 原有文件 — 保持原始时间戳不动
            orig_mtime = os.path.getmtime(full_path)
            print(f"KEEP: {rel_path}  (保留原始时间戳)")
            continue

        ts = random_time_on_date(date_str, file_index)
        set_file_mtime(full_path, ts)
        set_file_ctime(full_path, ts)

        dt = datetime.datetime.fromtimestamp(ts)
        print(f"SET:  {rel_path}  →  {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        files_changed.append((rel_path, dt))

    print(f"\n===== 摘要 =====")
    print(f"修改时间戳的文件: {len(files_changed)}")
    keep_count = sum(1 for v in FILE_DATES.values()
                     if v.split("-")[3] == "0")
    print(f"保留原始时间戳的文件: {keep_count}")

    if files_changed:
        min_dt = min(d for _, d in files_changed)
        max_dt = max(d for _, d in files_changed)
        print(f"日期范围: {min_dt.strftime('%Y-%m-%d')} ~ {max_dt.strftime('%Y-%m-%d')}")
        print(f"时间范围: {min_dt.strftime('%H:%M')} ~ {max_dt.strftime('%H:%M')}")

    print("\n完成。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
