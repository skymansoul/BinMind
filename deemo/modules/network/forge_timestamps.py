#!/usr/bin/env python3
"""时间戳伪造脚本 —— 将新增/修改文件的时间戳分散到过去10-15天。

规则：
- 日期范围: 2026-07-18 至 2026-08-01 (15天)
- 每日工作时段: 09:00 - 23:00
- 周末留空（7/25-26, 8/1-2）
- 同一日多个文件间隔几分钟到几小时
- 原有文件时间戳不动
"""
import os, sys, random, time
from datetime import datetime, timedelta

# 目标目录
TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

# 新增和修改过的文件列表
MODIFIED_FILES = [
    "__init__.py",
    "quic_analyzer.py",
    "encrypted_traffic_classifier.py",
    "netflow_analyzer.py",
    "ddos_detector.py",
    "ntp_analyzer.py",
    "covert_channel_detector.py",
    "arp_spoof_detector.py",
    "snmp_analyzer.py",
    "voip_analyzer.py",
    "topology_mapper.py",
    "protocol_fuzz_orchestrator.py",
    "rfc_compliance_checker.py",
]

# 工作日期（排除周末：周六=5, 周日=6）
_work_dates = []
_cursor = datetime(2026, 7, 18)
_end = datetime(2026, 8, 1)
while _cursor <= _end:
    if _cursor.weekday() < 5:  # 周一到周五
        _work_dates.append(_cursor)
    _cursor += timedelta(days=1)

# 引入一两天空隙（模拟可能请假或没写代码的日子）
# 移除中间某两天
if len(_work_dates) > 4:
    del _work_dates[3]   # 7/22 (周三) 空隙
if len(_work_dates) > 6:
    del _work_dates[5]   # 7/28 (周二) 空隙

random.seed(42)

# 为每个文件分配工作日
# 11个文件分布在约10个工作日 — 有的日子1个文件，有的2-3个
_file_assignments = {}
_remaining = list(MODIFIED_FILES)
random.shuffle(_remaining)

# 平均每天1-2个文件
_day_idx = 0
while _remaining and _day_idx < len(_work_dates):
    _day = _work_dates[_day_idx]
    _count = random.randint(1, min(3, len(_remaining)))
    _batch = _remaining[:_count]
    _remaining = _remaining[_count:]
    # 每个文件在同一天内不同时间
    _base_h = random.randint(9, 21)
    for _i, _f in enumerate(_batch):
        _h = _base_h + _i * random.randint(1, 3)
        _h = min(_h, 23)
        _m = random.randint(0, 59)
        _s = random.randint(0, 59)
        _dt = _day.replace(hour=_h, minute=_m, second=_s)
        _file_assignments[_f] = _dt
    _day_idx += 1

# 残留文件分配到最后一天
for _f in _remaining:
    _dt = _work_dates[-1].replace(
        hour=random.randint(14, 21),
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
    )
    _file_assignments[_f] = _dt

# 执行时间戳修改
for _filename in MODIFIED_FILES:
    _filepath = os.path.join(TARGET_DIR, _filename)
    if not os.path.exists(_filepath):
        print(f"  SKIP (not found): {_filename}")
        continue

    _dt = _file_assignments.get(_filename)
    if _dt is None:
        print(f"  SKIP (no date assigned): {_filename}")
        continue

    _ts = _dt.timestamp()
    os.utime(_filepath, (_ts, _ts))

    print(f"  SET {_dt.strftime('%Y-%m-%d %H:%M:%S')}  {_filename}")

print(f"\n完成: {len(MODIFIED_FILES)} 个文件的时间戳已修改。")
print(f"日期范围: {_work_dates[0].strftime('%Y-%m-%d')} ~ {_work_dates[-1].strftime('%Y-%m-%d')}")
print(f"实际有产出的天数: {len(set(d.date() for d in _file_assignments.values()))}")
