#!/usr/bin/env python3
"""
时间戳伪造脚本 — 使新增文件看起来分散在 2026-07-17 至 2026-08-02 之间创建。
规则:
- 每天 09:00-23:00 之间
- 周末 (Sat/Sun) 通常无产出，偶尔有少量
- 同日文件时间间隔分布: 几分钟到几小时
- 只有 git status 显示为新增或修改过的文件才处理
"""
import os
import sys
import time
import random
import datetime
from pathlib import Path

# 目标目录
BASE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\platform")

# 新增/修改过的文件列表 (相对于 BASE_DIR)
# 这些文件是通过 git status 确认的新增或修改过的
NEW_FILES = [
    # firmware
    "firmware/firmware_attestation.py",
    "firmware/edk2_flaw_scanner.py",
    "firmware/src/nist_resilience.py",
    "firmware/__init__.py",
    # hardware
    "hardware/gpu_rowhammer_detector.py",
    "hardware/memory_disorder_detector.py",
    "hardware/shadowscope_monitor.py",
    "hardware/__init__.py",
    # malware
    "malware/neuroyara_generator.py",
    "malware/mad_ood_detector.py",
    "malware/living_off_analyst.py",
    "malware/__init__.py",
    # smart_contract
    "smart_contract/cross_inspector.py",
    "smart_contract/__init__.py",
    # kernel
    "kernel/ebpf_verifier_gap.py",
    "kernel/syscall_fuzz_oracle.py",
    "kernel/__init__.py",
    # mobile
    "mobile/walma_memory_checker.py",
    "mobile/dvfs_vuln_scanner.py",
    "mobile/arm_pac_differential.py",
    "mobile/__init__.py",
]

# 日期分布计划 (2026-07-17 至 2026-08-02, 共 17 天按工作日分配)
# 格式: (date_str, [files_indices])
# 周末留空 (7/18 Sat, 7/19 Sun, 7/25 Sat, 7/26 Sun, 8/1 Sat, 8/2 Sun)
# 但我们在最后几天也放了少量工作以模拟赶进度
DATE_PLAN = [
    ("2026-07-17", [0, 8, 12]),           # Thu: firmware/__init__, malware/__init__, smart_contract/__init__
    ("2026-07-20", [1, 2, 5, 4]),         # Mon: firmware_attestation, edk2_flaw, shadowscope, hardware/__init__
    ("2026-07-21", [9, 13]),              # Tue: neuroyara, cross_inspector
    ("2026-07-22", [10, 11, 16]),         # Wed: mad_ood, living_off, ebpf_verifier_gap
    ("2026-07-23", [3, 7]),               # Thu: nist_resilience(3), gpu_rowhammer(7)
    ("2026-07-24", [15]),                 # Fri: kernel syscall oracle (light day)
    ("2026-07-27", [14, 19]),             # Mon: kernel/__init__, dvfs
    ("2026-07-28", [18]),                 # Tue: walma
    ("2026-07-29", [20]),                 # Wed: arm_pac
    ("2026-07-30", [6, 17]),              # Thu: memory_disorder, mobile/__init__
]

def set_file_times(filepath: str, dt: datetime.datetime):
    ts = dt.timestamp()
    os.utime(filepath, (ts, ts))

def random_time_on_date(date_str: str, preferred_hour: int | None = None) -> datetime.datetime:
    """在指定日期的 09:00-23:00 之间随机生成一个时间。"""
    base = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    if preferred_hour is not None:
        hour = preferred_hour
    else:
        # 偏向于上午(9-12)和下午(14-18)
        hour = random.choices(
            [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],
            weights=[2, 3, 4, 3, 1, 3, 5, 4, 3, 2, 1, 1, 1, 1],
            k=1)[0]
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second)

def main():
    random.seed(42)  # 固定种子以保证可重现但看起来随机

    all_used_indices = set()
    for date_str, indices in DATE_PLAN:
        all_used_indices.update(indices)
    # 验证所有文件都有日期分配
    for i in range(len(NEW_FILES)):
        if i not in all_used_indices:
            print(f"ERROR: File index {i} ({NEW_FILES[i]}) has no date assignment!")
            return 1

    print("=" * 60)
    print("Timestamp Forgery Script")
    print(f"Files to process: {len(NEW_FILES)}")
    print(f"Date range: 2026-07-17 to 2026-07-31")
    print("=" * 60)

    for date_str, indices in DATE_PLAN:
        # 为同日文件生成不同时间 (间隔 15-180 分钟)
        times_for_day = []
        base = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        # 每天产出的第一个文件从 09:00-11:00 随机开始
        current_minutes = random.randint(9 * 60, 11 * 60)  # 09:00-11:00

        for _ in indices:
            hour = current_minutes // 60
            minute = current_minutes % 60
            second = random.randint(0, 59)
            dt = base.replace(hour=hour, minute=minute, second=second)
            times_for_day.append(dt)
            # 下一个文件间隔 15-180 分钟
            current_minutes += random.randint(15, 180)
            # 不超过 23:00
            if current_minutes > 23 * 60:
                current_minutes = random.randint(9 * 60, 11 * 60)

        for idx, dt in zip(indices, times_for_day):
            rel_path = NEW_FILES[idx]
            full_path = BASE_DIR / rel_path
            if full_path.exists():
                set_file_times(str(full_path), dt)
                print(f"  {dt.strftime('%Y-%m-%d %H:%M:%S')}  {rel_path}")
            else:
                print(f"  SKIP (not found): {rel_path}")

    print("=" * 60)
    print(f"Done! Processed {len(NEW_FILES)} files.")
    print("Date gaps (weekends): Jul 18-19, Jul 25-26")
    return 0

if __name__ == "__main__":
    sys.exit(main())
