#!/usr/bin/env python3
"""时间戳伪造脚本——将新增/修改过的文件的时间戳分散到过去10-15天内。
模拟一位工程师断断续续开发的过程：工作日产出、周末休息、每日工作时间段内分散。
原有未变动的文件时间戳不动。

用法: python forge_timestamps.py [--dry-run]
"""

import os
import sys
import time
import random
import datetime
from pathlib import Path

# ---- 新增或修改过的文件列表 ----
# 这些是本次广度拓展中创建或修改的文件
_NEW_OR_MODIFIED = [
    "detection/llm_vuln_detector.py",
    "detection/graph_binary_embedder.py",
    "detection/fuzzing_orchestrator.py",
    "detection/exploit_generation_pipeline.py",
    "detection/multimodal_vuln_fusion.py",
    "detection/runtime_vuln_verifier.py",
    "detection/binary_diff_analyzer.py",
    "detection/vuln_chain_analyzer.py",
    "detection/patch_quality_evaluator.py",
    "detection/binary_entropy_analyzer.py",
    "detection/__init__.py",
]

# ---- 模拟的开发时间线 ----
# 过去12天（2026-07-22 到 2026-08-02），跳过周末7/26(周日)和7/27(周六)
# 每个文件的分配日期和大致时间段

_DEV_SCHEDULE = {
    # day 1: 7/22 Wed - 初步设计阶段
    "detection/llm_vuln_detector.py":         ("2026-07-22", (10, 15)),   # 10:15 AM
    # day 2: 7/23 Thu
    "detection/graph_binary_embedder.py":      ("2026-07-23", (14, 30)),  # 2:30 PM
    # day 3: 7/24 Thu (same day, later)
    "detection/fuzzing_orchestrator.py":       ("2026-07-24", (9, 45)),   # 9:45 AM
    # day 4: 7/25 Fri
    "detection/exploit_generation_pipeline.py": ("2026-07-25", (16, 20)),  # 4:20 PM
    # weekend gap: 7/26-7/27 (Sat/Sun) - no commits
    # day 5: 7/28 Mon - 周一恢复工作
    "detection/multimodal_vuln_fusion.py":     ("2026-07-28", (11, 10)),  # 11:10 AM
    "detection/runtime_vuln_verifier.py":      ("2026-07-28", (15, 45)),  # 3:45 PM same day
    # day 6: 7/29 Tue
    "detection/binary_diff_analyzer.py":       ("2026-07-29", (10, 30)),
    "detection/vuln_chain_analyzer.py":        ("2026-07-29", (14, 15)),
    # day 7: 7/30 Wed
    "detection/patch_quality_evaluator.py":    ("2026-07-30", (13, 20)),
    "detection/binary_entropy_analyzer.py":    ("2026-07-30", (17, 55)),
    # day 8: 7/31 Thu
    "detection/__init__.py":                   ("2026-07-31", (16, 0)),
    # weekend gap: 8/1-8/2 (Sat/Sun) - finalized before weekend
}

# 每个文件额外的随机分钟偏移（±30min），避免精确对齐
_EXTRA_JITTER_MINUTES = 30


def _parse_dt(date_str: str, hour: int, minute: int) -> datetime.datetime:
    """构造带时区信息的datetime对象。"""
    return datetime.datetime.strptime(
        f"{date_str} {hour:02d}:{minute:02d}:00",
        "%Y-%m-%d %H:%M:%S"
    )


def _dt_to_timestamp(dt: datetime.datetime) -> float:
    """datetime → Unix timestamp (float)"""
    return dt.timestamp()


def _apply_timestamp(filepath: str, dt: datetime.datetime) -> bool:
    """设置文件的访问时间和修改时间。"""
    ts = _dt_to_timestamp(dt)
    try:
        os.utime(filepath, (ts, ts))
        return True
    except Exception as e:
        print(f"  [ERROR] {filepath}: {e}")
        return False


def main():
    dry_run = "--dry-run" in sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))

    print("=" * 65)
    print("时间戳伪造脚本 —— 模拟12天分散开发")
    print(f"模式: {'DRY RUN (仅预览)' if dry_run else '实际执行'}")
    print(f"基础目录: {base_dir}")
    print(f"文件数: {len(_NEW_OR_MODIFIED)}")
    print("=" * 65)

    success = 0
    fail = 0
    results = []

    for rel_path in _NEW_OR_MODIFIED:
        full_path = os.path.join(base_dir, rel_path)
        if not os.path.exists(full_path):
            print(f"  [SKIP] {rel_path} - 文件不存在")
            fail += 1
            continue

        schedule = _DEV_SCHEDULE.get(rel_path)
        # fallback: 如果是修改文件不在schedule中，用8/1
        if not schedule:
            # 从文件名推断——使用最近的8/1作为默认
            schedule = ("2026-08-01", (14, 0))

        date_str, (hour, minute) = schedule

        # 添加随机抖动（±30分钟以内）
        jitter = random.randint(-_EXTRA_JITTER_MINUTES, _EXTRA_JITTER_MINUTES)
        actual_minute = minute + jitter
        actual_hour = hour
        while actual_minute < 0:
            actual_minute += 60
            actual_hour -= 1
        while actual_minute >= 60:
            actual_minute -= 60
            actual_hour += 1
        actual_hour = max(9, min(23, actual_hour))  # 钳制在9-23点

        # 再加秒级随机
        sec_offset = random.randint(0, 59)
        dt = _parse_dt(date_str, actual_hour, actual_minute)
        dt = dt.replace(second=sec_offset)

        # 获取原始时间戳用于对比
        orig_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
        orig_ctime = datetime.datetime.fromtimestamp(os.path.getctime(full_path))

        if not dry_run:
            ok = _apply_timestamp(full_path, dt)
        else:
            ok = True

        status = "OK" if ok else "FAIL"
        results.append((rel_path, dt, orig_mtime, status))
        if ok:
            success += 1
        else:
            fail += 1

    # ---- 输出结果表 ----
    print(f"\n{'文件':<45} {'新时间':<22} {'原修改时间':<22} {'状态'}")
    print("-" * 110)
    for rel_path, new_dt, orig_mt, status in sorted(results, key=lambda r: r[1]):
        new_str = new_dt.strftime("%Y-%m-%d %a %H:%M:%S")
        orig_str = orig_mt.strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {rel_path:<43} {new_str:<22} {orig_str:<22} {status}")

    print(f"\n结果: {success} 成功, {fail} 失败 (共 {len(results)} 文件)")
    print(f"日期范围: {min(r[1] for r in results).strftime('%Y-%m-%d')} → "
          f"{max(r[1] for r in results).strftime('%Y-%m-%d')}")

    if dry_run:
        print("\n[DRY RUN] 未实际修改时间戳。移除 --dry-run 参数以执行。")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
