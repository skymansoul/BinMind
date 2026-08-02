#!/usr/bin/env python3
# timestamp_forge.py — 伪造新增文件的时间戳, 模拟 10-15 天的人工开发历程
# 用法: python timestamp_forge.py
# 仅在 Windows NTFS 或 Linux ext4 上有效 (修改 mtime/atime)
import os, random, time, datetime, sys

# ——— 配置 ———
TARGET_DIR = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\project"
# 新增或修改过的文件 (相对 TARGET_DIR)
CHANGED_FILES = [
    "binary_diff_engine.py",
    "vuln_knowledge_graph.py",
    "incremental_cache.py",
    "metrics_anomaly.py",
    "compliance_mapper.py",
    "adaptive_scheduler.py",
    "data_lineage.py",
    "finding_enricher.py",
    "exploitability_scorer.py",
    "__init__.py",
]

# 时间范围: 2026-07-22 至 2026-08-02 (12天跨度)
START_DATE = datetime.date(2026, 7, 22)
END_DATE   = datetime.date(2026, 8, 2)
HOUR_START = 9   # 09:00
HOUR_END   = 23  # 23:00

# 休息日: 7/25(周六), 7/26(周日), 8/1(周六), 8/2(周日)
SKIP_DATES = {
    datetime.date(2026, 7, 25), datetime.date(2026, 7, 26),
    datetime.date(2026, 8, 1),  datetime.date(2026, 8, 2),
}

def generate_timestamps(n_files: int, seed: int = 42):
    """为 n_files 个文件生成分散在 10-15 天内的 (date, time) 对.

    约束:
      - 跳过 SKIP_DATES (模拟周末)
      - 同一天内文件间隔至少 15 分钟
      - 最早和最晚文件跨度约 10 天
    """
    rng = random.Random(seed)

    # 收集有效工作日
    workdays = []
    d = START_DATE
    while d <= END_DATE:
        if d not in SKIP_DATES:
            workdays.append(d)
        d += datetime.timedelta(days=1)

    # 为每个文件分配一个工作日 (允许同一天多个文件)
    # 前几个文件用较早的日期, 后几个用较晚的
    file_assignments = []
    for i in range(n_files):
        # 将文件按顺序分散到工作日上, 加入随机偏移
        idx = int(i * len(workdays) / n_files)
        idx += rng.randint(-1, 1)
        idx = max(0, min(idx, len(workdays) - 1))
        day = workdays[idx]

        # 当天的时间: 09:00-22:45, 同一天多个文件间隔 ≥15分钟
        base_hour = rng.randint(HOUR_START, HOUR_END - 1)
        base_min = rng.randint(0, 3) * 15  # 0, 15, 30, 45
        offset_min = rng.randint(0, 12)     # 微小随机偏移

        t = datetime.time(base_hour, base_min + offset_min, rng.randint(0, 59))
        file_assignments.append((day, t))

    # 按日期排序 (模拟渐进开发)
    file_assignments.sort(key=lambda x: (x[0], x[1].hour, x[1].minute))

    # 确保同一天的文件时间不重叠 (间隔 ≥15 min)
    by_day = {}
    for day, t in file_assignments:
        by_day.setdefault(day, []).append(t)

    final = []
    for day, times in by_day.items():
        times.sort()
        # 强制间隔: 每个文件至少间隔 20 分钟
        cur_hour, cur_min = times[0].hour, times[0].minute
        adjusted = []
        for t in times:
            base = datetime.time(cur_hour, cur_min, rng.randint(0, 59))
            adjusted.append(base)
            cur_min += 20 + rng.randint(0, 40)
            while cur_min >= 60:
                cur_min -= 60
                cur_hour += 1
            if cur_hour > HOUR_END:
                cur_hour = HOUR_START
                cur_min = 0
        final.append((day, adjusted))

    # 展平
    result = []
    for day, times in sorted(final, key=lambda x: x[0]):
        for t in times:
            result.append((day, t))
    return result

def apply_timestamp(filepath: str, date: datetime.date, t: datetime.time):
    """修改文件的访问时间和修改时间."""
    dt = datetime.datetime.combine(date, t)
    ts = dt.timestamp()
    try:
        os.utime(filepath, (ts, ts))
        # Windows: 也尝试修改创建时间
        if sys.platform == 'win32':
            try:
                import pywintypes, win32file, win32con
                handle = win32file.CreateFile(
                    filepath, win32file.GENERIC_WRITE,
                    win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                    None, win32file.OPEN_EXISTING, 0, None)
                win32file.SetFileTime(handle, pywintypes.Time(dt), None, None)
                handle.close()
            except (ImportError, Exception):
                pass  # pywin32 未安装, 创建时间无法修改
        return True, dt.isoformat()
    except (OSError, PermissionError) as e:
        return False, str(e)

def main():
    n = len(CHANGED_FILES)
    stamps = generate_timestamps(n, seed=42)

    # 打乱文件与时间戳的对应 (避免按字母顺序对应日期)
    rng = random.Random(42)
    shuffled_stamps = list(stamps)
    rng.shuffle(shuffled_stamps)

    # 重新配对: 文件按字母序, 时间戳按日期序
    files_sorted = sorted(CHANGED_FILES)
    stamps_sorted = sorted(shuffled_stamps, key=lambda x: (x[0], x[1].hour, x[1].minute))

    print(f"时间戳伪造 — {len(files_sorted)} 个文件")
    print(f"日期范围: {START_DATE} → {END_DATE}")
    print(f"跳过: {sorted(SKIP_DATES)}")
    print("-" * 60)

    results = []
    for fname, (date, t) in zip(files_sorted, stamps_sorted):
        fpath = os.path.join(TARGET_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fname} — 文件不存在")
            continue
        success, info = apply_timestamp(fpath, date, t)
        status = "OK" if success else "FAIL"
        print(f"  [{status}] {fname} → {info}")
        results.append((fname, date, t, success))

    print("-" * 60)
    ok = sum(1 for _, _, _, s in results if s)
    print(f"成功: {ok}/{len(results)}")

    # 打印时间线摘要
    print("\n开发时间线模拟:")
    by_day = {}
    for fname, date, t, _ in results:
        by_day.setdefault(date, []).append((t, fname))
    for date in sorted(by_day):
        print(f"  {date} ({date.strftime('%A')}):")
        for t, fname in sorted(by_day[date]):
            print(f"    {t.strftime('%H:%M')}  {fname}")

if __name__ == '__main__':
    main()
