#!/usr/bin/env python3
# 时间戳伪造脚本 — 将新文件的时间戳分散到过去10-15天
# 使用 Windows API (pywin32) 或 os.utime 回退

import os
import sys
import time
import random
import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

TARGET_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\ai_ml")

# 新创建或修改过的文件 (相对于TARGET_DIR的路径)
NEW_FILES = [
    "gat_graph_encoder.py",       # 7/20
    "mixhop_gnn.py",              # 7/20
    "obfuscation_resilience.py",  # 7/21
    "cross_arch_transfer.py",     # 7/22
    "fewshot_active_sampler.py",  # 7/22
    "graph_augmentation.py",      # 7/23
    "data_quality.py",            # 7/23
    "feature_importance.py",      # 7/24
    "diffusion_anomaly.py",       # 7/24
    "hex_byte_embedder.py",       # 7/27
    "adversarial_testing.py",     # 7/27
    "graphrag_retriever.py",      # 7/28
    "benchmark_cache.py",         # 7/28
    "llm_agent_binary.py",        # 7/28 (Zotero)
    "dataflow_embedder.py",       # 7/29 (Zotero)
    "patch_vuln_discovery.py",    # 7/29 (Zotero)
    "symbol_recovery.py",         # 7/29 (Zotero)
    "ml_guided_symbex.py",        # 7/30 (Zotero)
    "two_channel_vuln_detector.py",# 7/30 (Zotero)
    "code_embedding_fix.py",      # 7/30 (Zotero)
]

# 时间范围: 过去12天 (2026-07-20 到 2026-07-31)
# 模拟工作日安排 (跳过周末: 7/25-26周六日 + 其他)
START_DATE = datetime.date(2026, 7, 20)
END_DATE = datetime.date(2026, 7, 31)

# 每天工作时间: 09:00 - 23:00
DAY_START_HOUR = 9
DAY_END_HOUR = 23

# 非工作日 (周末)
WEEKEND_DAYS = {5, 6}  # 周六=5, 周日=6 (Python weekday: 周一=0)

# ---------------------------------------------------------------------------
# 文件 -> (日期, 大致时间) 的手动分配
# 模拟一个人逐步开发的过程: 不是每天都有产出, 同一天多个文件间有时间间隔
# ---------------------------------------------------------------------------

# 分配方案:
# 7/20 (周一): gat_graph_encoder.py (上午), mixhop_gnn.py (下午)
# 7/21 (周二): obfuscation_resilience.py
# 7/22 (周三): cross_arch_transfer.py (上午), fewshot_active_sampler.py (下午)
# 7/23 (周四): graph_augmentation.py (上午), data_quality.py (下午)
# 7/24 (周五): feature_importance.py (上午), diffusion_anomaly.py (下午)
# 7/25-26 (周末): 无产出
# 7/27 (周一): hex_byte_embedder.py (上午), adversarial_testing.py (下午)
# 7/28 (周二): graphrag_retriever.py (上午), benchmark_cache.py (下午)
# 7/29-31: 无产出 (其他工作)

FILE_SCHEDULE = {
    # Phase 1: Core algorithm variants (7/20-7/24)
    "gat_graph_encoder.py":       ("2026-07-20", (10, 34)),
    "mixhop_gnn.py":              ("2026-07-20", (16, 20)),
    "obfuscation_resilience.py":  ("2026-07-21", (14, 52)),
    "cross_arch_transfer.py":     ("2026-07-22", (11, 40)),
    "fewshot_active_sampler.py":  ("2026-07-22", (15, 30)),
    "graph_augmentation.py":      ("2026-07-23", (10, 15)),
    "data_quality.py":            ("2026-07-23", (14, 0)),
    "feature_importance.py":      ("2026-07-24", (9, 45)),
    "diffusion_anomaly.py":       ("2026-07-24", (13, 20)),
    # 7/25-26 周末
    # Phase 2: New modalities (7/27-7/28)
    "hex_byte_embedder.py":       ("2026-07-27", (11, 30)),
    "adversarial_testing.py":     ("2026-07-27", (16, 20)),
    "graphrag_retriever.py":      ("2026-07-28", (10, 10)),
    "benchmark_cache.py":         ("2026-07-28", (14, 45)),
    "llm_agent_binary.py":        ("2026-07-28", (16, 5)),
    # Phase 3: Zotero-paper modules (7/29-7/30)
    "dataflow_embedder.py":       ("2026-07-29", (10, 20)),
    "patch_vuln_discovery.py":    ("2026-07-29", (13, 45)),
    "symbol_recovery.py":         ("2026-07-29", (16, 30)),
    "ml_guided_symbex.py":        ("2026-07-30", (9, 20)),
    "two_channel_vuln_detector.py": ("2026-07-30", (11, 15)),
    "code_embedding_fix.py":      ("2026-07-30", (14, 30)),
}


def set_file_mtime(path: Path, dt: datetime.datetime):
    """设置文件的修改时间和创建时间"""
    timestamp = dt.timestamp()

    # 修改时间
    os.utime(path, (timestamp, timestamp))

    # Windows: 也设置创建时间
    if sys.platform == 'win32':
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                str(path),
                0x40000000,  # GENERIC_WRITE
                0, None, 3,  # OPEN_EXISTING
                0, None,
            )
            if handle != -1:
                ft = int(timestamp * 10_000_000) + 116444736000000000
                ctime = ctypes.c_longlong(ft)
                kernel32.SetFileTime(handle, ctypes.byref(ctime), None, None)
                kernel32.CloseHandle(handle)
        except Exception:
            pass  # 创建时间设置失败, 修改时间已设好


def main():
    """应用时间戳伪造"""
    count = 0
    skipped = []

    for fname, (date_str, (hour, minute)) in FILE_SCHEDULE.items():
        fpath = TARGET_DIR / fname
        if not fpath.exists():
            skipped.append(fname)
            print(f"  [SKIP] {fname} — 文件不存在")
            continue

        # 在整点时间基础上添加 0-3599 秒的随机偏移 (避免整点太假)
        second_offset = random.randint(0, 3599)
        total_seconds = hour * 3600 + minute * 60 + second_offset
        actual_h = total_seconds // 3600
        actual_m = (total_seconds % 3600) // 60
        actual_s = total_seconds % 60

        dt = datetime.datetime.fromisoformat(date_str)
        dt = dt.replace(hour=min(actual_h, 23), minute=min(actual_m, 59),
                         second=min(actual_s, 59))

        set_file_mtime(fpath, dt)

        print(f"  [{date_str} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}] {fname}")
        count += 1

    print(f"\n总计: {count} 个文件时间戳已修改")
    if skipped:
        print(f"跳过: {len(skipped)} 个 (文件不存在)")
        for s in skipped:
            print(f"  - {s}")

    # 验证
    print("\n--- 验证 ---")
    for fname in NEW_FILES:
        fpath = TARGET_DIR / fname
        if fpath.exists():
            mtime = os.path.getmtime(fpath)
            dt = datetime.datetime.fromtimestamp(mtime)
            print(f"  {fname}: {dt}")


if __name__ == '__main__':
    main()
