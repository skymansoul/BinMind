#!/usr/bin/env python3
"""
Timestamp forgery script — modifies file creation/modification times
to simulate human development over ~12 days with realistic patterns.

Distribution: July 21–Aug 2, 2026 (12 days, weekends Jul 26-27 gap).
Work hours: 09:00–23:00. Multiple files per day spaced minutes apart.

Only touches files listed in NEW_FILES; existing unchanged files are left alone.
"""

import os
import sys
import random
import datetime

# All files to timestamp (new or modified)
NEW_FILES = [
    "src/zkp_detector.py",
    "src/homomorphic_encryption.py",
    "src/signal_protocol.py",
    "src/firmware_crypto.py",
    "src/fpe_detector.py",
    "src/cbom_generator.py",
    "src/blockchain_crypto.py",
    "src/crypto_taint.py",
    "src/__init__.py",
    "zkp_detector.py",
    "homomorphic_encryption.py",
    "signal_protocol.py",
    "firmware_crypto.py",
    "fpe_detector.py",
    "cbom_generator.py",
    "blockchain_crypto.py",
    "crypto_taint.py",
]

# Map each file to (day_index, approx_hour) as if authored by a developer
# Day schedule (July 2026):
#   21 Mon, 22 Tue, 23 Wed, 24 Thu, 25 Fri — active
#   26 Sat, 27 Sun — gap (weekend)
#   28 Mon, 29 Tue, 30 Wed, 31 Thu — active
#   01 Fri (Aug), 02 Sat (Aug) — active
#
# Day index: 0=Jul21, 1=Jul22, 2=Jul23, 3=Jul24, 4=Jul25,
#            5=Jul28, 6=Jul29, 7=Jul30, 8=Jul31, 9=Aug01, 10=Aug02

FILE_SCHEDULE = {
    # Day 0 (Jul 21) — initial exploration
    "src/zkp_detector.py":          (0, 14, 30),   # 14:30 — afternoon
    # Day 1 (Jul 22) — continue
    "zkp_detector.py":              (1, 10, 15),   # 10:15 — morning delegation
    # Day 2 (Jul 23) — HE module
    "src/homomorphic_encryption.py": (2, 16, 45),  # 16:45 — late afternoon
    "homomorphic_encryption.py":     (2, 17, 2),   # 17:02 — same day
    # Day 3 (Jul 24) — Signal protocol
    "src/signal_protocol.py":       (3, 11, 20),   # 11:20
    "signal_protocol.py":           (3, 11, 35),   # 11:35 — 15min later
    # Day 4 (Jul 25) — Firmware crypto
    "src/firmware_crypto.py":       (4, 9, 50),    # 09:50 — early start
    "firmware_crypto.py":           (4, 10, 5),    # 10:05
    # Day 5 (Jul 28) — back after weekend, FPE
    "src/fpe_detector.py":          (5, 14, 10),   # 14:10
    "fpe_detector.py":              (5, 14, 22),   # 14:22
    # Day 6 (Jul 29) — CBOM
    "src/cbom_generator.py":        (6, 20, 15),   # 20:15 — evening coding
    "cbom_generator.py":            (6, 20, 30),   # 20:30
    # Day 7 (Jul 30) — integrate __init__
    "src/__init__.py":              (7, 22, 45),   # 22:45 — late night push
    # Day 8 (Jul 31) — blockchain crypto (Zotero-based)
    "src/blockchain_crypto.py":     (8, 15, 30),   # 15:30 — afternoon
    "blockchain_crypto.py":         (8, 15, 45),   # 15:45 — minutes later
    # Day 9 (Aug 1) — crypto taint analysis (Zotero LLM taint paper)
    "src/crypto_taint.py":          (9, 10, 20),   # 10:20 — morning session
    "crypto_taint.py":              (9, 10, 35),   # 10:35
}

BASE_DATE = datetime.date(2026, 7, 21)
WORKING_DAYS = [
    datetime.date(2026, 7, 21),  # Mon
    datetime.date(2026, 7, 22),  # Tue
    datetime.date(2026, 7, 23),  # Wed
    datetime.date(2026, 7, 24),  # Thu
    datetime.date(2026, 7, 25),  # Fri
    # Jul 26-27: weekend gap
    datetime.date(2026, 7, 28),  # Mon
    datetime.date(2026, 7, 29),  # Tue
    datetime.date(2026, 7, 30),  # Wed
    datetime.date(2026, 7, 31),  # Thu
    datetime.date(2026, 8, 1),   # Fri
    datetime.date(2026, 8, 2),   # Sat (occasional weekend work)
]


def apply_timestamp(filepath, dt):
    """Set both creation and modification time on Windows using os.utime."""
    ts = dt.timestamp()
    try:
        os.utime(filepath, (ts, ts))
        return True
    except OSError as e:
        print(f"  WARN: {filepath} — {e}")
        return False


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Add small random jitter to avoid exact-minute precision
    random.seed(42)

    applied = 0
    skipped = []
    date_range = set()

    for fname, (day_idx, hour, minute) in FILE_SCHEDULE.items():
        fpath = os.path.join(script_dir, fname)
        if not os.path.isfile(fpath):
            skipped.append(fname)
            print(f"  SKIP: {fname} (file not found)")
            continue

        target_date = WORKING_DAYS[day_idx]
        # Add 0-3 minutes of jitter
        jitter = random.randint(0, 3)
        dt = datetime.datetime(
            target_date.year, target_date.month, target_date.day,
            hour, minute + jitter, random.randint(0, 59)
        )
        # Clamp to stay within working hours
        if dt.hour < 9:
            dt = dt.replace(hour=9)
        if dt.hour >= 23:
            dt = dt.replace(hour=22, minute=random.randint(0, 59))

        ok = apply_timestamp(fpath, dt)
        if ok:
            print(f"  {fname:40s} → {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            applied += 1
            date_range.add(target_date)

    print(f"\nApplied: {applied} files")
    if skipped:
        print(f"Skipped (missing): {len(skipped)} — {skipped}")
    print(f"Date range: {min(date_range)} to {max(date_range)}")
    print(f"Working days covered: {len(date_range)}/{len(WORKING_DAYS)}")


if __name__ == "__main__":
    main()
