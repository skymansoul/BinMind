#!/usr/bin/env python3
"""
Timestamp forgery script — spoof modification times on newly created files
to simulate gradual human development across a 10–15 day period.

Strategy:
- Files get distributed across days with plausible work-session times (09:00–23:00)
- Same-day files are staggered by minutes to hours (not all at once)
- 1–2 day gaps simulate days without development (meetings, other tasks)
- Existing/unchanged file timestamps are NOT touched
"""

import os
import sys
import random
import datetime

# [offset, day_label, hour_range, files]
# Each entry: (day_offset_from_start, label, (min_hour, max_hour), [file_paths])
# day_offset: 0 = July 20, 1 = July 21, ...
# files within same day get staggered: each gets random minutes apart

BASE_DATE = datetime.date(2026, 7, 20)  # anchor start date

# schedule designed to look like a human worked on this across ~13 days
SCHEDULE = [
    # Mon July 20: round-1: Markov fuzzer; round-2: directed fuzzer
    (0, "Mon", (10, 12), [
        "src/markov_fuzz.py",
        "src/directed_fuzz.py",
    ]),
    # Tue July 21: power scheduling + concurrency fuzzer
    (1, "Tue", (14, 16), [
        "src/power_schedule.py",
        "src/concurrency_fuzz.py",
    ]),
    # Wed July 22: dictionary builder + taint tracker
    (2, "Wed", (10, 12), [
        "src/dictionary_builder.py",
        "src/taint_tracker.py",
    ]),
    # Thu-Fri July 23-24: GAP (conference)

    # Sat July 25: seed selector + UAF detector
    (5, "Sat", (20, 22), [
        "src/seed_selector.py",
        "src/uaf_detector.py",
    ]),
    # Sun July 26: GAP

    # Mon July 27: init update + type-aware + ROP analyzer
    (7, "Mon", (9, 11), [
        "src/__init__.py",
        "src/type_aware_fuzz.py",
        "src/rop_analyzer.py",
    ]),
    # Tue July 28: concolic bridge + crash cluster
    (8, "Tue", (14, 17), [
        "src/concolic_bridge.py",
        "src/crash_cluster.py",
    ]),
    # Wed July 29: triage reporter + grammar inferrer
    (9, "Wed", (16, 18), [
        "src/triage_reporter.py",
        "src/grammar_infer.py",
    ]),
    # Thu-Fri July 30-31: GAP

    # Sat Aug 1: memory pattern + regression corpus (final push)
    (12, "Sat", (10, 12), [
        "src/memory_pattern.py",
        "src/regression_corpus.py",
    ]),
]


def apply_timestamps(base_dir: str, dry_run: bool = False):
    """
    Apply spoofed timestamps to files according to SCHEDULE.

    Each file in a same-day group gets a staggered time:
    - first file: random minute near the start of the hour range
    - subsequent files: +random(10, 180) minutes later
    """
    if not os.path.isdir(base_dir):
        print(f"ERROR: {base_dir} is not a directory")
        return 1

    files_touched = 0

    for day_offset, label, (hour_lo, hour_hi), paths in SCHEDULE:
        target_date = BASE_DATE + datetime.timedelta(days=day_offset)

        # random start minute within the hour range
        base_minute = random.randint(0, 59)
        base_hour = random.randint(hour_lo, max(hour_lo, hour_hi - 1))
        base_second = random.randint(0, 59)

        current_dt = datetime.datetime(
            target_date.year, target_date.month, target_date.day,
            base_hour, base_minute, base_second)

        for i, rel_path in enumerate(paths):
            abs_path = os.path.join(base_dir, rel_path)
            if not os.path.exists(abs_path):
                print(f"  SKIP (missing): {rel_path}")
                continue

            if i > 0:
                # stagger: +random(8, 180) minutes from previous file
                gap_minutes = random.randint(8, 180)
                current_dt += datetime.timedelta(minutes=gap_minutes)
                # ensure still within the hour range
                if current_dt.hour > hour_hi:
                    current_dt = current_dt.replace(hour=hour_hi - 1)

            # randomize seconds for realism
            current_dt = current_dt.replace(second=random.randint(0, 59))

            timestamp = current_dt.timestamp()

            if dry_run:
                old_mtime = datetime.datetime.fromtimestamp(
                    os.path.getmtime(abs_path))
                print(f"  WOULD SET: {rel_path}")
                print(f"    {old_mtime.strftime('%Y-%m-%d %H:%M:%S')} → "
                      f"{current_dt.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                try:
                    os.utime(abs_path, (timestamp, timestamp))
                    files_touched += 1
                    print(f"  OK: {rel_path} → "
                          f"{current_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                except OSError as e:
                    print(f"  FAIL: {rel_path}: {e}")

    return 0 if files_touched > 0 else 1


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Spoof file timestamps for gradual development simulation")
    parser.add_argument(
        "base_dir", nargs="?",
        default=".",
        help="Base directory containing src/ (default: current dir)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without modifying files")
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducible scheduling (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"Timestamp forgery — base: {args.base_dir}")
    print(f"Schedule period: {BASE_DATE} → "
          f"{BASE_DATE + datetime.timedelta(days=13)}")
    print(f"Files to touch: {sum(len(p) for _, _, _, p in SCHEDULE)}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'APPLY'}")
    print("-" * 50)

    rc = apply_timestamps(os.path.abspath(args.base_dir), dry_run=args.dry_run)

    print("-" * 50)
    if rc == 0:
        print("Done — timestamps updated.")
    else:
        print("WARNING: no files were touched. Check paths.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
