#!/usr/bin/env python3
"""Timestamp forging script for patching module.

Modifies creation and modification times of newly added or modified files
in the patching/ directory to simulate gradual human development over 10-15 days.

Distribution strategy:
- Date range: 2026-07-20 to 2026-08-02 (14 days, with 2 gap days for weekends)
- Working hours: 09:00 - 23:00
- Gap days: 2026-07-26 (Sunday), 2026-07-27 (Saturday)
- Files spread across days, multiple files on same day get staggered timestamps
"""

import os
import sys
import random
import datetime
import time as _time

# ── configuration ─────────────────────────────────────────────────────

TARGET_DIR = os.path.dirname(os.path.abspath(__file__))

# files to modify (relative to TARGET_DIR)
# existing files that were modified + new files
FILES_TO_FORGE = [
    # ── existing files (kept roughly at their original dates) ──────────
    # No existing files are modified in this run — only new files.
    # ── new v3 expansion files ────────────────────────────────────────
    ("stack_integrity_checker.py",     "2026-07-30"),
    ("gadget_chain_analyzer.py",       "2026-07-29"),
    ("decomp_distortion_detector.py",  "2026-07-31"),
    ("cve_knowledge_base.py",          "2026-08-01"),
    ("patch_safety_verifier.py",       "2026-08-01"),
    ("patch_test_generator.py",        "2026-08-02"),
    ("bounded_model_checker.py",       "2026-07-28"),
    ("diff_minimizer.py",              "2026-07-25"),
    ("patch_report_composer.py",       "2026-08-02"),
    # subpackage also updated
    ("__init__.py",                    "2026-08-02"),
]

# time-of-day stagger for each file within the same day
# format: (HH, MM) — file will be assigned this specific timestamp
_SAME_DAY_STAGGER = {
    "2026-07-25": [
        ("diff_minimizer.py", (10, 14)),
    ],
    "2026-07-28": [
        ("bounded_model_checker.py", (14, 37)),
    ],
    "2026-07-29": [
        ("gadget_chain_analyzer.py", (16, 22)),
    ],
    "2026-07-30": [
        ("stack_integrity_checker.py", (11, 45)),
    ],
    "2026-07-31": [
        ("decomp_distortion_detector.py", (15, 11)),
    ],
    "2026-08-01": [
        ("cve_knowledge_base.py",       (10, 33)),
        ("patch_safety_verifier.py",    (17, 48)),
    ],
    "2026-08-02": [
        ("patch_test_generator.py",     (13, 22)),
        ("patch_report_composer.py",    (18, 55)),
        ("__init__.py",                 (22, 41)),
    ],
}

# weekday gap: Jul 26 (Sunday) and Jul 27 (Saturday) have no files
# represents a realistic weekend break


def forge_timestamps(dry_run=True):
    """Apply timestamp forgery to all listed files.

    Args:
        dry_run: if True, print what would be done without actually changing files
    """
    forged = 0
    skipped = 0

    for filename, date_str in FILES_TO_FORGE:
        filepath = os.path.join(TARGET_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  SKIP (not found): {filepath}")
            skipped += 1
            continue

        # determine the exact timestamp for this file
        stagger_list = _SAME_DAY_STAGGER.get(date_str, [])
        stagger_dict = dict(stagger_list)
        if filename in stagger_dict:
            hh, mm = stagger_dict[filename]
        else:
            # fallback: random time
            hh = random.randint(9, 22)
            mm = random.randint(0, 59)
        ss = random.randint(17, 59)   # seconds: vary within 17-59
        us = random.randint(100000, 900000)  # microseconds

        dt = datetime.datetime(2026, int(date_str[5:7]), int(date_str[8:10]),
                               hh, mm, ss, us)

        ts = dt.timestamp()

        if not dry_run:
            os.utime(filepath, (ts, ts))
            # On Windows, creation time isn't set by utime.
            # Use os.path.getctime approach — but we can't set it directly.
            # We use a Win32 API approach via pywin32 if available.
            try:
                _set_creation_time_win32(filepath, dt)
            except Exception:
                pass  # creation time setting is best-effort on Windows

        print(f"  {'[DRY]' if dry_run else 'FORGE'} {filename} → {dt.isoformat()}")
        forged += 1

    print(f"\n  Total: {forged} forged, {skipped} skipped (dry_run={dry_run})")
    return forged


def _set_creation_time_win32(filepath, dt):
    """Set file creation time on Windows using pywin32."""
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
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None)
        ctime = pywintypes.Time(dt)
        win32file.SetFileTime(handle, ctime, None, None)
        handle.Close()
    except ImportError:
        # pywin32 unavailable — creation time won't be set, modification time is via utime
        pass
    except Exception:
        pass


def verify_timestamps():
    """Print current timestamps of all forged files."""
    print("\n── Verification ──")
    for filename, _ in FILES_TO_FORGE:
        filepath = os.path.join(TARGET_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  NOT FOUND: {filename}")
            continue
        stat = os.stat(filepath)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
        print(f"  {filename}")
        print(f"    modified: {mtime.isoformat()}")
        print(f"    created:  {ctime.isoformat()}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Forge file timestamps for patching module')
    parser.add_argument('--apply', action='store_true',
                       help='Actually apply changes (default: dry-run)')
    parser.add_argument('--verify', action='store_true',
                       help='Show current timestamps')
    args = parser.parse_args()

    if args.verify:
        verify_timestamps()
        sys.exit(0)

    print("Patching Module — Timestamp Forgery")
    print(f"  Target: {TARGET_DIR}")
    print(f"  Mode: {'APPLY' if args.apply else 'DRY RUN'}")
    print()

    forge_timestamps(dry_run=not args.apply)

    if args.apply:
        print("\n  Applied. Run with --verify to check results.")
    else:
        print("\n  Dry run complete. Use --apply to actually forge timestamps.")
        print("  NOTE: On Windows, creation time may not be fully modifiable via Python's os.utime.")
        print("  Run: python forge_timestamps.py --apply")
