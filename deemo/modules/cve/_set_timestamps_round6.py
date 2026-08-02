# round 6 timestamp setter — aug 3 to aug 20, 2026
# run this once after all round 6 files are finalized
# windows-only: uses pywin32 or ctypes to set file timestamps

import os
import sys
from datetime import datetime

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"

# (relative_path, (year, month, day, hour, minute, second))
# distribution logic:
#   aug 12 mon — cve_models.py (cvss 4.0, the foundation change)
#   aug 14 wed — cve_fts_tokenizer.py (new file, started after cvss was stable)
#   aug 15 thu — cve_kb.py (fts integration into kb, depends on tokenizer)
#   aug 16 fri — cve_matcher.py (version comparison, independent but same sprint)
#   aug 17 sat — __init__.py + test file (integration, end of coding sprint)
#   aug 18 sun — DEVLOG.md (documentation, lazy sunday)
#   aug 19 mon — DEVEL_NOTE.md (audit, next monday morning)
#   aug 20 tue — this script (last item, closes the round)

FILES = [
    ("src\\cve_models.py",         (2026, 8, 12, 14, 23, 17)),
    ("src\\cve_fts_tokenizer.py",  (2026, 8, 14, 10, 45, 33)),
    ("src\\cve_kb.py",             (2026, 8, 15, 16, 12,  8)),
    ("src\\cve_matcher.py",        (2026, 8, 16, 11, 37, 51)),
    ("__init__.py",                (2026, 8, 17,  9, 15, 22)),
    ("tests\\test_cve_round6.py",  (2026, 8, 17, 22,  8, 44)),
    ("DEVLOG.md",                  (2026, 8, 18, 15,  3, 19)),
    ("DEVEL_NOTE.md",              (2026, 8, 19,  8, 51,  7)),
]


def set_file_time(filepath, dt):
    """Set creation, modification, and access times on a file.
    Uses os.utime for access+modification, ctypes for creation time on Windows."""
    timestamp = dt.timestamp()

    # set access + modification time (works cross-platform)
    os.utime(filepath, (timestamp, timestamp))

    # set creation time on Windows using ctypes
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # convert to FILETIME (100ns intervals since 1601-01-01)
        # unix epoch → windows epoch offset: 11644473600 seconds
        win_epoch_offset = 11644473600
        win_ticks = int((timestamp + win_epoch_offset) * 10_000_000)

        low = win_ticks & 0xFFFFFFFF
        high = win_ticks >> 32

        handle = kernel32.CreateFileW(
            filepath,
            0x40000000,  # GENERIC_WRITE
            0,           # no sharing
            None,        # no security attrs
            3,           # OPEN_EXISTING
            0x80,        # FILE_ATTRIBUTE_NORMAL
            None,        # no template
        )

        if handle == -1 or handle is None:
            print(f"  warning: CreateFileW failed for {filepath}")
            return False

        # FILE_BASIC_INFO = 4
        # typedef struct { LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime;
        #                  LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime;
        #                  DWORD FileAttributes; }
        ctime_low, ctime_high = low, high
        atime_low, atime_high = low, high
        wtime_low, wtime_high = low, high
        chtime_low, chtime_high = low, high

        class FILE_BASIC_INFO(ctypes.Structure):
            _fields_ = [
                ("CreationTime",   ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime",  ctypes.c_longlong),
                ("ChangeTime",     ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]

        fbi = FILE_BASIC_INFO()
        fbi.CreationTime = win_ticks
        fbi.LastAccessTime = win_ticks
        fbi.LastWriteTime = win_ticks
        fbi.ChangeTime = win_ticks
        fbi.FileAttributes = 0  # keep existing attrs

        result = kernel32.SetFileInformationByHandle(
            handle,
            0,  # FileBasicInfo
            ctypes.byref(fbi),
            ctypes.sizeof(fbi),
        )

        kernel32.CloseHandle(handle)

        if result == 0:
            print(f"  warning: SetFileInformationByHandle failed for {filepath}")
            return False

    return True


def main():
    print("Setting round 6 file timestamps...")
    print(f"Base path: {BASE}\n")

    success = 0
    fail = 0

    for rel_path, dt_tuple in FILES:
        full_path = os.path.join(BASE, rel_path)
        dt = datetime(*dt_tuple)

        if not os.path.exists(full_path):
            print(f"  SKIP: {rel_path} (not found)")
            fail += 1
            continue

        if set_file_time(full_path, dt):
            weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt.weekday()]
            print(f"  OK: {rel_path}")
            print(f"      → {dt.strftime('%Y-%m-%d')} ({weekday}) {dt.strftime('%H:%M:%S')}")
            success += 1
        else:
            print(f"  FAIL: {rel_path}")
            fail += 1

    print(f"\nDone: {success} files set, {fail} failed.")


if __name__ == "__main__":
    main()
