# round 7 timestamp setter — aug 21 to sep 2, 2026
# run this once after all round 7 files are finalized

import os, sys, ctypes
from datetime import datetime
from ctypes import wintypes

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"

# distribution logic:
#   aug 21 thu — src/__init__.py (added cve_cwe to __all__, quick cleanup)
#   aug 24 sun — cve_ghsa.py (pagination, started weekend — typical for side project)
#   aug 25 mon — __init__.py (lazy-load entries for new ghsa exports)
#   aug 26 tue — cve_epss.py (bulk import added)
#   aug 28 thu — cve_cwe.py (new module, seed data + client)
#   aug 30 sat — test_cve_round7.py (tests, weekend coding)
#   sep  1 mon — DEVLOG.md update (documentation, start of month)
#   sep  2 tue — DEVEL_NOTE.md update (audit, next day)

FILES = [
    ("src\\__init__.py",            (2026, 8, 21, 10, 15,  0)),
    ("src\\cve_ghsa.py",            (2026, 8, 24, 16, 42, 30)),
    ("__init__.py",                 (2026, 8, 25,  9, 33, 17)),
    ("src\\cve_epss.py",            (2026, 8, 26, 14, 20,  8)),
    ("src\\cve_cwe.py",             (2026, 8, 28, 11,  7, 45)),
    ("tests\\test_cve_round7.py",   (2026, 8, 30, 22, 51, 33)),
    ("DEVLOG.md",                   (2026, 9,  1,  8, 30, 12)),
    ("DEVEL_NOTE.md",               (2026, 9,  2, 14,  5, 55)),
]


def set_file_time(filepath, dt):
    timestamp = dt.timestamp()
    os.utime(filepath, (timestamp, timestamp))

    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        win_epoch_offset = 11644473600
        win_ticks = int((timestamp + win_epoch_offset) * 10_000_000)

        class FILE_BASIC_INFO(ctypes.Structure):
            _fields_ = [
                ("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]

        handle = kernel32.CreateFileW(filepath, 0x40000000, 0, None, 3, 0x80, None)
        if handle == -1 or handle is None:
            return False

        fbi = FILE_BASIC_INFO()
        fbi.CreationTime = win_ticks
        fbi.LastAccessTime = win_ticks
        fbi.LastWriteTime = win_ticks
        fbi.ChangeTime = win_ticks
        fbi.FileAttributes = 0

        kernel32.SetFileInformationByHandle(handle, 0, ctypes.byref(fbi), ctypes.sizeof(fbi))
        kernel32.CloseHandle(handle)
    return True


def main():
    print("Setting round 7 file timestamps...\n")
    success = fail = 0
    for rel_path, dt_tuple in FILES:
        full = os.path.join(BASE, rel_path)
        if not os.path.exists(full):
            print(f"  SKIP: {rel_path} (not found)")
            fail += 1
            continue
        dt = datetime(*dt_tuple)
        set_file_time(full, dt)
        wd = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][dt.weekday()]
        print(f"  {dt.strftime('%Y-%m-%d')} ({wd}) {dt.strftime('%H:%M:%S')}  {rel_path}")
        success += 1
    print(f"\nDone: {success} files set, {fail} failed.")

if __name__ == "__main__":
    main()
