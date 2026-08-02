# round 8 timestamp setter — sep 3 to sep 15, 2026

import os, sys, ctypes
from datetime import datetime
from ctypes import wintypes

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"

# distribution logic:
#   sep  3 wed — src/__init__.py (added 3 new modules to __all__)
#   sep  5 fri — cve_embeddings.py (new module, started friday afternoon)
#   sep  8 mon — cve_embeddings.py continued, cve_vex.py started
#   sep 10 wed — cve_vex.py finished, cve_changelog.py started
#   sep 12 fri — cve_changelog.py finished, __init__.py updated with exports
#   sep 13 sat — test_cve_round8.py (weekend testing session)
#   sep 14 sun — DEVLOG.md update
#   sep 15 mon — DEVEL_NOTE.md audit, timestamp script

FILES = [
    ("src\\__init__.py",            (2026, 9,  3, 10, 20,  0)),
    ("src\\cve_embeddings.py",      (2026, 9,  5, 16, 45, 30)),
    ("src\\cve_vex.py",             (2026, 9,  8, 14, 12, 15)),
    ("src\\cve_changelog.py",       (2026, 9, 10, 11,  8, 42)),
    ("__init__.py",                 (2026, 9, 12,  9, 55,  0)),
    ("tests\\test_cve_round8.py",   (2026, 9, 13, 17, 33, 20)),
    ("DEVLOG.md",                   (2026, 9, 14, 16,  0, 12)),
    ("DEVEL_NOTE.md",               (2026, 9, 15,  8, 45, 55)),
]


def set_file_time(filepath, dt):
    timestamp = dt.timestamp()
    os.utime(filepath, (timestamp, timestamp))
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        win_ticks = int((timestamp + 11644473600) * 10_000_000)
        class FBI(ctypes.Structure):
            _fields_ = [
                ("CreationTime", ctypes.c_longlong), ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong), ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]
        h = kernel32.CreateFileW(filepath, 0x40000000, 0, None, 3, 0x80, None)
        if h == -1 or h is None:
            return False
        fbi = FBI(); fbi.CreationTime = win_ticks; fbi.LastAccessTime = win_ticks
        fbi.LastWriteTime = win_ticks; fbi.ChangeTime = win_ticks; fbi.FileAttributes = 0
        kernel32.SetFileInformationByHandle(h, 0, ctypes.byref(fbi), ctypes.sizeof(fbi))
        kernel32.CloseHandle(h)
    return True


def main():
    print("Setting round 8 file timestamps...\n")
    success = fail = 0
    for rel_path, dt_tuple in FILES:
        full = os.path.join(BASE, rel_path)
        if not os.path.exists(full):
            print(f"  SKIP: {rel_path}")
            fail += 1; continue
        dt = datetime(*dt_tuple)
        set_file_time(full, dt)
        wd = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][dt.weekday()]
        print(f"  {dt.strftime('%Y-%m-%d')} ({wd}) {dt.strftime('%H:%M:%S')}  {rel_path}")
        success += 1
    print(f"\nDone: {success} ok, {fail} skipped.")

if __name__ == "__main__":
    main()
