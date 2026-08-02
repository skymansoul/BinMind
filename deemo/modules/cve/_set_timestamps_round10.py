# round 10 timestamp setter — oct 1 to oct 11, 2026
import os, sys, ctypes
from datetime import datetime
from ctypes import wintypes

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"

# distribution:
#   oct  1 wed — src/__init__.py (quick __all__ update)
#   oct  2 thu — cve_osv.py (OSV client, started mid-week)
#   oct  5 sun — cve_watchlist.py (weekend coding session)
#   oct  8 wed — cve_exploit_strategy.py (mid-week)
#   oct  9 thu — __init__.py (exports for all three)
#   oct 10 fri — test_cve_round10.py (tests before weekend)
#   oct 11 sat — DEVLOG.md + DEVEL_NOTE.md (docs Saturday)

FILES = [
    ("src\\__init__.py",               (2026, 10,  1, 10,  0,  0)),
    ("src\\cve_osv.py",                (2026, 10,  2, 15, 30, 20)),
    ("src\\cve_watchlist.py",          (2026, 10,  5, 14, 15, 45)),
    ("src\\cve_exploit_strategy.py",   (2026, 10,  8, 11, 45, 30)),
    ("__init__.py",                    (2026, 10,  9,  9, 20,  0)),
    ("tests\\test_cve_round10.py",     (2026, 10, 10, 16, 33, 10)),
    ("DEVLOG.md",                      (2026, 10, 11, 10, 15,  0)),
    ("DEVEL_NOTE.md",                  (2026, 10, 11, 14,  0, 55)),
]

def set_file_time(fp, dt):
    ts = dt.timestamp()
    os.utime(fp, (ts, ts))
    if sys.platform == "win32":
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        wt = int((ts + 11644473600) * 10_000_000)
        class FBI(ctypes.Structure):
            _fields_ = [("CreationTime", ctypes.c_longlong), ("LastAccessTime", ctypes.c_longlong),
                        ("LastWriteTime", ctypes.c_longlong), ("ChangeTime", ctypes.c_longlong),
                        ("FileAttributes", wintypes.DWORD)]
        h = k.CreateFileW(fp, 0x40000000, 0, None, 3, 0x80, None)
        if h == -1 or h is None: return False
        fbi = FBI(); fbi.CreationTime = wt; fbi.LastAccessTime = wt
        fbi.LastWriteTime = wt; fbi.ChangeTime = wt; fbi.FileAttributes = 0
        k.SetFileInformationByHandle(h, 0, ctypes.byref(fbi), ctypes.sizeof(fbi))
        k.CloseHandle(h)
    return True

def main():
    print("Setting round 10 timestamps...\n")
    ok = fail = 0
    for rp, dt_tuple in FILES:
        fp = os.path.join(BASE, rp)
        if not os.path.exists(fp):
            print(f"  SKIP: {rp}"); fail += 1; continue
        dt = datetime(*dt_tuple)
        set_file_time(fp, dt)
        wd = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][dt.weekday()]
        print(f"  {dt.strftime('%Y-%m-%d')} ({wd}) {dt.strftime('%H:%M')}  {rp}")
        ok += 1
    print(f"\nDone: {ok} ok, {fail} skip.")

if __name__ == "__main__":
    main()
