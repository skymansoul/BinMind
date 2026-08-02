# round 11 — oct 13 to oct 25, 2026
import os, sys, ctypes
from datetime import datetime
from ctypes import wintypes

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"
FILES = [
    ("src\\__init__.py",             (2026, 10, 13, 10,  0,  0)),
    ("src\\cve_nvd_sync.py",         (2026, 10, 15, 14, 30, 20)),
    ("src\\cve_correlation.py",      (2026, 10, 17, 16, 15, 45)),
    ("src\\cve_remediation.py",      (2026, 10, 20, 11, 20, 10)),
    ("__init__.py",                  (2026, 10, 22,  9, 10,  0)),
    ("tests\\test_cve_round11.py",   (2026, 10, 23, 15, 45, 30)),
    ("DEVLOG.md",                    (2026, 10, 24, 18,  0,  0)),
    ("DEVEL_NOTE.md",                (2026, 10, 25, 10, 30, 15)),
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

ok = fail = 0
for rp, dt_tuple in FILES:
    fp = os.path.join(BASE, rp)
    if not os.path.exists(fp):
        print(f"SKIP: {rp}"); fail += 1; continue
    dt = datetime(*dt_tuple); set_file_time(fp, dt)
    wd = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][dt.weekday()]
    print(f"{dt.strftime('%Y-%m-%d')} ({wd}) {rp}")
    ok += 1
print(f"{ok} ok, {fail} skip")

# self
sfp = os.path.join(BASE, '_set_timestamps_round11.py')
os.utime(sfp, (datetime(2026,10,25,11,0,0).timestamp(),)*2)
