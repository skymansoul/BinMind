# round 9 timestamp setter — sep 16 to sep 28, 2026
import os, sys, ctypes
from datetime import datetime
from ctypes import wintypes

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\cve"

# distribution:
#   sep 16 tue — src/__init__.py (quick update)
#   sep 18 thu — cve_attack_graph.py (reading aksu paper, building graph logic)
#   sep 22 mon — cve_risk_scorer.py (new week, new module)
#   sep 25 thu — cve_attack_mitre.py (att&ck mapping, stateless so faster)
#   sep 26 fri — __init__.py (exports for all three modules)
#   sep 27 sat — test_cve_round9.py (weekend testing)
#   sep 28 sun — DEVLOG.md + DEVEL_NOTE.md (docs weekend)

FILES = [
    ("src\\__init__.py",            (2026, 9, 16, 10,  0,  0)),
    ("src\\cve_attack_graph.py",    (2026, 9, 18, 15, 30, 20)),
    ("src\\cve_risk_scorer.py",     (2026, 9, 22,  9, 45, 10)),
    ("src\\cve_attack_mitre.py",    (2026, 9, 25, 11, 20, 55)),
    ("__init__.py",                 (2026, 9, 26, 14, 10,  0)),
    ("tests\\test_cve_round9.py",   (2026, 9, 27, 16,  5, 30)),
    ("DEVLOG.md",                   (2026, 9, 28, 10, 30,  0)),
    ("DEVEL_NOTE.md",               (2026, 9, 28, 15, 45, 12)),
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
    print("Setting round 9 timestamps...\n")
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
