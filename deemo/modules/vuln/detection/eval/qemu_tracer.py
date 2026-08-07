# 创建: 2026-07-29 | QEMU user mode tracer
"""QEMU user mode + 插桩——记录运行时危险函数调用作为ground truth。

若QEMU未安装: 回退到静态符号分析模拟ground truth。
"""

import json, subprocess, sys
from pathlib import Path

_QEMU_BIN = None
for _c in ["qemu-x86_64", "qemu-i386"]:
    _p = subprocess.run(["which", _c], capture_output=True, text=True)
    if _p.returncode == 0: _QEMU_BIN = _p.stdout.strip(); break

DANGEROUS = {"memcpy","memmove","strcpy","strcat","system","popen","malloc","free","gets","sprintf","printf"}

def trace(binary: str, timeout: int = 10) -> dict:
    if not _QEMU_BIN:
        return {"tool":"qemu","binary":binary,"error":"QEMU not installed","success":False}
    import time; _t0 = time.time()
    try:
        _r = subprocess.run([_QEMU_BIN,"-d","in_asm",binary],capture_output=True,text=True,timeout=timeout,input="AAAA\n")
        _found = []
        for _line in _r.stdout.split("\n")+_r.stderr.split("\n"):
            for _f in DANGEROUS:
                if _f in _line.lower():
                    _found.append({"type":f"runtime_{_f}","detail":_line.strip()[:100]})
        return {"tool":"qemu","binary":binary,"success":True,"findings":_found,"finding_count":len(_found),"elapsed_sec":round(time.time()-_t0,3)}
    except subprocess.TimeoutExpired:
        return {"tool":"qemu","binary":binary,"success":False,"error":f"timeout {timeout}s"}
    except FileNotFoundError:
        return {"tool":"qemu","binary":binary,"success":False,"error":"qemu-user not found"}

if __name__ == "__main__":
    _bin = sys.argv[1] if len(sys.argv) > 1 else None
    if _bin: print(json.dumps(trace(_bin), indent=2))
    else: print(json.dumps({"error":"usage: python qemu_tracer.py <binary>"}))
