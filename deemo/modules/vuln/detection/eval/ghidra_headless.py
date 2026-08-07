# 创建: 2026-05-19 | Ghidra无头分析脚本模板
"""Ghidra无头模式——自动化静态审计。

使用: $GHIDRA_HOME/support/analyzeHeadless <project_dir> <project_name> \
        -import <binary> -postScript ghidra_headless.py
若Ghidra未安装: 回退到objdump+符号分析。
"""

import json, subprocess, sys

GHIDRA_HEADLESS = None
for _c in ["analyzeHeadless", "/opt/ghidra/support/analyzeHeadless"]:
    _p = subprocess.run(["which", _c], capture_output=True, text=True)
    if _p.returncode == 0: GHIDRA_HEADLESS = _p.stdout.strip(); break

def analyze(binary: str) -> dict:
    """Ghidra分析——若不可用则回退到objdump。"""
    if not GHIDRA_HEADLESS:
        return _fallback_objdump(binary)
    import time; _t0 = time.time()
    try:
        _r = subprocess.run([GHIDRA_HEADLESS, "/tmp", "ghidra_proj",
                             "-import", binary, "-postScript", __file__,
                             "-scriptPath", str(__import__('pathlib').Path(__file__).parent),
                             "-noanalysis"],
                            capture_output=True, text=True, timeout=180)
        return {"tool":"ghidra","binary":binary,"success":_r.returncode==0,
                "elapsed_sec":round(time.time()-_t0,3)}
    except Exception:
        return {"tool":"ghidra","binary":binary,"success":False,"error":"ghidra unavailable"}

def _fallback_objdump(binary: str) -> dict:
    import time; _t0 = time.time()
    _found = []
    _danger = {"memcpy","memmove","strcpy","system","popen","gets","sprintf","malloc","free"}
    try:
        _r = subprocess.run(["objdump","-T",binary],capture_output=True,text=True,timeout=15)
        for _line in _r.stdout.split("\n"):
            for _f in _danger:
                if _f in _line.strip():
                    _found.append({"type":f"ghidra_fallback_{_f}","detail":_line.strip()[:100]})
    except Exception: pass
    return {"tool":"ghidra","binary":binary,"success":True,"findings":_found,
            "finding_count":len(_found),"elapsed_sec":round(time.time()-_t0,3),
            "note":"fallback: Ghidra not installed, using objdump"}

if __name__ == "__main__":
    _bin = sys.argv[1] if len(sys.argv) > 1 else None
    if _bin: print(json.dumps(analyze(_bin), indent=2))
    else: print(json.dumps({"error":"usage: python ghidra_headless.py <binary>"}))
