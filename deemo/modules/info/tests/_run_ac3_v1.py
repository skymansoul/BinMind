#!/usr/bin/env python
import sys, json; target = sys.argv[1]; sample_dir = sys.argv[2]
sys.path.insert(0, "."); sys.path.insert(0, "info_collection"); sys.path.insert(0, "info_collection/src")
import subprocess
# 提取导入
imports = {"all_imports": {}}
try:
    p = subprocess.run(["objdump", "-T", target], capture_output=True, text=True, timeout=10)
    for line in p.stdout.splitlines():
        if "*UND*" in line:
            parts = line.split()
            if len(parts) >= 5:
                imports["all_imports"].setdefault("libc.so.6", []).append(parts[-1])
except: pass
# 提取字符串
try:
    p = subprocess.run(["strings", target], capture_output=True, text=True, timeout=10)
    strings = [(i, s) for i, s in enumerate(p.stdout.splitlines()) if len(s) >= 3]
except: strings = []
# checksec
checksec = {"arch": "x86_64"}
# AC3检测
from info_collection.src.heap_overflow_detector import detect_heap_overflow
result = detect_heap_overflow(imports, strings, checksec)
stats = result.get("stats", {})
out = {"findings": stats.get("total", 0), "high_conf": stats.get("high_conf", 0),
       "avg_confidence": stats.get("avg_confidence", 0)}
print(json.dumps(out))
