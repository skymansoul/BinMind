#!/usr/bin/env python3
"""批量读取缺少README的CVE样本源码, 生成README."""
import os, re, sys

BASE = os.path.join(os.path.dirname(__file__), "..", "tests", "cve_samples", "heap_overflow")
BASE = os.path.normpath(BASE)

# 读取已有README模板
template = None
t = os.path.join(BASE, "cve_01_simple_overflow", "README.md")
if os.path.exists(t):
    with open(t, "r", encoding="utf-8", errors="replace") as f:
        template = f.read()

# 获取缺少README的目录
missing = []
for name in sorted(os.listdir(BASE)):
    dirpath = os.path.join(BASE, name)
    if not os.path.isdir(dirpath):
        continue
    if name in ("scan_results", "__pycache__"):
        continue
    readme = os.path.join(dirpath, "README.md")
    if os.path.exists(readme):
        continue
    # 找.c文件
    cfiles = [f for f in os.listdir(dirpath) if f.endswith(".c")]
    if not cfiles:
        continue
    missing.append((name, dirpath, cfiles[0]))

print(f"Missing README: {len(missing)}")
for name, dirpath, cfile in missing:
    src = os.path.join(dirpath, cfile)
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    lines = content.split("\n")
    print(f"\n=== {name} ({cfile}) ===")
    for line in lines[:20]:
        print(f"  {line}")
