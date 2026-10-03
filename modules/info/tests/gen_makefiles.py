#!/usr/bin/env python
"""tests/gen_makefiles.py — 为所有样本目录自动生成 Makefile
遍历 samples/ 下每个目录, 若不存在 Makefile 则自动生成。
检测源码中的 #include 和链接需求, 智能选择编译器和标志。
"""
import os, re
from pathlib import Path

SAMPLES = Path(__file__).parent / "regression" / "samples"

MAKEFILE_TEMPLATE = """# Auto-generated Makefile for {name}
CC ?= gcc
CFLAGS ?= -Wall -O0 -g -fno-stack-protector -z execstack -no-pie
LDFLAGS ?=

all: vuln.exe

vuln.exe: vuln.c
\t$ $(CFLAGS) -o vuln.exe vuln.c $(LDFLAGS)

vuln: vuln.c
\t$ $(CFLAGS) -o vuln vuln.c $(LDFLAGS)

clean:
\trm -f vuln.exe vuln vuln.elf *.o

.PHONY: all clean
"""


def detect_link_flags(code: str) -> str:
    """检测源码是否使用数学库等需要额外链接标志。"""
    flags = []
    if re.search(r'\b(sin|cos|sqrt|pow|ceil|floor|atan)\s*\(', code):
        flags.append("-lm")
    if re.search(r'pthread_create|pthread_join', code):
        flags.append("-lpthread")
    if re.search(r'\b(dlopen|dlsym|dlclose)\s*\(', code):
        flags.append("-ldl")
    return " ".join(flags)


def main():
    created = 0; skipped = 0
    for d in sorted(SAMPLES.iterdir()):
        if not d.is_dir() or d.name == "tests":
            continue
        mf = d / "Makefile"
        if mf.exists():
            skipped += 1
            continue
        src = d / "vuln.c"
        ldflags = ""
        if src.exists():
            ldflags = detect_link_flags(src.read_text(encoding="utf-8", errors="replace"))
        content = MAKEFILE_TEMPLATE.format(name=d.name)
        if ldflags:
            content = content.replace("$(LDFLAGS)", f"$(LDFLAGS) {ldflags}")
        mf.write_text(content)
        created += 1
        print(f"  Created: {d.name}/Makefile")
    print(f"\nDone: {created} created, {skipped} already existed")


if __name__ == "__main__":
    main()
