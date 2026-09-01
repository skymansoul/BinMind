#!/usr/bin/env python3
# 生成BWR样本集的Makefile与README.
# 每个样本目录已含 vuln.c, 此处补齐构建与说明文件, 保证独立可编译.
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples_bwr")

MAKEFILE = """CC = gcc
CFLAGS = -O0 -g -fno-builtin -fno-inline
TARGET = vuln.exe

all: $(TARGET)

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) vuln.c -o $(TARGET)

clean:
\trm -f $(TARGET)
"""

INFO = {
    "bwr_01_strcpy_literal_overflow": ("堆溢出(确定)", "strcpy 源字面量恢复上界15 > malloc(4)可用区 → 确认溢出; 基线跳过无界写会漏报"),
    "bwr_02_strcpy_literal_safe": ("安全", "strcpy 源字面量上界6 ≤ malloc(64)可用区 → BWR判定安全不告警"),
    "bwr_03_strcpy_heap_source_safe": ("安全", "源为malloc(32)堆缓冲, 目标malloc(64); 栈槽别名解析恢复上界32≤64 → 安全"),
    "bwr_04_sprintf_literal_overflow": ("堆溢出(确定)", "sprintf 格式串'%s!'+实参'hello' → 最大输出7 > malloc(4)可用区 → 确认溢出"),
    "bwr_05_snprintf_argfix": ("堆溢出(确定)", "snprintf size 实参在第2位(32) > malloc(8)可用区; PCST修正参数索引后检出"),
    "bwr_06_strcpy_stack_source_safe": ("安全", "源为栈缓冲tmp[16], 经lea[rbp-X]恢复上界16 ≤ malloc(32)可用区 → 安全"),
    "bwr_07_fread_product": ("堆溢出(确定)", "fread size*nmemb=4096 > malloc(256)可用区; PCST取乘积实参后检出"),
    "bwr_08_read_dstfix": ("堆溢出(确定)", "read 目标缓冲在第2实参, 写入64 > malloc(32)可用区; PCST修正dst索引后检出"),
}

for name, (cls, desc) in INFO.items():
    d = os.path.join(SAMPLES, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Makefile"), "w", encoding="utf-8", newline="\n") as f:
        f.write(MAKEFILE)
    with open(os.path.join(d, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {name}\n\n")
        f.write(f"- 类别: {cls}\n")
        f.write(f"- 判定: {desc}\n")
        f.write("- 构建: `make`\n")
        f.write("- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表\n")

print("generated %d sample makefiles/readmes" % len(INFO))
