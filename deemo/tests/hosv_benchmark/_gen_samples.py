# coding: utf-8
"""
堆溢出测试样本集生成器 — 20 个样本 (13 VULN + 7 SAFE).

样本定义 (源码/CVE/期望判定) 见 hosv_sample_defs.py.
本文件仅含目录创建与文件写出逻辑.

覆盖真实 CVE 写模式: 指针游走写, 结构体数组 off-by-one, 无界输入
(scanf %s / gets), calloc 回绕/工厂指针, 终止符 off-by-one,
memcpy 变量长度符号关联.
SAFE 对照: 有守卫边界/有界输入/正确 +1 分配的变体, 用于验证无误报.
"""

import json
import os

from hosv_sample_defs import (
    SAMPLES_DEF, README_TMPL, TRUTHS, LABEL_TO_VERDICT,
)

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, "samples")


def gen() -> None:
    for sid, cve, mode, label, src in SAMPLES_DEF:
        d = os.path.join(SAMPLES, sid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "vuln.c"), "w", encoding="utf-8") as f:
            f.write(src)
        with open(os.path.join(d, "Makefile"), "w", encoding="utf-8") as f:
            f.write("CC = gcc\n"
                    "CFLAGS = -O0 -g\n\n"
                    "all: vuln\n\n"
                    "vuln: vuln.c\n"
                    "\t$(CC) $(CFLAGS) -o vuln vuln.c\n\n"
                    "run: vuln\n"
                    "\t./vuln\n\n"
                    "clean:\n"
                    "\trm -f vuln\n")
        why = TRUTHS.get(sid, "")
        readme = README_TMPL.format(cve=cve, mode=mode, label=label, why=why)
        with open(os.path.join(d, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)
        with open(os.path.join(d, "truth.json"), "w", encoding="utf-8") as f:
            json.dump({
                "sample": sid, "cve": cve, "mode": mode,
                "label": label, "verdict": LABEL_TO_VERDICT[label],
                "why": why,
            }, f, ensure_ascii=False, indent=2)
    print("generated %d samples in %s" % (len(SAMPLES_DEF), SAMPLES))


if __name__ == "__main__":
    gen()
