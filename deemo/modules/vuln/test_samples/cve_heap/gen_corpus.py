# coding: utf-8
# 创建: 2026-05-24  |  堆溢出 CVE 样本语料生成器
#
"""
CVE 样本语料生成器 (逻辑部分)。

数据来自 samples_vuln_a / samples_vuln_b / samples_safe。
为每个样本生成 vuln.c、Makefile、README.md, 并写出 expected.csv。

样本布局 (16 个, 12 TP + 4 TN):
  TP — 真实堆溢出 (12): CVE 2014-0038 ~ 2024-2961
  TN — 安全场景 (4):  有界守卫 / 同源分配 / 对齐 padding / 多分配点

运行: python gen_corpus.py [--out DIR]
"""

import argparse
from pathlib import Path

from samples_vuln_a import SAMPLES_VULN_A
from samples_vuln_b import SAMPLES_VULN_B
from samples_safe import SAMPLES_SAFE

MAKEFILE = """CC ?= gcc
CFLAGS = -Wall -O0 -g -fno-builtin -fno-stack-protector -no-pie

vuln.exe: vuln.c
\t$ $(CFLAGS) -o $@ vuln.c

vuln.asm: vuln.exe
\tobjdump -d -M intel vuln.exe > vuln.asm

all: vuln.exe vuln.asm

clean:
\trm -f vuln.exe vuln.asm vuln.o
"""

SAMPLES = SAMPLES_VULN_A + SAMPLES_VULN_B + SAMPLES_SAFE


def gen_readme(s) -> str:
    return f"""# {s['cve']} — {s['title']}

# 漏洞模式

{s['pattern']}

# 触发条件

{s['trigger']}

# 为何有效

{s['why']}

# Ground Truth

Expected: **{s['expected']}**

# 构建

```sh
make
# 产出 vuln.exe (MinGW PE) 与 vuln.asm (objdump 反汇编)
```
"""


def gen_one(out: Path, s: dict) -> None:
    d = out / s["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "vuln.c").write_text(s["code"].strip() + "\n", encoding="utf-8")
    (d / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (d / "README.md").write_text(gen_readme(s), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="generate CVE heap corpus")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent))
    args = ap.parse_args()
    out = Path(args.out)
    for s in SAMPLES:
        s["expected"] = "TP" if s["id"].startswith("cve") else "TN"
        gen_one(out, s)
        print(f"  gen {s['id']}  expected={s['expected']}")
    gt = ["sample_id,expected"]
    gt += [f"{s['id']},{s['expected']}" for s in SAMPLES]
    (out / "expected.csv").write_text("\n".join(gt) + "\n", encoding="utf-8")
    print(f"generated {len(SAMPLES)} samples into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
