# coding: utf-8
# 创建: 2026-05-02  |  UAF 语料生成器
#
"""UAF 语料生成器 (逻辑部分).

数据来自 samples_uaf_a / samples_uaf_b / samples_uaf_safe。
生成 vuln.c / Makefile / README.md / expected.csv。

样本布局: 16 个 (12 UAF + 4 SAFE)。

运行: python gen_corpus.py [--out DIR]
"""

import argparse
from pathlib import Path

from samples_uaf_a import SAMPLES_UAF_A
from samples_uaf_b import SAMPLES_UAF_B
from samples_uaf_safe import SAMPLES_UAF_SAFE

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

SAMPLES = SAMPLES_UAF_A + SAMPLES_UAF_B + SAMPLES_UAF_SAFE


def gen_readme(s) -> str:
    return f"""# {s['id']} — {s['title']}

# 漏洞模式

{s['pattern']}

# 触发条件

{s['trigger']}

# 为何有效

{s['why']}

# Ground Truth

Expected: **{s['expected']}** (UAF / SAFE)

# 构建

```sh
make
```
"""


def gen_one(out: Path, s: dict) -> None:
    d = out / s["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "vuln.c").write_text(s["code"].strip() + "\n", encoding="utf-8")
    (d / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (d / "README.md").write_text(gen_readme(s), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="generate UAF corpus")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent))
    args = ap.parse_args()
    out = Path(args.out)
    for s in SAMPLES:
        s["expected"] = "TP" if s["id"].startswith("uaf_") and \
            not s["id"].startswith("uaf_safe_") else "TN"
        gen_one(out, s)
        print(f"  gen {s['id']}  expected={s['expected']}")
    gt = ["sample_id,expected"]
    gt += [f"{s['id']},{s['expected']}" for s in SAMPLES]
    (out / "expected.csv").write_text("\n".join(gt) + "\n", encoding="utf-8")
    print(f"generated {len(SAMPLES)} samples into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
