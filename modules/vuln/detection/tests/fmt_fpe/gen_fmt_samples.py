"""生成 FPE 格式字符串样本集目录 (源码/Makefile/说明/manifest).

创建: 2024-11-05
每个样本独立目录: <ROOT>/<ID>/ {源码, Makefile, README.md}
顶层生成 manifest.json。
用法:
  python gen_fmt_samples.py [目标根目录]
"""

import json
import sys
from pathlib import Path

from modules.vuln.detection.tests.fmt_fpe.samples_data import (
    ALL_FMT_SAMPLES, expected_label, description)

_MAKEFILE = """\
# {name} — {sid}
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/{name}.exe
packed: bin/packed/{name}.exe

bin/plain/{name}.exe: {name}.c
	$(CC) $(CFLAGS_O0) {name}.c -o $@

bin/packed/{name}.exe: {name}.c
	$(CC) $(CFLAGS_O2) {name}.c -o $@

clean:
	rm -rf bin
"""

_README = """# {sid} — {name}

## 样本类别
**{expected}** ({expected_cn})

## 漏洞/行为描述
{desc}

## 触发条件
- 编译: `make`
- 检测: 静态扫描 bin/plain/{name}.exe 或 bin/packed/{name}.exe

## 为何该样本有效
- {expected_desc}
"""


def write_sample(root: Path, sid: str, name: str, src: str, desc: str):
    d = root / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.c").write_text(src, encoding="utf-8")
    (d / "Makefile").write_text(
        _MAKEFILE.format(name=name, sid=sid), encoding="utf-8")
    exp = expected_label(sid)
    exp_cn = "用户可控格式串" if exp == "vuln" else "常量格式串"
    exp_desc = ("编译产物中的格式参数溯源必须指向用户输入" if exp == "vuln"
                else "格式参数溯源必须指向常量池, 检测应滤除")
    (d / "README.md").write_text(
        _README.format(sid=sid, name=name, expected=exp,
                       expected_cn=exp_cn, desc=desc,
                       expected_desc=exp_desc),
        encoding="utf-8")


def generate(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for sid, name, src, desc in ALL_FMT_SAMPLES:
        write_sample(root, sid, name, src, desc)
        manifest.append({
            "id": sid, "name": name,
            "expected": expected_label(sid),
            "description": description(sid),
            "source": f"{sid}/{name}.c",
        })
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[gen] {len(manifest)} samples written to {root}")


def main() -> None:
    here = Path(__file__).resolve().parent
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "samples"
    generate(target)


if __name__ == "__main__":
    main()
