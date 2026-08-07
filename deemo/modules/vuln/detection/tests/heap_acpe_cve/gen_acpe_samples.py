"""生成 ACPE 堆溢出样本集目录 (源码/Makefile/README/manifest).

创建: 2026-07-21
每个样本独立目录:
  <SAMPLE_ROOT>/<ID>/
    <name>.c       CVE 复现或良性对照源码
    Makefile       gcc 编译规则 (O0/O2 双档)
    README.md      漏洞描述/触发条件/为何有效
顶层生成 manifest.json 记录 (id, name, expected, description)。

用法:
  python gen_acpe_samples.py [目标根目录]
"""

import json
import sys
from pathlib import Path

from modules.vuln.detection.tests.heap_acpe_cve.samples_data import (
    ALL_SAMPLES, expected_label, description)


_MAKEFILE = """\
# {name} — {cve}
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
# O2 档保留漏洞逻辑: 禁用死代码消除/存储消除/内联/builtin展开,
# 防止未使用结果的示例代码被整体优化掉 (真实工程结果均为已用)。
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/{name}.exe
packed: bin/packed/{name}.exe

bin/plain/{name}.exe: {name}.c
	$ $(CFLAGS_O0) {name}.c -o $@

bin/packed/{name}.exe: {name}.c
	$ $(CFLAGS_O2) {name}.c -o $@

clean:
	rm -rf bin
"""

_README = """# {cve} — {name}

# 样本类别
**{expected}** ({expected_cn})

# 漏洞/行为描述
{desc}

# 触发条件
- 编译: `make` (生成 bin/plain 与 bin/packed 两档)
- 运行: 直接执行, 触发堆写入路径
- 检测: 静态扫描 bin/plain/{name}.exe 或 bin/packed/{name}.exe

# 为何该样本有效
- {expected_desc}
- 该模式覆盖 {cve} 的核心容量失衡点, 可被分配容量溯源
  分析 (ACPE) 复现并归类。

# 备注
- 源码为最小化复现, 仅保留分配-拷贝容量关系, 不含真实库代码。
- 良性对照组用于测量误报削减率, 不包含漏洞。
"""


def write_sample(root: Path, sid: str, name: str, src: str, desc: str):
    """写入单个样本目录."""
    d = root / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.c").write_text(src, encoding="utf-8")
    (d / "Makefile").write_text(
        _MAKEFILE.format(name=name, cve=sid), encoding="utf-8")
    exp = expected_label(sid)
    exp_cn = "真实堆溢出" if exp == "vuln" else "良性安全"
    exp_desc = ("编译产物中的 malloc→memcpy 容量失衡必须被检出" if exp == "vuln"
                else "含守卫/等价容量, 检测必须滤除以免误报")
    (d / "README.md").write_text(
        _README.format(cve=sid, name=name, expected=exp,
                       expected_cn=exp_cn, desc=desc,
                       expected_desc=exp_desc),
        encoding="utf-8")


def generate(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for sid, name, src, desc in ALL_SAMPLES:
        write_sample(root, sid, name, src, desc)
        manifest.append({
            "id": sid,
            "name": name,
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
