# UAF基准测试样本生成器 (UAF Benchmark Sample Generator)
# 一键生成15个CVE复现样本: 源码 + Makefile + README + manifest.
# 每个样本模拟一个真实CVE的UAF核心模式.
# 创建: 2026-07-23

import json
from pathlib import Path
from gen_uaf_templates import get_template, SAMPLE_DEFS

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples_uaf"


def _c_source(cve: str, desc: str, pattern: str, safe_name: str) -> str:
    body = get_template(pattern, safe_name)
    return f'''/**
 * {cve} — {desc}
 * UAF模式: {pattern}
 *
 * 样本设计:
 *   精简化复现该CVE的核心UAF机制.
 *   保留原始漏洞的数据流结构: malloc→free→use.
 *   去除平台特定代码, 仅保留可静态分析的user-space等价逻辑.
 *
 * 对静态分析具有挑战性的原因:
 *   1. free和use可能在不同的执行路径上 (路径敏感)
 *   2. 指针可能通过全局变量/栈/寄存器间接到use (别名分析)
 *   3. free后可能有NULL赋值但走不到use (条件分析)
 *   4. 跨函数free→use传播 (过程间分析)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{body}
'''


def _makefile(cve: str, target: str, src: str) -> str:
    T = "\t"
    return f'''# {cve} — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: {target}_O0 {target}_O2 {target}_Os

{target}_O0: {src}
{T}$ $(CFLAGS) -O0 -o $@ $<

{target}_O2: {src}
{T}$ $(CFLAGS) -O2 -o $@ $<

{target}_Os: {src}
{T}$ $(CFLAGS) -Os -o $@ $<

clean:
{T}rm -f {target}_O0 {target}_O2 {target}_Os
'''


def _readme(cve: str, desc: str, pattern: str) -> str:
    return f'''# {cve} — UAF Benchmark Sample
- **CVE ID**: {cve}
- **Type**: Use-After-Free
- **Description**: {desc}
- **Pattern**: {pattern}

# Detection Challenges
1. Path Sensitivity: free/use may be on different execution paths
2. Pointer Aliasing: multiple pointers to same freed object
3. Cross-Function: free in callee, use in caller
4. Global/Stack Tracking: pointer stored in non-register storage

# Compilation
```bash
make && make clean
```
'''


def generate_all():
    """生成全部15个UAF基准测试样本."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []

    for cve, dirname, desc, pattern in SAMPLE_DEFS:
        sample_dir = SAMPLES_DIR / dirname
        sample_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "v_" + dirname.replace("cve_", "").replace("-", "_")[:24]
        src_name = f"{dirname}_uaf.c"
        target_name = f"{dirname}_uaf"

        src_path = sample_dir / src_name
        src_path.write_text(
            _c_source(cve, desc, pattern, safe_name), encoding="utf-8")

        mf_path = sample_dir / "Makefile"
        mf_path.write_text(
            _makefile(cve, target_name, src_name), encoding="utf-8")

        readme_path = sample_dir / "README.md"
        readme_path.write_text(
            _readme(cve, desc, pattern), encoding="utf-8")

        for opt in ("O0", "O2", "Os"):
            manifest.append({
                "cve": cve, "type": "uaf", "pattern": pattern,
                "binary": str((sample_dir / f"{target_name}_{opt}").resolve()),
                "compiler": "gcc", "opt": opt,
                "compiled": False,
                "source": str(src_path.resolve()),
            })

        print(f"  Generated: {dirname} ({cve}) [{pattern}]")

    manifest_path = SAMPLES_DIR / "benchmark_uaf_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(SAMPLE_DEFS)} UAF benchmark samples...")
    generate_all()
    print("Done. Run 'make' in each sample directory to compile.")
