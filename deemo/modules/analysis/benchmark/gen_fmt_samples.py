# 格式字符串基准测试样本生成器 (Format String Benchmark Sample Generator)
# 一键生成15个CVE复现样本: 源码 + Makefile + README + manifest.
# 创建: 2026-07-02

import json
from pathlib import Path
from gen_fmt_templates import get_template, SAMPLE_DEFS

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples_fmt"


def _c_source(cve: str, desc: str, pattern: str, safe_name: str) -> str:
    body = get_template(pattern, safe_name)
    return f'''/**
 * {cve} — {desc}
 * 模式: {pattern}
 *
 * 样本设计: 精简化复现格式字符串漏洞核心机制.
 * 对静态分析的挑战:
 *   1. 格式字符串来源需追踪 (寄存器/栈/全局/跨函数)
 *   2. 字面量格式字符串应被过滤 (误报控制)
 *   3. 跨函数传播需参数追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{body}
'''


def _makefile(cve: str, target: str, src: str) -> str:
    T = "\t"
    return f'''# {cve} — Format String Benchmark
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


def generate_all():
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []

    for cve, dirname, desc, pattern in SAMPLE_DEFS:
        sample_dir = SAMPLES_DIR / dirname
        sample_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "v_" + dirname.replace("cve_", "").replace("-", "_")[:24]
        src_name = f"{dirname}_fmt.c"
        target_name = f"{dirname}_fmt"

        src_path = sample_dir / src_name
        src_path.write_text(
            _c_source(cve, desc, pattern, safe_name), encoding="utf-8")

        mf_path = sample_dir / "Makefile"
        mf_path.write_text(
            _makefile(cve, target_name, src_name), encoding="utf-8")

        readme = sample_dir / "README.md"
        readme.write_text(f"# {cve} — Format String Benchmark\n"
                          f"- Pattern: {pattern}\n- Description: {desc}\n",
                          encoding="utf-8")

        for opt in ("O0", "O2", "Os"):
            manifest.append({
                "cve": cve, "type": "format_string", "pattern": pattern,
                "binary": str((sample_dir / f"{target_name}_{opt}").resolve()),
                "compiler": "gcc", "opt": opt,
                "compiled": False,
                "source": str(src_path.resolve()),
            })

        print(f"  Generated: {dirname} ({cve}) [{pattern}]")

    manifest_path = SAMPLES_DIR / "benchmark_fmt_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(SAMPLE_DEFS)} format string benchmark samples...")
    generate_all()
    print("Done.")
