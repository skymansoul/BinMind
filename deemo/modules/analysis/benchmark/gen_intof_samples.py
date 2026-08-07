# 整数溢出基准测试样本生成器 (Integer Overflow Benchmark Sample Generator)
# 生成12个CVE复现样本: 12种不同的溢出模式 × 3优化级 = 36个二进制.
# 创建: 2026-04-21

import json
import subprocess
from pathlib import Path
from gen_intof_templates import get_template, SAMPLE_DEFS

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples_intof"


def _c_source(cve: str, desc: str, pattern: str, safe_name: str) -> str:
    body = get_template(pattern, safe_name)
    return f'''/**
 * {cve} — {desc}
 * 模式: {pattern}
 *
 * 对静态分析的挑战:
 *   1. 溢出算术指令 (imul/shl/add) 的结果追踪
 *   2. 跨寄存器/栈槽的标记传播
 *   3. 编译器优化 (O2/Os) 后的模式识别
 *   4. 宽度转换 (32→64, 16→32) 的精确追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

{body}
'''


def _makefile(cve: str, target: str, src: str) -> str:
    T = "\t"
    return f'''# {cve} — Integer Overflow Benchmark
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


def generate_all(compile: bool = True):
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []

    for cve, dirname, desc, pattern in SAMPLE_DEFS:
        sample_dir = SAMPLES_DIR / dirname
        sample_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "v_" + dirname.replace("cve_", "").replace("-", "_")[:24]
        src_name = f"{dirname}_intof.c"
        target_name = f"{dirname}_intof"

        # Write source
        src_path = sample_dir / src_name
        src_path.write_text(
            _c_source(cve, desc, pattern, safe_name), encoding="utf-8")

    # Write Makefile
        mf_path = sample_dir / "Makefile"
        mf_path.write_text(
            _makefile(cve, target_name, src_name), encoding="utf-8")

    # Write README
        readme = sample_dir / "README.md"
        readme.write_text(f"# {cve} — Integer Overflow Benchmark\n"
                          f"- Pattern: {pattern}\n- Description: {desc}\n",
                          encoding="utf-8")

    # Compile
        compiled = {}
        if compile:
            for opt in ("O0", "O2", "Os"):
                exe_name = f"{target_name}_{opt}.exe"
                exe_path = sample_dir / exe_name
                result = subprocess.run(
                    ["gcc", f"-{opt}", "-no-pie", "-fno-pie",
                     "-o", str(exe_path), str(src_path)],
                    capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    compiled[opt] = True
                else:
                    compiled[opt] = False
                    print(f"  COMPILE ERROR {dirname} {opt}: {result.stderr[:200]}")

        for opt in ("O0", "O2", "Os"):
            exe_path = sample_dir / f"{target_name}_{opt}.exe"
            manifest.append({
                "cve": cve, "type": "integer_overflow", "pattern": pattern,
                "binary": str(exe_path.resolve()),
                "compiler": "gcc", "opt": opt,
                "compiled": compiled.get(opt, False),
                "source": str(src_path.resolve()),
            })

        compiled_str = ",".join(k for k, v in compiled.items() if v)
        print(f"  Generated: {dirname} ({cve}) [{pattern}] compiled=[{compiled_str}]")

    manifest_path = SAMPLES_DIR / "benchmark_intof_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    compiled_count = sum(1 for m in manifest if m["compiled"])
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries, {compiled_count} compiled)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(SAMPLE_DEFS)} integer overflow benchmark samples...")
    generate_all(compile=True)
    print("Done.")
