# 栈溢出基准测试样本生成器 (Stack Overflow Benchmark Sample Generator)
# 12个CVE复现样本 × 3优化级 = 36个二进制.

import json, subprocess
from pathlib import Path
from gen_stackof_templates import get_template, SAMPLE_DEFS

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples_stackof"


def _c_source(cve: str, desc: str, pattern: str, safe_name: str) -> str:
    body = get_template(pattern, safe_name)
    return f'''/**
 * {cve} - {desc}
 * 模式: {pattern}
 *
 * 对静态分析的挑战:
 *   1. 栈缓冲区地址识别 (lea rcx,[rbp-N])
 *   2. 危险函数调用检测 (gets/strcpy/sprintf/memcpy)
 *   3. 写入大小 vs 缓冲区容量比较
 *   4. O2/Os优化后的代码模式保持
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

{body}
'''


def _makefile(cve: str, target: str, src: str) -> str:
    T = "\t"
    return f'''# {cve} - Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: {target}_O0 {target}_O2 {target}_Os

{target}_O0: {src}
{T}$(CC) $(CFLAGS) -O0 -o $@ $<

{target}_O2: {src}
{T}$(CC) $(CFLAGS) -O2 -o $@ $<

{target}_Os: {src}
{T}$(CC) $(CFLAGS) -Os -o $@ $<

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
        src_name = f"{dirname}_stackof.c"
        target_name = f"{dirname}_stackof"

        src_path = sample_dir / src_name
        src_path.write_text(_c_source(cve, desc, pattern, safe_name), encoding="utf-8")

        mf_path = sample_dir / "Makefile"
        mf_path.write_text(_makefile(cve, target_name, src_name), encoding="utf-8")

        readme = sample_dir / "README.md"
        readme.write_text(f"# {cve} - Stack Overflow Benchmark\n"
                          f"- Pattern: {pattern}\n- Description: {desc}\n",
                          encoding="utf-8")

        compiled = {}
        if compile:
            for opt in ("O0", "O2", "Os"):
                exe_name = f"{target_name}_{opt}.exe"
                exe_path = sample_dir / exe_name
                result = subprocess.run(
                    ["gcc", f"-{opt}", "-no-pie", "-fno-pie", "-fno-builtin",
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
                "cve": cve, "type": "stack_overflow", "pattern": pattern,
                "binary": str(exe_path.resolve()),
                "compiler": "gcc", "opt": opt,
                "compiled": compiled.get(opt, False),
                "source": str(src_path.resolve()),
            })

        compiled_str = ",".join(k for k, v in compiled.items() if v)
        print(f"  {dirname} ({cve}) [{pattern}] compiled=[{compiled_str}]")

    manifest_path = SAMPLES_DIR / "benchmark_stackof_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    cc = sum(1 for m in manifest if m["compiled"])
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries, {cc} compiled)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(SAMPLE_DEFS)} stack overflow benchmark samples...")
    generate_all(compile=True)
    print("Done.")
