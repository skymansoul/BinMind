# 自动编译所有CVE样本 — 支持 gcc/clang 多编译器矩阵

import os, sys, subprocess, glob, json, time
from dataclasses import dataclass, field
from typing import List

@dataclass
class BuildResult:
    sample: str; compiler: str; opt: str
    success: bool; binary_path: str = ""; error: str = ""

COMPILERS = [("gcc", ["gcc", "-O0", "-g", "-w"]),
             ("gcc", ["gcc", "-O2", "-g", "-w"]),
             ("clang", ["clang", "-O0", "-g", "-w"])]

def compile_all(samples_dir: str, output_dir: str) -> List[BuildResult]:
    os.makedirs(output_dir, exist_ok=True)
    results = []

    for sample_name in sorted(os.listdir(samples_dir)):
        sample_path = os.path.join(samples_dir, sample_name)
        if not os.path.isdir(sample_path): continue
        srcs = glob.glob(os.path.join(sample_path, "*.c"))
        if not srcs: continue

        for compiler_name, base_cmd in COMPILERS:
            out_name = f"{sample_name}_{compiler_name}_O{base_cmd[1][1]}"
            out_path = os.path.join(output_dir, out_name)
            cmd = base_cmd + srcs + ["-o", out_path]

            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=30)
                results.append(BuildResult(sample_name, compiler_name,
                               base_cmd[1][1], True, out_path))
            except subprocess.CalledProcessError as e:
                results.append(BuildResult(sample_name, compiler_name,
                               base_cmd[1][1], False, error=str(e.stderr)[:200]))
            except subprocess.TimeoutExpired:
                results.append(BuildResult(sample_name, compiler_name,
                               base_cmd[1][1], False, error="timeout"))
    return results

if __name__ == "__main__":
    samples = os.path.join(os.path.dirname(__file__), "regression", "samples")
    binaries = os.path.join(os.path.dirname(__file__), "regression", "binaries")
    results = compile_all(samples, binaries)
    ok = sum(1 for r in results if r.success)
    fail = len(results) - ok
    print(f"Compiled {ok}/{len(results)} samples ({fail} failed)")
    for r in results:
        status = "OK" if r.success else f"FAIL: {r.error[:60]}"
        print(f"  [{r.compiler} {r.opt}] {r.sample}: {status}")
    with open(os.path.join(binaries, "build_results.json"), "w") as f:
        json.dump([vars(r) for r in results], f, indent=2, default=str)
