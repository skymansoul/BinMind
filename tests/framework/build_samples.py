"""
CVE 样本编译模块 — 批量编译 CVE 演示源码为 ELF 二进制。

每个样本位于独立子目录，包含 vuln.c 和可选的 Makefile。
编译使用 gcc 并强制关闭栈保护以便漏洞演示。
跨平台: Linux (gcc) / macOS (clang) / Windows (MinGW 交叉编译跳过 ELF 目标)。
"""

import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List


SAMPLES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVE_DIR = os.path.join(SAMPLES_DIR, "cve_samples")
BUILD_OUT = os.path.join(SAMPLES_DIR, "cve_binaries")


@dataclass
class BuildResult:
    sample_name: str
    success: bool
    binary_path: str
    error: str = ""
    compiler: str = "gcc"


def detect_compiler() -> str:
    for cc in ("gcc", "clang", "cc"):
        try:
            subprocess.run([cc, "--version"], capture_output=True, timeout=5)
            return cc
        except Exception:
            continue
    return ""


def build_all(compiler: str = "") -> List[BuildResult]:
    """编译所有 CVE 样本。返回 BuildResult 列表。"""
    cc = compiler or detect_compiler()
    if not cc:
        return [BuildResult("all", False, "", "No C compiler found")]

    os.makedirs(BUILD_OUT, exist_ok=True)
    results: List[BuildResult] = []

    for sample_dir in sorted(os.listdir(CVE_DIR)):
        sample_path = os.path.join(CVE_DIR, sample_dir)
        if not os.path.isdir(sample_path):
            continue

        vuln_c = os.path.join(sample_path, "vuln.c")
        if not os.path.isfile(vuln_c):
            continue

        binary_name = f"{sample_dir}.elf"
        binary_path = os.path.join(BUILD_OUT, binary_name)

        cmd = [
            cc, vuln_c, "-o", binary_path,
            "-fno-stack-protector", "-z", "execstack",
            "-no-pie", "-g", "-O0",
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and os.path.isfile(binary_path):
                results.append(BuildResult(
                    sample_name=sample_dir, success=True,
                    binary_path=binary_path, compiler=cc,
                ))
            else:
                results.append(BuildResult(
                    sample_name=sample_dir, success=False,
                    binary_path="", error=proc.stderr[:200], compiler=cc,
                ))
        except subprocess.TimeoutExpired:
            results.append(BuildResult(
                sample_name=sample_dir, success=False,
                binary_path="", error="Compilation timeout", compiler=cc,
            ))
        except Exception as e:
            results.append(BuildResult(
                sample_name=sample_dir, success=False,
                binary_path="", error=str(e), compiler=cc,
            ))

    return results


if __name__ == "__main__":
    cc = detect_compiler()
    if not cc:
        print("ERROR: No C compiler found. Install gcc or clang.")
        sys.exit(1)
    print(f"Compiler: {cc}")
    results = build_all(cc)
    ok = sum(1 for r in results if r.success)
    print(f"Built: {ok}/{len(results)} samples")
    for r in results:
        status = "OK" if r.success else f"FAIL ({r.error[:60]})"
        print(f"  {r.sample_name}: {status}")
