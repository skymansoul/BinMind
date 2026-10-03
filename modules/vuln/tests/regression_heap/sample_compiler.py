"""
样本编译模块 — 编译所有堆溢出CVE样本为ELF.

遍历sample_bins/heap_overflow_cve/CVE_XX/目录,
用gcc编译vuln.c为可执行文件, 返回编译状态.

创建: 2024-10-11
"""

import os
import subprocess
from typing import Dict, List

SAMPLE_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "..", "sample_bins", "heap_overflow_cve")

CFLAGS = ["-O0", "-g", "-no-pie", "-fno-stack-protector"]


def find_samples() -> List[str]:
    """扫描sample目录, 返回CVE_XX目录名列表."""
    if not os.path.isdir(SAMPLE_ROOT):
        return []
    names = []
    for entry in sorted(os.listdir(SAMPLE_ROOT)):
        full = os.path.join(SAMPLE_ROOT, entry)
        if os.path.isdir(full) and entry.startswith("CVE_"):
            src = os.path.join(full, "vuln.c")
            if os.path.isfile(src):
                names.append(entry)
    return names


def compile_sample(name: str) -> Dict:
    """编译单个样本, 返回 {name, binary, success, error}."""
    sample_dir = os.path.join(SAMPLE_ROOT, name)
    src = os.path.join(sample_dir, "vuln.c")
    binary = os.path.join(sample_dir, f"vuln_{name}")

    if not os.path.isfile(src):
        return {"name": name, "binary": "", "success": False,
                "error": "vuln.c not found"}

    try:
        result = subprocess.run(
            ["gcc"] + CFLAGS + ["-o", binary, src],
            capture_output=True, timeout=30)
        stderr = result.stderr.decode("utf-8", errors="replace")
        if result.returncode == 0 or os.path.isfile(binary):
            return {"name": name, "binary": binary,
                    "success": True, "error": ""}
        return {"name": name, "binary": "", "success": False,
                "error": stderr[:500]}
    except FileNotFoundError:
        return {"name": name, "binary": "", "success": False,
                "error": "gcc not found"}
    except subprocess.TimeoutExpired:
        return {"name": name, "binary": "", "success": False,
                "error": "compilation timeout"}
    except Exception as e:
        return {"name": name, "binary": "", "success": False,
                "error": str(e)}


def compile_all() -> List[Dict]:
    """编译所有样本, 返回编译结果列表."""
    names = find_samples()
    results = []
    for name in names:
        results.append(compile_sample(name))
    return results


if __name__ == "__main__":
    results = compile_all()
    ok = sum(1 for r in results if r["success"])
    print(f"Compiled {ok}/{len(results)} samples")
    for r in results:
        status = "OK" if r["success"] else "FAIL"
        print(f"  {r['name']}: {status}")

__all__ = ["find_samples", "compile_sample", "compile_all"]
