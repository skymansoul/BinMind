"""
编译所有堆溢出测试样本.
遍历每个 cve_* 目录, 运行 make, 收集编译结果.
"""

import os
import subprocess
import sys
import json
import time
from pathlib import Path
from typing import Dict, List


SAMPLE_DIR = Path(__file__).parent
RESULTS_FILE = SAMPLE_DIR / "compile_results.json"


def find_samples(base: Path) -> List[Path]:
    """找到所有包含 Makefile 的样本目录."""
    samples = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "Makefile").exists():
            samples.append(d)
    return samples


def compile_sample(sample_dir: Path) -> Dict:
    """编译单个样本, 返回结果字典."""
    result = {
        "sample": sample_dir.name,
        "success": False,
        "binary": "",
        "error": "",
        "compile_time_ms": 0,
    }

    t0 = time.time()
    try:
        proc = subprocess.run(
            ["make", "clean"],
            cwd=str(sample_dir),
            capture_output=True,
            text=True,
            timeout=15,
        )
        proc = subprocess.run(
            ["make"],
            cwd=str(sample_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        result["compile_time_ms"] = (time.time() - t0) * 1000

        if proc.returncode == 0:
            # 找到生成的 ELF 文件
            for f in sample_dir.iterdir():
                if f.is_file() and f.suffix == "" and os.access(str(f), os.X_OK):
                    result["binary"] = str(f.resolve())
                    result["success"] = True
                    break
            if not result["binary"]:
                # 检查 Makefile 中的 TARGET
                for f in sample_dir.iterdir():
                    if f.is_file() and not f.suffix:
                        result["binary"] = str(f.resolve())
                        result["success"] = True
                        break
        else:
            result["error"] = proc.stderr[:200]
    except subprocess.TimeoutExpired:
        result["error"] = "Compilation timed out"
        result["compile_time_ms"] = (time.time() - t0) * 1000
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def main():
    samples = find_samples(SAMPLE_DIR)
    print(f"Found {len(samples)} samples to compile")

    results = []
    success_count = 0

    for s in samples:
        print(f"  Compiling {s.name}...", end=" ")
        r = compile_sample(s)
        results.append(r)
        if r["success"]:
            success_count += 1
            print("OK")
        else:
            print(f"FAIL: {r['error'][:60]}")

    # 写入结果
    summary = {
        "total": len(samples),
        "success": success_count,
        "failed": len(samples) - success_count,
        "results": results,
    }

    with open(RESULTS_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nCompiled {success_count}/{len(samples)} samples")
    print(f"Results written to {RESULTS_FILE}")
    return 0 if success_count == len(samples) else 1


if __name__ == "__main__":
    sys.exit(main())
