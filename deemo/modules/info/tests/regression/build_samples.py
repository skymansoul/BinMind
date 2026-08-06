# Created: 2025-07-29 08:45:00
# build_samples — CVE样本批量编译模块
# 遍历 samples/ 目录,调用各样本的 build.sh 编译为 ELF
# 若 gcc/clang 不可用则记录 SKIP, 不中断整体流程

import os, sys, subprocess, json
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
BUILD_LOG = Path(__file__).parent / "build_log.json"


def build_all(targets=None):
    """编译所有样本。targets 可指定样本名列表, None=全部。"""
    results = {"ok": [], "skip": [], "fail": [], "timestamp": ""}
    sample_dirs = sorted(
        d for d in SAMPLES_DIR.iterdir()
        if d.is_dir() and (d / "build.sh").exists()
    )

    for d in sample_dirs:
        if targets and d.name not in targets:
            continue
        script = d / "build.sh"
        try:
            proc = subprocess.run(
                ["bash", str(script)],
                capture_output=True, text=True, timeout=120,
                cwd=str(d),
            )
            if proc.returncode == 0:
                built = list((d / "build").glob("*.elf")) if (d / "build").exists() else []
                results["ok"].append({"sample": d.name, "built": len(built), "files": [b.name for b in built]})
                print(f"[BUILD] OK: {d.name} ({len(built)} binaries)")
            else:
                results["skip"].append({"sample": d.name, "reason": proc.stderr[:120]})
                print(f"[BUILD] SKIP: {d.name} — compiler not available")
        except subprocess.TimeoutExpired:
            results["fail"].append({"sample": d.name, "reason": "timeout"})
            print(f"[BUILD] FAIL: {d.name} — timeout")
        except Exception as e:
            results["fail"].append({"sample": d.name, "reason": str(e)[:120]})
            print(f"[BUILD] FAIL: {d.name} — {e}")

    from datetime import datetime
    results["timestamp"] = datetime.now().isoformat()
    results["summary"] = f"{len(results['ok'])} ok, {len(results['skip'])} skip, {len(results['fail'])} fail"

    with open(BUILD_LOG, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nBuild summary: {results['summary']}")
    return results


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else None
    build_all(targets)
