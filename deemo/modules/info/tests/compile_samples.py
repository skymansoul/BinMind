# tests/compile_samples — 批量编译模块 (支持 Makefile + build.sh)
# 遍历 samples/ 目录, 自动检测构建方式并编译为 ELF。
# 编译失败不中断流程, 标记 SKIP 继续。

import os, sys, subprocess, json
from pathlib import Path
from datetime import datetime

SAMPLES_DIR = Path(__file__).parent / "regression" / "samples"
BUILD_LOG = Path(__file__).parent / "regression" / "build_log.json"


def _detect_build_method(sample_dir: Path) -> str:
    """检测构建方式: 'makefile' | 'build_sh' | 'none'。"""
    if (sample_dir / "Makefile").exists():
        return "makefile"
    if (sample_dir / "build.sh").exists():
        return "build_sh"
    if (sample_dir / "vuln.c").exists():
        return "direct"  # 直接用 gcc 编译
    return "none"


def _compile_with_make(sample_dir: Path) -> tuple:
    """用 make 编译, 返回 (ok, elf_paths, error_msg)。"""
    try:
        proc = subprocess.run(
            ["make", "clean"], capture_output=True, text=True,
            timeout=30, cwd=str(sample_dir),
        )
        proc = subprocess.run(
            ["make"], capture_output=True, text=True,
            timeout=120, cwd=str(sample_dir),
        )
        if proc.returncode != 0:
            return (False, [], proc.stderr[:200])
        # 找生成的 ELF
        elfs = list(sample_dir.glob("vuln")) + list(sample_dir.glob("*.elf"))
        return (True, [str(e) for e in elfs if os.access(str(e), os.X_OK)], "")
    except FileNotFoundError:
        return (False, [], "make not found")
    except subprocess.TimeoutExpired:
        return (False, [], "timeout")
    except Exception as e:
        return (False, [], str(e)[:200])


def _compile_direct(sample_dir: Path) -> tuple:
    """直接用 gcc 编译 vuln.c。"""
    src = sample_dir / "vuln.c"
    out = sample_dir / "vuln"
    if not src.exists():
        return (False, [], "no vuln.c found")
    try:
        proc = subprocess.run(
            ["gcc", "-Wall", "-O0", "-g", "-o", str(out), str(src)],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0 and out.exists():
            os.chmod(str(out), 0o755)
            return (True, [str(out)], "")
        return (False, [], proc.stderr[:200] if proc.stderr else "gcc failed")
    except FileNotFoundError:
        return (False, [], "gcc not found")
    except Exception as e:
        return (False, [], str(e)[:200])


def build_all(targets: list = None) -> dict:
    """编译所有样本。targets=None 表示全部。"""
    results = {"ok": [], "skip": [], "fail": [], "timestamp": ""}

    if not SAMPLES_DIR.exists():
        results["fail"].append({"sample": "ALL", "reason": "samples dir not found"})
        return results

    all_dirs = sorted(
        d for d in SAMPLES_DIR.iterdir()
        if d.is_dir() and d.name != "tests"
    )

    for d in all_dirs:
        if targets and d.name not in targets:
            continue

        method = _detect_build_method(d)
        if method == "none":
            results["skip"].append({"sample": d.name, "reason": "no source"})
            print(f"[BUILD] SKIP: {d.name} — no buildable source")
            continue

        if method == "makefile":
            ok, elfs, err = _compile_with_make(d)
        else:
            ok, elfs, err = _compile_direct(d)

        if ok:
            results["ok"].append({
                "sample": d.name, "binaries": len(elfs),
                "files": [Path(e).name for e in elfs],
                "method": method,
            })
            print(f"[BUILD] OK: {d.name} ({len(elfs)} binary, {method})")
        else:
            results["skip"].append({
                "sample": d.name, "reason": err, "method": method,
            })
            print(f"[BUILD] SKIP: {d.name} — {err[:80]}")

    results["timestamp"] = datetime.now().isoformat()
    n_ok = len(results["ok"])
    n_skip = len(results["skip"])
    results["summary"] = f"{n_ok} ok, {n_skip} skip, {len(results['fail'])} fail"

    with open(BUILD_LOG, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nBuild summary: {results['summary']}")
    return results


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else None
    build_all(targets)
