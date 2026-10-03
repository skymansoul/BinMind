"""自动化样本编译——遍历samples/目录, 调用gcc编译vuln.c, 记录产出。

每个样本目录下必须包含 vuln.c。
编译产物: vuln (ELF可执行文件)。

输出: build_manifest.json — {sample_id: {success, binary_path, compiler_output}}。
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# GCC路径探测——Windows环境可能需要在PATH中
_GCC_CANDIDATES = ["gcc", "x86_64-w64-mingw32-gcc", "/d/mingw64/bin/gcc"]
_GCC_PATH: str = ""
for _gc in _GCC_CANDIDATES:
    if shutil.which(_gc):
        _GCC_PATH = _gc
        break

_SAMPLES_ROOT = Path(__file__).parent / "samples"


def find_samples(root: Path = _SAMPLES_ROOT) -> list[Path]:
    """发现所有含vuln.c的样本目录。"""
    _samples = []
    for _d in sorted(root.iterdir()):
        if _d.is_dir() and (_d / "vuln.c").exists():
            _samples.append(_d)
    return _samples


def build_sample(sample_dir: Path) -> dict:
    """编译单个样本——调用gcc直接编译vuln.c。"""
    _src = sample_dir / "vuln.c"
    _binary = sample_dir / "vuln"

    if not _src.exists():
        return {
            "sample_id": sample_dir.name,
            "success": False, "binary_path": None,
            "error": "vuln.c not found",
        }
    if not _GCC_PATH:
        return {
            "sample_id": sample_dir.name,
            "success": False, "binary_path": None,
            "error": "gcc not found in PATH — install mingw-w64 or gcc",
        }

    try:
        _result = subprocess.run(
            [_GCC_PATH, "-g", "-O0", "-fno-stack-protector",
             "-o", str(_binary), str(_src)],
            cwd=str(sample_dir),
            capture_output=True, text=True, timeout=30,
        )
        # Windows GCC produces .exe; check both
        _binary_exe = sample_dir / "vuln.exe"
        _actual_binary = _binary if _binary.exists() else (
            _binary_exe if _binary_exe.exists() else None
        )
        _success = _result.returncode == 0 and _actual_binary is not None
        return {
            "sample_id": sample_dir.name,
            "success": _success,
            "binary_path": str(_actual_binary) if _actual_binary else None,
            "returncode": _result.returncode,
            "compiler_output": (_result.stdout + _result.stderr)[:500],
            "error": None if _success else f"gcc exit={_result.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {
            "sample_id": sample_dir.name,
            "success": False, "binary_path": None,
            "error": "compilation timeout (30s)",
        }


def build_all(root: Path = _SAMPLES_ROOT, out_json: str = "build_manifest.json") -> str:
    """编译所有样本——写manifest JSON到文件。"""
    _samples = find_samples(root)
    _manifest = {}
    _success = 0

    for _dir in _samples:
        print(f"  building {_dir.name}...", end=" ")
        _result = build_sample(_dir)
        _manifest[_dir.name] = _result
        if _result["success"]:
            print("OK")
            _success += 1
        else:
            print(f"FAIL: {_result.get('error', 'unknown')}")

    _out = Path(out_json)
    _out.write_text(json.dumps(_manifest, indent=2, ensure_ascii=False))
    print(f"\nbuild: {_success}/{len(_samples)} succeeded → {_out}")
    return str(_out)


if __name__ == "__main__":
    build_all()
