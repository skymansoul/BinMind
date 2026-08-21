# 回归测试 - 样本编译模块 (Windows 可用版)
# 替代 scan_runner.py 中不可跨平台的编译逻辑.
# 输入: manifest.json (每项含 src, type, 编译参数)
# 输出: build/{cve}_{type}_{opt}.exe + 更新manifest的binary字段.
#
# 决策: MinGW gcc 输出 PE 二进制, objdump 可解析;
# 与 Linux ELF 仅格式差异, 分析管线 (disasm_util) 已兼容.

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD_DIR = HERE / "build"
SRC_DIR = HERE / "src"
RESULTS_DIR = HERE / "results"


def _find_gcc():
    for cand in ("gcc", "gcc.exe"):
        try:
            r = subprocess.run([cand, "--version"], capture_output=True,
                               timeout=10)
            if r.returncode == 0:
                return cand
        except FileNotFoundError:
            continue
    return None


def compile_sample(entry: dict, gcc: str) -> dict:
    """编译单个样本, 返回更新后的 entry."""
    out = dict(entry)
    cve = entry.get("cve", "unknown")
    vtype = entry.get("type", "unknown")
    opt = entry.get("opt", "O0")

    # 兼容两种 src 定位: 直接路径 或 src 目录
    src_path = Path(entry.get("src", ""))
    if not src_path.exists():
        cand = SRC_DIR / f"{cve}_{vtype}.c"
        if cand.exists():
            src_path = cand
        else:
            out["compiled"] = False
            out["error"] = "source not found"
            return out

    exe_name = f"{cve}_{vtype}_{opt}.exe"
    exe_path = BUILD_DIR / exe_name
    cmd = [gcc, f"-{opt}", "-no-pie", "-fno-pie", "-fno-builtin",
           "-o", str(exe_path), str(src_path)]
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        out["compiled"] = False
        out["error"] = "compile timeout"
        return out
    out["compile_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["compiled"] = (r.returncode == 0 and exe_path.exists())
    out["binary"] = str(exe_path)
    if not out["compiled"]:
        out["error"] = (r.stderr or r.stdout or "")[:200]
    return out


def compile_all(manifest_path: Path) -> list:
    """编译 manifest 中所有未编译样本."""
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    gcc = _find_gcc()
    if not gcc:
        print("ERROR: gcc not found in PATH")
        return []

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for entry in manifest:
        cve = entry.get("cve", "unknown")
        if entry.get("compiled") and Path(entry.get("binary", "")).exists():
            results.append(entry)
            continue
        out = compile_sample(entry, gcc)
        status = "OK" if out["compiled"] else f"FAIL {out.get('error','')}"
        print(f"  {cve} [{entry.get('type')}-{entry.get('opt')}]: {status}")
        results.append(out)

    out_path = BUILD_DIR / "manifest_compiled.json"
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"manifest_compiled.json: {len(results)} entries")
    return results


if __name__ == "__main__":
    manifest = Path(sys.argv[1]) if len(sys.argv) > 1 \
        else BUILD_DIR / "manifest_all.json"
    compile_all(manifest)
