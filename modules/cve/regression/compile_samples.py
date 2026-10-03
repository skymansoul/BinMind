# 样本编译模块.
#
# 决策逻辑:
#   编译全部样本为 O0 / O2 两档, 产出与 manifest 一一对应的 build 目录.
#   若 upx 可用, 额外生成加壳变体, 供"加壳/未加壳"分组实验.
#   编译失败不中断, 记录到 manifest 的 compiled 字段.
#

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT.parent / "samples"
BUILD = ROOT / "build"
MANIFEST = SAMPLES / "manifest.json"

OPT_LEVELS = ("O0", "O2")


def _compiler() -> str:
    cc = shutil.which("gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    return cc or "gcc"


def _suffix() -> str:
    return ".exe" if os.name == "nt" else ""


def compile_one(sample: dict, opt: str, compiler: str,
                pack: bool = False) -> dict:
    """编译单个样本的一档优化, 返回结果记录."""
    sid = sample["sample_id"]
    src = SAMPLES / sid / "vuln.c"
    out = BUILD / f"{sid}_{opt}{_suffix()}"
    os.makedirs(BUILD, exist_ok=True)
    record = {
        "sample_id": sid, "opt": opt, "binary": str(out.resolve()),
        "compiled": False, "packed": False, "error": "",
    }
    if not src.exists():
        record["error"] = "source missing"
        return record

    cmd = [compiler, f"-{opt}", "-Wall", "-Wno-stringop-overflow",
           str(src), "-o", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not out.exists():
        record["error"] = (r.stderr or r.stdout)[:200]
        return record
    record["compiled"] = True

    if pack:
        upx = shutil.which("upx")
        if upx:
            pout = BUILD / f"{sid}_{opt}_packed{_suffix()}"
            pr = subprocess.run([upx, "-q", str(out), "-o", str(pout)],
                                capture_output=True, text=True, timeout=120)
            if pr.returncode == 0 and pout.exists():
                record["packed"] = True
                record["packed_binary"] = str(pout.resolve())
    return record


def compile_all(pack: bool = False) -> list:
    """编译全部样本, 返回更新后的 manifest 列表."""
    if not MANIFEST.exists():
        print(f"manifest not found: {MANIFEST}. Run gen_samples.py first.")
        return []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    compiler = _compiler()
    print(f"compiler: {compiler}")

    for sample in manifest:
        sid = sample["sample_id"]
        for opt in OPT_LEVELS:
            rec = compile_one(sample, opt, compiler, pack=pack)
            sample[f"compiled_{opt}"] = rec
            status = "OK" if rec["compiled"] else "FAIL"
            extra = " [packed]" if rec.get("packed") else ""
            print(f"  [{status}]{extra} {sid} {opt}"
                  + (f" | {rec['error']}" if rec["error"] else ""))
        sample["compiled"] = any(
            sample.get(f"compiled_{o}", {}).get("compiled")
            for o in OPT_LEVELS)

    manifest_path = BUILD / "manifest_build.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nbuild manifest -> {manifest_path}")
    return manifest


if __name__ == "__main__":
    pack = "--pack" in sys.argv
    compile_all(pack=pack)
