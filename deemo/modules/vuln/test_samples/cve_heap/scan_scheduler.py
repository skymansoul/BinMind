# coding: utf-8
# 创建: 2026-07-06  |  回归套件——扫描调度模块
#
"""
扫描调度模块: 对每个已编译样本调度 GASRI 分析与朴素基线分析,
输出每样本的原始判定记录。

职责:
  - 遍历样本目录, 定位 vuln.exe / vuln.asm
  - 调度 GASRI 管线 (heapver) → gasri 判定
  - 调度朴素基线 (无守卫/无 padding/无 dst 关联) → naive 判定
  - 输出 scan_results.json (供 result_collector 消费)

朴素基线定义 (代表旧检测行为, 用于量化改进):
  - 写入不可证 ≤ 分配 → 一律报溢出 (保守保留 → TN 上出 FP)
  - 分配/写入配对取"最近一次分配", 不做 dst 关联
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

SAMPLE_DIR = Path(__file__).resolve().parent
DETECTION_ROOT = Path(__file__).resolve().parents[2] / "detection"

sys.path.insert(0, str(DETECTION_ROOT))


def naive_pair_verdict(alloc_region, write_region, unbounded: bool) -> str:
    """朴素基线判定: 无可证明安全机制."""
    if unbounded:
        return "OVERFLOW"
    usable = alloc_region.hi if alloc_region.has_upper_bound else 0
    if write_region.has_upper_bound and write_region.hi <= usable:
        return "SAFE"
    return "OVERFLOW"  # 保守保留 → 误报


def run_naive(pipe, text: str, binary: str) -> dict:
    """朴素基线: 复用解析器, 关闭守卫/padding/关联机制."""
    from heapver.pipeline import GASRIPipeline
    from heapver.insn import parse_disasm, callee_name
    from heapver.abi import find_alloc, find_write
    from heapver.defuse import DefUseResolver
    from heapver.region import Region

    # 用独立管线实例, 强制禁用机制
    naive = GASRIPipeline()
    naive._abi = "win64"
    functions = parse_disasm(text)
    resolver = DefUseResolver()
    findings = []
    for fn in functions:
        alloc_sizes = []  # 近邻分配大小 (按出现序)
        for i, insn in enumerate(fn.insns):
            if not insn.is_call:
                continue
            name = callee_name(insn)
            akey = find_alloc(name)
            wkey = find_write(name)
            if akey:
                from heapver.abi import ALLOC_FUNCS
                cands = [r for role, regs in ALLOC_FUNCS[akey]["win64"]
                         if role == "size" for r in regs]
                reg = resolver.resolve(fn.insns, i, cands)
                alloc_sizes.append(reg)
                continue
            if wkey:
                if not alloc_sizes:
                    continue
                si = WRITE_UNBOUNDED.get(wkey)
                wreg = Region.unbounded()
                unbounded = wkey in ("strcpy", "strcat", "gets")
                if not unbounded:
                    wreg = resolver.resolve(fn.insns, i, WRITE_SIZE_REG[wkey])
                areg = alloc_sizes[-1]  # 最近一次分配 (朴素配对)
                v = naive_pair_verdict(areg, wreg, unbounded)
                if v != "SAFE":
                    findings.append({
                        "func": fn.name, "addr": insn.addr,
                        "write": wkey, "verdict": v,
                    })
    return {"findings": findings, "detected": len(findings) > 0}


WRITE_SIZE_REG = {
    "memcpy": ["r8", "r8d"], "memmove": ["r8", "r8d"],
    "memset": ["r8", "r8d"], "strncpy": ["r8", "r8d"],
}
WRITE_UNBOUNDED = {"strcpy": True, "strcat": True, "gets": True}


def scan_one(sample_dir: Path) -> dict:
    from heapver.pipeline import GASRIPipeline

    sid = sample_dir.name
    exe = sample_dir / "vuln.exe"
    asm = sample_dir / "vuln.asm"

    pipe = GASRIPipeline()
    t0 = time.perf_counter()
    if exe.exists():
        rep = pipe.analyze_binary(str(exe))
    elif asm.exists():
        text = asm.read_text(encoding="utf-8", errors="replace")
        rep = pipe.analyze(text, binary_path=str(asm))
    else:
        return {"sample_id": sid, "error": "no binary/asm",
                "detected": False}
    gasri_ms = round((time.perf_counter() - t0) * 1000, 1)

    # 朴素基线
    t0 = time.perf_counter()
    naive_text = ""
    if exe.exists():
        import subprocess
        naive_text = subprocess.run(
            ["objdump", "-d", "-M", "intel", str(exe)],
            capture_output=True, text=True, timeout=60).stdout
    elif asm.exists():
        naive_text = asm.read_text(encoding="utf-8", errors="replace")
    naive = run_naive(pipe, naive_text, sid)
    naive_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "sample_id": sid,
        "detected": rep.detected,
        "n_pairs": rep.n_pairs,
        "n_safe": rep.n_safe,
        "n_overflow": rep.n_overflow,
        "n_suspicious": rep.n_suspicious,
        "n_findings": len(rep.findings),
        "fp_reduction_pct": rep.fp_reduction_pct,
        "per_rule": rep.per_rule,
        "gasri_ms": gasri_ms,
        "naive_detected": naive["detected"],
        "naive_findings": naive["findings"],
        "naive_ms": naive_ms,
        "findings": [
            {"func": p.func, "write_func": p.write_func,
             "addr": p.write_addr, "verdict": p.verdict,
             "rule": p.rule,
             "alloc": p.alloc_region.to_dict(),
             "write": p.write_region.to_dict(),
             "usable": p.usable}
            for p in rep.pairs
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="scan CVE heap corpus")
    ap.add_argument("--samples", nargs="*")
    args = ap.parse_args()

    dirs = sorted(d for d in SAMPLE_DIR.iterdir()
                  if d.is_dir() and (d / "vuln.c").exists())
    if args.samples:
        dirs = [d for d in dirs if d.name in args.samples]

    results = []
    for d in dirs:
        rec = scan_one(d)
        results.append(rec)
        flag = "DETECT" if rec.get("detected") else "clean "
        print(f"  [{rec['sample_id']:28s}] gasri={flag} "
              f"pairs={rec.get('n_pairs', 0)} "
              f"safe={rec.get('n_safe', 0)} "
              f"findings={rec.get('n_findings', 0)} "
              f"naive={rec.get('naive_detected')} "
              f"{rec.get('gasri_ms', 0)}ms")

    out = SAMPLE_DIR / "scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nsaved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
