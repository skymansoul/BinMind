# coding: utf-8
# 创建: 2026-06-06  |  UAF 回归套件——扫描调度模块
#
"""
扫描调度模块: 对每样本调度 UAF-PROV 分析与朴素基线 (寄存器/槽键,
无对象身份/无重分配感知), 输出 scan_results.json。

朴素基线代表旧行为: free 的指针槽被标记, 之后任何加载自该槽的
解引用均报 UAF, 不区分新 malloc 复用与其他对象。
"""

import json
import re
import sys
import time
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent
DETECTION_ROOT = Path(__file__).resolve().parents[2] / "detection"
sys.path.insert(0, str(DETECTION_ROOT))

_SLOT = re.compile(r"\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]")
_REG = re.compile(r"\[([a-z0-9]+)\]")
_PTR_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
})


def _slot_key(m) -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}"


def _mem_bases(insn) -> list:
    bases = []
    for op in insn.ops:
        m = _REG.search(op)
        if m and m.group(1) in _PTR_REGS and m.group(1) not in (
                "rbp", "rsp", "rip"):
            bases.append(m.group(1))
    return bases


def _backward_slot(insns, idx, reg) -> str:
    for j in range(idx - 1, max(-1, idx - 10), -1):
        insn = insns[j]
        if insn.mnem != "mov" or len(insn.ops) < 2:
            continue
        dst = insn.op(0)
        if dst.split()[-1] == reg:
            for o in insn.ops[1:]:
                m = _SLOT.search(o)
                if m:
                    return _slot_key(m)
    return ""


def naive_scan(insns) -> list:
    """朴素基线: 寄存器键 UAF, 无对象身份/无重分配/无重赋值感知.

    模拟旧检测行为: free 的参数寄存器被标记, 之后任何同一寄存器的
    解引用均报 UAF——寄存器被新对象/新加载重用即误报。
    """
    findings = []
    freed = {}
    for i, insn in enumerate(insns):
        if insn.is_call:
            op0 = str(insn.op(0))
            if "free" in op0 or "realloc" in op0:
                reg = _free_arg_reg(insns, i)
                if reg:
                    freed[reg] = i
            continue
        for base in _mem_bases(insn):
            if base in freed:
                findings.append((freed[base], i, base, ""))
    return findings


def _free_arg_reg(insns, idx) -> str:
    """free/realloc 的参数寄存器来源: 反向找 mov rcx/rdi, <X> 中的 X."""
    for j in range(idx - 1, max(-1, idx - 8), -1):
        insn = insns[j]
        if insn.mnem != "mov" or len(insn.ops) < 2:
            continue
        dst = insn.op(0).split()[-1]
        if dst in ("rcx", "rdi"):
            src = insn.op(1).split()[-1]
            if src in _PTR_REGS:
                return src
            return ""
    return ""


def scan_one(sample_dir: Path) -> dict:
    from uafprov.pipeline import UafProvenancePipeline

    sid = sample_dir.name
    exe = sample_dir / "vuln.exe"
    asm = sample_dir / "vuln.asm"
    pipe = UafProvenancePipeline()
    t0 = time.perf_counter()
    if exe.exists():
        rep = pipe.analyze_binary(str(exe))
    elif asm.exists():
        rep = pipe.analyze(asm.read_text(encoding="utf-8", errors="replace"),
                           binary_path=str(asm))
    else:
        return {"sample_id": sid, "error": "no binary/asm",
                "detected": False}
    prov_ms = round((time.perf_counter() - t0) * 1000, 1)

    # 朴素基线
    from heapver.insn import parse_disasm
    text = ""
    if exe.exists():
        import subprocess
        text = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                              capture_output=True, text=True,
                              timeout=60).stdout
    elif asm.exists():
        text = asm.read_text(encoding="utf-8", errors="replace")
    naive_findings = []
    for fn in parse_disasm(text):
        naive_findings.extend(naive_scan(fn.insns))

    return {
        "sample_id": sid,
        "detected": rep.detected,
        "n_pairs": rep.n_pairs,
        "n_uaf": rep.n_uaf,
        "n_safe": rep.n_safe,
        "n_suspicious": rep.n_suspicious,
        "n_findings": len(rep.findings),
        "fp_reduction_pct": rep.fp_reduction_pct,
        "per_rule": rep.per_rule,
        "prov_ms": prov_ms,
        "naive_detected": len(naive_findings) > 0,
        "naive_findings": naive_findings,
        "findings": [
            {"func": p.func, "use_idx": p.use_idx, "free_idx": p.free_idx,
             "verdict": p.verdict, "rule": p.rule,
             "free_alloc": p.free_alloc, "use_alloc": p.use_alloc,
             "base_reg": p.base_reg}
            for p in rep.pairs
        ],
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="scan UAF corpus")
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
        print(f"  [{rec['sample_id']:26s}] prov={'DETECT' if rec.get('detected') else 'clean '} "
              f"pairs={rec.get('n_pairs', 0)} uaf={rec.get('n_uaf', 0)} "
              f"safe={rec.get('n_safe', 0)} naive={rec.get('naive_detected')} "
              f"{rec.get('prov_ms', 0)}ms")

    out = SAMPLE_DIR / "scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nsaved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
