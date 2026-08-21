# coding: utf-8
#
"""
扫描调度: 每样本调度 FMTPROV 与朴素基线 (仅看 call 前 5 条是否
lea/mov offset——即旧 format_string_detector 行为), 输出 JSON。
"""

import json
import sys
import time
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent
DETECTION_ROOT = Path(__file__).resolve().parents[2] / "detection"
sys.path.insert(0, str(DETECTION_ROOT))

# 旧检测的"常量格式串"识别: call 前 5 条内出现 lea rip / mov offset
_CONST_HINTS = ("lea", "offset", "LC", ".l", "[rip", "rip+", "rip-")


def naive_is_const(insns, call_idx) -> bool:
    for j in range(max(0, call_idx - 5), call_idx):
        raw = insns[j].raw.lower()
        if any(h in raw for h in _CONST_HINTS):
            return True
    return False


def naive_scan(insns) -> list:
    """朴素基线: fmt 参数非常量字面量 → 一律报 VULN (旧行为)."""
    from fmtprov.fmt_abi import find_format
    from heapver.insn import callee_name
    findings = []
    for i, insn in enumerate(insns):
        if not insn.is_call:
            continue
        _, sig = find_format(callee_name(insn))
        if sig is None:
            continue
        if not naive_is_const(insns, i):
            findings.append(i)
    return findings


def scan_one(sample_dir: Path) -> dict:
    from fmtprov.pipeline import FmtProvenancePipeline
    from heapver.insn import parse_disasm

    sid = sample_dir.name
    exe = sample_dir / "vuln.exe"
    asm = sample_dir / "vuln.asm"
    pipe = FmtProvenancePipeline()
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

    text = ""
    if exe.exists():
        import subprocess
        text = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                              capture_output=True, text=True,
                              timeout=60).stdout
    elif asm.exists():
        text = asm.read_text(encoding="utf-8", errors="replace")
    naive = []
    for fn in parse_disasm(text):
        naive.extend(naive_scan(fn.insns))

    return {
        "sample_id": sid,
        "detected": rep.detected,
        "n_calls": rep.n_calls,
        "n_safe": rep.n_safe,
        "n_vuln": rep.n_vuln,
        "n_suspicious": rep.n_suspicious,
        "n_findings": len([f for f in rep.findings if f.is_finding]),
        "fp_reduction_pct": rep.fp_reduction_pct,
        "per_class": rep.per_class,
        "prov_ms": prov_ms,
        "naive_detected": len(naive) > 0,
        "naive_findings": naive,
        "findings": [
            {"func": f.func, "addr": f.addr, "fmt_func": f.fmt_func,
             "verdict": f.verdict, "rule": f.rule,
             "classification": f.classification}
            for f in rep.findings
        ],
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="scan fmt corpus")
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
        print(f"  [{rec['sample_id']:24s}] prov={'DETECT' if rec.get('detected') else 'clean '} "
              f"calls={rec.get('n_calls',0)} safe={rec.get('n_safe',0)} "
              f"vuln={rec.get('n_vuln',0)} naive={rec.get('naive_detected')} "
              f"{rec.get('prov_ms',0)}ms")

    out = SAMPLE_DIR / "scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nsaved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
