# coding: utf-8
#
"""
GASRI 命令行入口。

用法:
  python -m heapver.cli <binary> [--mode glibc] [--json out.json]
  python -m heapver.cli --asm <disasm.txt>
  python -m heapver.cli --batch <samples_dir> --gt <expected.csv>

输出:
  单文件: 打印每 (alloc, write) 对的判定与证据
  --json: 输出 GASRIReport 的完整 JSON
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from .pipeline import GASRIPipeline, GASRIReport


def _print_report(rep: GASRIReport, verbose: bool = False) -> None:
    print(f"GASRI report: {rep.binary_path}")
    print(f"  functions={rep.n_functions} alloc={rep.n_alloc} "
          f"writes={rep.n_write} pairs={rep.n_pairs}")
    print(f"  verdicts: SAFE={rep.n_safe} OVERFLOW={rep.n_overflow} "
          f"SUSPICIOUS={rep.n_suspicious} unlinked_write={rep.n_unlinked_write}")
    print(f"  FP reduction={rep.fp_reduction_pct}%  "
          f"time={rep.elapsed_ms}ms")
    print(f"  per-rule: {rep.per_rule}")
    if verbose:
        for p in rep.pairs:
            flag = "KEEP" if p.is_finding else "SAFE"
            print(f"  [{flag}] {p.func}: {p.write_func}@0x{p.write_addr:x} "
                  f"vs {p.alloc_func}@0x{p.alloc_addr:x} "
                  f"alloc={p.alloc_region} usable={p.usable} "
                  f"write={p.write_region} rule={p.rule}")
            for e in p.evidence:
                print(f"        {e}")
        for u in rep.unlinked_writes:
            print(f"  [UNLINK] {u['func']}: {u['write']}@{u['addr']:#x} "
                  f"({u['reason']})")


def report_to_dict(rep: GASRIReport) -> dict:
    return {
        "binary_path": rep.binary_path,
        "n_functions": rep.n_functions,
        "n_alloc": rep.n_alloc,
        "n_write": rep.n_write,
        "n_pairs": rep.n_pairs,
        "n_safe": rep.n_safe,
        "n_overflow": rep.n_overflow,
        "n_suspicious": rep.n_suspicious,
        "n_unlinked_write": rep.n_unlinked_write,
        "fp_reduction_pct": rep.fp_reduction_pct,
        "elapsed_ms": rep.elapsed_ms,
        "per_rule": rep.per_rule,
        "findings": [
            {
                "func": p.func, "verdict": p.verdict,
                "write_func": p.write_func, "write_addr": p.write_addr,
                "alloc_func": p.alloc_func, "alloc_addr": p.alloc_addr,
                "alloc_region": p.alloc_region.to_dict(),
                "write_region": p.write_region.to_dict(),
                "usable": p.usable, "rule": p.rule,
                "evidence": p.evidence,
            }
            for p in rep.pairs
        ],
        "unlinked_writes": rep.unlinked_writes,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="GASRI heap overflow verifier")
    ap.add_argument("binary", nargs="?", default=None)
    ap.add_argument("--asm", type=str, default=None, help="disasm text file")
    ap.add_argument("--mode", choices=["glibc", "msvcrt", "none"],
                    default="glibc")
    ap.add_argument("--json", type=str, default=None)
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--batch", type=str, default=None,
                    help="sample dir with expected.csv ground truth")
    args = ap.parse_args(argv)

    pipe = GASRIPipeline(args.mode)

    if args.batch:
        return _run_batch(pipe, args.batch)

    if args.asm:
        text = Path(args.asm).read_text(encoding="utf-8", errors="replace")
        rep = pipe.analyze(text, binary_path=args.asm)
    elif args.binary:
        rep = pipe.analyze_binary(args.binary)
    else:
        ap.print_help()
        return 1

    _print_report(rep, args.verbose)
    if args.json:
        Path(args.json).write_text(
            json.dumps(report_to_dict(rep), indent=2, ensure_ascii=False))
        print(f"JSON saved: {args.json}")
    return 0


def _run_batch(pipe: GASRIPipeline, samples_dir: str) -> int:
    from .bench import run_corpus_benchmark
    rep = run_corpus_benchmark(pipe, samples_dir)
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
