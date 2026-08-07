# coding: utf-8
# 创建: 2026-04-18  |  UAF-PROV 命令行入口
#
"""单二进制分析入口.

用法: python -m uafprov.cli <binary> [--json out.json]
"""

import argparse
import json
import sys
from pathlib import Path

from .pipeline import UafProvenancePipeline


def report_to_dict(rep) -> dict:
    return {
        "binary_path": rep.binary_path,
        "n_functions": rep.n_functions,
        "n_frees": rep.n_frees,
        "n_derefs": rep.n_derefs,
        "n_pairs": rep.n_pairs,
        "n_uaf": rep.n_uaf,
        "n_safe": rep.n_safe,
        "n_suspicious": rep.n_suspicious,
        "fp_reduction_pct": rep.fp_reduction_pct,
        "elapsed_ms": rep.elapsed_ms,
        "per_rule": rep.per_rule,
        "pairs": [
            {"func": p.func, "verdict": p.verdict, "rule": p.rule,
             "free_idx": p.free_idx, "use_idx": p.use_idx,
             "free_alloc": p.free_alloc, "use_alloc": p.use_alloc,
             "base_reg": p.base_reg, "evidence": p.evidence}
            for p in rep.pairs
        ],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="UAF-PROV verifier")
    ap.add_argument("binary", nargs="?", default=None)
    ap.add_argument("--asm", type=str, default=None)
    ap.add_argument("--json", type=str, default=None)
    args = ap.parse_args(argv)

    pipe = UafProvenancePipeline()
    if args.asm:
        rep = pipe.analyze(Path(args.asm).read_text(
            encoding="utf-8", errors="replace"), binary_path=args.asm)
    elif args.binary:
        rep = pipe.analyze_binary(args.binary)
    else:
        ap.print_help()
        return 1

    print(f"UAF-PROV report: {rep.binary_path}")
    print(f"  functions={rep.n_functions} frees={rep.n_frees} "
          f"derefs={rep.n_derefs} pairs={rep.n_pairs}")
    print(f"  verdicts: UAF={rep.n_uaf} SAFE={rep.n_safe} "
          f"SUSPICIOUS={rep.n_suspicious} FP_reduction={rep.fp_reduction_pct}%")
    for p in rep.pairs:
        flag = "KEEP" if p.is_finding else "SAFE"
        print(f"  [{flag}] {p.func}: use@{p.use_idx} base={p.base_reg} "
              f"free@{p.free_idx} free_obj={p.free_alloc} "
              f"use_obj={p.use_alloc} rule={p.rule}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(report_to_dict(rep), indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"JSON saved: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
