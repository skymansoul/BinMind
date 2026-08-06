# Created: 2025-07-29 13:00:00
# run_regression — 回归测试主入口
# 编排完整流程: 编译 → 扫描 → 解析 → 报告
# 用法: python run_regression.py [--tier 3] [--sample CVE-2014-0160_heartbleed]

import sys, argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    p = argparse.ArgumentParser(description="CAIR regression test runner")
    p.add_argument("--tier", type=int, default=3, help="Max detection tier (1-3)")
    p.add_argument("--sample", type=str, default=None, help="Single sample name to test")
    p.add_argument("--skip-build", action="store_true", help="Skip compilation step")
    args = p.parse_args()

    print(f"=== CAIR Regression Test (Tier {args.tier}) ===\n")

    # Phase 1: Build
    if not args.skip_build:
        print("[Phase 1/3] Building samples...")
        from build_samples import build_all
        targets = [args.sample] if args.sample else None
        build_all(targets)
    else:
        print("[Phase 1/3] Skipping build (--skip-build)")

    # Phase 2: Scan
    print("\n[Phase 2/3] Scanning with CAIR detector...")
    from scan_runner import scan_all_samples
    scan_all_samples(tier=args.tier)

    # Phase 3: Parse results
    print("\n[Phase 3/3] Parsing results...")
    from result_parser import parse_latest, print_report
    stats = parse_latest()
    print_report(stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
