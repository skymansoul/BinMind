#!/usr/bin/env python3
"""Main launcher — delegates to core.pipeline + core.report.

Kept for backward compatibility: scripts doing `from main import run_pipeline`
continue to work. For interactive CLI use, prefer binmind.py (→ cli.commands).
"""

import argparse, os, sys, time

from utils.logging_setup import init_logging
from config import ensure_dirs, ENABLE_SYMBOLIC, ENABLE_CRYPTO_SCAN


def _quick_parse(argv=None):
    """Legacy argument parser — prefer binmind CLI for interactive use."""
    p = argparse.ArgumentParser(
        prog='binmind',
        description='Binary vulnerability analysis (programmatic entry)',
    )
    p.add_argument('binary', nargs='?', help='path to binary')
    p.add_argument('-o', '--output', default='./results', help='output dir')
    p.add_argument('--crash', help='crash log file')
    p.add_argument('--functions', nargs='*', help='functions to analyze')
    p.add_argument('--max-funcs', type=int, default=20)
    p.add_argument('--include-lib', action='store_true')
    p.add_argument('--parallel', action='store_true')
    p.add_argument('--format', choices=['markdown', 'json'],
                   default='markdown')
    p.add_argument('--decompiler', choices=['auto', 'r2', 'ghidra'],
                   default='auto')
    p.add_argument('--hooks', help='hooks directory')
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--no-crypto', action='store_true')
    p.add_argument('--no-symbolic', action='store_true')
    return p.parse_args(argv)


# entry point

def main(argv=None):
    args = _quick_parse(argv)

    if not args.binary:
        print("usage: python main.py <binary> [options]")
        print("       see binmind CLI for full help: python -m binmind --help")
        return 1

    init_logging('DEBUG' if args.verbose else 'INFO')
    ensure_dirs()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        sys.stderr.write(f"error: not a file: {binary}\n")
        return 1

    t0 = time.time()

    from core.pipeline import run_pipeline

    # respect top-level feature toggles
    if args.no_symbolic:
        import config; config.ENABLE_SYMBOLIC = False
    if args.no_crypto:
        import config; config.ENABLE_CRYPTO_SCAN = False

    result = run_pipeline(
        binary_path=binary,
        crash_path=args.crash,
        functions=args.functions,
        max_funcs=args.max_funcs,
        include_lib=args.include_lib,
        parallel=args.parallel,
        output_format=args.format,
        hooks_dir=args.hooks,
        decompiler=args.decompiler,
    )

    if 'error' in result:
        sys.stderr.write(f"error: {result['error']}\n")
        return 1

    elapsed = result.get('elapsed', time.time() - t0)
    reports = result.get('reports', {})

    print()
    print(f"  done in {elapsed:.1f}s")
    print(f"  functions: {len(result.get('decomp_analysis', []))}")
    print(f"  vulns:     {result.get('total_vulns', 0)}")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
