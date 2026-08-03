#!/usr/bin/env python3
"""Command-line interface — argparse-based, delegates to core.pipeline."""

import argparse, os, sys, time

from config import ensure_dirs
from utils.logging_setup import init_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='binmind',
        description='Binary vulnerability analysis tool',
    )

    sub = p.add_subparsers(dest='command', help='subcommands')

    # ---- analyze ----
    ap = sub.add_parser('analyze', help='analyze a binary file')
    ap.add_argument('binary', help='path to ELF/PE/Mach-O file')
    ap.add_argument('-o', '--output', default='./results',
                    help='output directory (default: ./results)')
    ap.add_argument('-f', '--format', choices=['markdown', 'json'],
                    default='markdown', help='report format')
    ap.add_argument('--crash', metavar='FILE',
                    help='crash log to analyze alongside the binary')
    ap.add_argument('--functions', nargs='*',
                    help='specific function(s) to analyze')
    ap.add_argument('--max-funcs', type=int, default=20,
                    help='max functions to decompile (default: 20)')
    ap.add_argument('--include-lib', action='store_true',
                    help='include library functions in analysis')
    ap.add_argument('--parallel', action='store_true',
                    help='run function analysis in parallel')
    ap.add_argument('--symbolic', action='store_true',
                    help='enable symbolic execution (requires angr)')
    ap.add_argument('--no-crypto', action='store_true',
                    help='skip cryptographic constant scanning')
    ap.add_argument('--decompiler', choices=['auto', 'r2', 'ghidra'],
                    default='auto', help='decompiler backend')
    ap.add_argument('--hooks', metavar='DIR',
                    help='directory containing hook scripts')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='debug logging')

    # ---- batch ----
    bp = sub.add_parser('batch', help='analyze multiple binaries')
    bp.add_argument('directory', help='directory containing binaries')
    bp.add_argument('-o', '--output', default='./results', help='output dir')
    bp.add_argument('-f', '--format', choices=['markdown', 'json'],
                    default='markdown')

    # ---- version ----
    sub.add_parser('version', help='show version info')

    return p


def cmd_analyze(args):
    from core.pipeline import run_pipeline

    init_logging('DEBUG' if args.verbose else 'INFO')
    ensure_dirs()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print(f"error: not a file: {binary}", file=sys.stderr)
        return 1

    print(f"\n  BinMind — Binary Vulnerability Analysis ")
    print(f"  target : {binary}")
    print(f"  output : {args.output}\n")

    t0 = time.time()
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
        print(f"\n  error: {result['error']}", file=sys.stderr)
        return 1

    elapsed = result.get('elapsed', time.time() - t0)
    reports = result.get('reports', {})

    print()
    print(f"  Analysis complete ({elapsed:.1f}s)")
    print(f"  Functions analyzed : {len(result.get('decomp_analysis', []))}")
    print(f"  Vulnerabilities    : {result.get('total_vulns', 0)}")
    print(f"  Report (md)        : {reports.get('markdown', 'n/a')}")
    print(f"  Report (json)      : {reports.get('json', 'n/a')}")
    print()

    return 0


def cmd_batch(args):
    from core.binary_info import detect_format

    init_logging('INFO')
    ensure_dirs()

    if not os.path.isdir(args.directory):
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 1

    binaries = []
    for fname in sorted(os.listdir(args.directory)):
        fpath = os.path.join(args.directory, fname)
        if os.path.isfile(fpath) and detect_format(fpath) != 'unknown':
            binaries.append(fpath)

    if not binaries:
        print("No supported binaries found in that directory.")
        return 0

    print(f"Found {len(binaries)} binary(ies)\n")
    for i, b in enumerate(binaries, 1):
        print(f"  [{i}/{len(binaries)}] {os.path.basename(b)}")
        try:
            result = cmd_analyze(argparse.Namespace(
                binary=b, output=args.output, format=args.format,
                crash=None, functions=None, max_funcs=20,
                include_lib=False, parallel=False, symbolic=False,
                no_crypto=False, decompiler='auto', hooks=None,
                verbose=False))
        except Exception as e:
            print(f"  failed: {e}", file=sys.stderr)
    return 0


def cmd_version():
    print("binmind v1.4.0 — Binary Vulnerability Analysis Tool")
    print("https://github.com/binmind/binmind")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == 'analyze':
        return cmd_analyze(args)
    elif args.command == 'batch':
        return cmd_batch(args)
    elif args.command == 'version':
        return cmd_version()
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
