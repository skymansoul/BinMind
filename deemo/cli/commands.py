#!/usr/bin/env python3
# cli/commands.py - 命令行入口 (argparse 分发到 core.pipeline 与各子命令)

import argparse, os, sys, time

from config import ensure_dirs
from utils.logging_setup import init_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='binmind',
        description='Binary vulnerability analysis tool',
    )

    sub = p.add_subparsers(dest='command', help='subcommands')

    # analyze
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
    ap.add_argument('--fuzz', action='store_true',
                    help='generate libFuzzer harness workspace for the target')
    ap.add_argument('--no-crypto', action='store_true',
                    help='skip cryptographic constant scanning')
    ap.add_argument('--decompiler', choices=['auto', 'r2', 'ghidra'],
                    default='auto', help='decompiler backend')
    ap.add_argument('--hooks', metavar='DIR',
                    help='directory containing hook scripts')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='debug logging')

    # batch
    bp = sub.add_parser('batch', help='analyze multiple binaries')
    bp.add_argument('directory', help='directory containing binaries')
    bp.add_argument('-o', '--output', default='./results', help='output dir')
    bp.add_argument('-f', '--format', choices=['markdown', 'json'],
                    default='markdown')

    # serve
    svp = sub.add_parser('serve', help='start the Web API service')
    svp.add_argument('--host', default='127.0.0.1',
                     help='listen address (default: 127.0.0.1)')
    svp.add_argument('--port', type=int, default=8000,
                     help='listen port (default: 8000)')
    svp.add_argument('--reload', action='store_true',
                     help='enable uvicorn auto-reload (dev only)')

    # fuzz
    fp = sub.add_parser('fuzz', help='fuzzing tools (delegates to binmind-fuzzing)')
    fp.add_argument('args', nargs=argparse.REMAINDER,
                    help='arguments forwarded to the fuzzing CLI')

    # version
    sub.add_parser('version', help='show version info')

    # export
    ep = sub.add_parser('export', help='export analysis reports')
    ep.add_argument('binary', help='binary whose reports to export')
    ep.add_argument('-o', '--output', default='./exported_reports',
                    help='target directory for exported reports')

    # status
    sub.add_parser('status', help='show analysis run status from DB')

    # replay
    rp = sub.add_parser('replay', help='replay recorded analysis (placeholder)')
    rp.add_argument('run_id', type=int, help='analysis run id to replay')

    # debug
    dp = sub.add_parser('debug', help='manual entry for internal capabilities')
    dp.add_argument('tool', choices=['checksec', 'plt', 'strings', 'gadgets', 'libc', 'symexec'])
    dp.add_argument('binary', help='target binary')

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
        symbolic=args.symbolic,
        fuzz=args.fuzz,
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
                fuzz=False, no_crypto=False, decompiler='auto', hooks=None,
                verbose=False))
        except Exception as e:
            print(f"  failed: {e}", file=sys.stderr)
    return 0


def cmd_serve(args):
    try:
        from modules.output.web_api import start_server
    except ImportError:
        print("error: FastAPI/uvicorn 未安装，无法启动 Web 服务", file=sys.stderr)
        return 1
    start_server(host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_fuzz(args):
    from modules.fuzzing.src.cli import main as fuzz_main
    return fuzz_main(args.args)


def cmd_export(args):
    # 子命令 export：复制已有 md/json 报告产物到目标目录。
    import shutil
    from config import RESULTS_DIR
    binary_stem = os.path.splitext(os.path.basename(os.path.abspath(args.binary)))[0]
    if not os.path.isdir(RESULTS_DIR):
        print("error: 报告目录不存在", file=sys.stderr)
        return 1
    matches = sorted(
        f for f in os.listdir(RESULTS_DIR)
        if f.startswith(binary_stem) and f.endswith(('.md', '.json')))
    if not matches:
        print(f"error: 未找到 {binary_stem} 的报告", file=sys.stderr)
        return 1
    os.makedirs(args.output, exist_ok=True)
    for f in matches:
        shutil.copy2(os.path.join(RESULTS_DIR, f), args.output)
    print(f"exported {len(matches)} report(s) to {args.output}")
    return 0


def cmd_status(args):
    # 子命令 status：汇总 analysis_runs 与 findings 计数。
    import sqlite3
    from config import DB_PATH
    if not os.path.isfile(DB_PATH):
        print("error: 数据库不存在，尚无分析记录", file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    runs = conn.execute(
        "SELECT id, started_at, status, binary_path, summary FROM analysis_runs "
        "ORDER BY id DESC LIMIT 10").fetchall()
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()
    print(f"findings total: {total}")
    for r in runs:
        print(f"  run {r['id']} [{r['status']}] "
              f"{os.path.basename(r['binary_path'])} — {r['summary'] or ''}")
    return 0


def cmd_replay(args):
    # 子命令 replay：重放分析结果，实现未就绪。
    print(f"Not implemented yet (run_id={args.run_id})")
    return 0


def cmd_debug(args):
    # 子命令 debug：转发至 core 内部能力函数, JSON 输出。
    import json as _json
    if args.tool == 'checksec':
        from core.checksec_api import detect_checksec
        out = detect_checksec(args.binary)
    elif args.tool == 'plt':
        from core.plt_scanner import scan_plt
        out = scan_plt(args.binary)
    elif args.tool == 'strings':
        from core.static_analysis import scan_strings
        out = scan_strings(args.binary)
    elif args.tool == 'gadgets':
        from modules.core.compat.gadget_scan import headless_scan_gadgets
        out = headless_scan_gadgets([args.binary])
    elif args.tool == 'libc':
        from core.libc_identifier import identify_libc
        out = identify_libc(args.binary)
    elif args.tool == 'symexec':
        from core.symexec import run_symbolic
        out = run_symbolic(args.binary)
    else:
        print('error: unknown tool', file=sys.stderr)
        return 1
    print(_json.dumps(out, ensure_ascii=False, indent=2, default=str))
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
    elif args.command == 'serve':
        return cmd_serve(args)
    elif args.command == 'fuzz':
        return cmd_fuzz(args)
    elif args.command == 'export':
        return cmd_export(args)
    elif args.command == 'status':
        return cmd_status(args)
    elif args.command == 'replay':
        return cmd_replay(args)
    elif args.command == 'debug':
        return cmd_debug(args)
    elif args.command == 'version':
        return cmd_version()
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
