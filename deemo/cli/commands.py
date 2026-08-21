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

    # 顶级开关 — 不需要子命令
    p.add_argument('--test', action='store_true',
                   help='run test suite (equivalent to python -m tests.run_tests --all)')
    p.add_argument('--ai-analysis', dest='ai_analysis', action='store_true',
                   help='enable LLM-assisted vulnerability analysis')
    p.add_argument('--reverse-report', dest='reverse_report', action='store_true',
                   help='generate reverse engineering report (requires prior analysis)')

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
    ap.add_argument('--ai-analysis', dest='ai_analysis', action='store_true',
                    help='enable LLM-assisted vulnerability analysis')

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
    rp = sub.add_parser('replay', help='replay recorded analysis from DB')
    rp.add_argument('run_id', type=int, help='analysis run id to replay')

    # debug
    dp = sub.add_parser('debug', help='manual entry for internal capabilities')
    dp.add_argument('tool', choices=['checksec', 'plt', 'strings', 'gadgets', 'libc', 'symexec'])
    dp.add_argument('binary', help='target binary')

    # feedback — exploit 反馈迭代
    fp = sub.add_parser('feedback', help='run exploit feedback loop (analyze->execute->fix)')
    fp.add_argument('binary', help='path to ELF/PE/Mach-O file')
    fp.add_argument('--script', default='', help='initial exploit script; empty = use generated draft')
    fp.add_argument('--iterations', type=int, default=3, help='max iteration rounds')
    fp.add_argument('--timeout', type=int, default=30, help='per-execution timeout seconds')

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
        no_crypto=args.no_crypto,
        output_dir=args.output,
        ai_analysis=getattr(args, 'ai_analysis', False),
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
                verbose=False, ai_analysis=False))
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
    """重放已记录分析: 从 DB 载入 run 与 findings, 重建报告到 reports 目录。

    findings 经 run_ts(analysis_runs.started_at)+binary_path 关联到运行记录;
    该运行无记录时如实报错, 不模拟成功。
    """
    import sqlite3
    from config import DB_PATH, RESULTS_DIR
    if not os.path.isfile(DB_PATH):
        print("error: 数据库不存在，尚无分析记录", file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    run = conn.execute(
        "SELECT * FROM analysis_runs WHERE id=?", (args.run_id,)).fetchone()
    if run is None:
        conn.close()
        print(f"error: 运行记录 {args.run_id} 不存在", file=sys.stderr)
        return 1
    rows = conn.execute(
        "SELECT * FROM findings WHERE run_ts=? AND binary_path=?",
        (run['started_at'], run['binary_path'])).fetchall()
    conn.close()

    print(f"  Replaying run {run['id']} [{run['status']}]")
    print(f"  binary : {run['binary_path']}")
    print(f"  summary: {run['summary'] or ''}")
    print(f"  findings: {len(rows)}")

    if not rows:
        print("  (无 findings)")
        return 0

    findings = [{k: r[k] for k in r.keys()} for r in rows]
    # 报告生成器读取 type 字段, findings 行使用 vuln_type 列名
    for f in findings:
        f.setdefault('type', f.get('vuln_type', '?'))

    from core.report import generate_markdown
    try:
        from core.binary_info import get_binary_info
        binfo = get_binary_info(run['binary_path'])
    except Exception:
        binfo = {'path': run['binary_path'],
                 'filename': os.path.basename(run['binary_path'])}

    md = generate_markdown(findings, binfo, None)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stem = os.path.splitext(os.path.basename(run['binary_path']))[0]
    out = os.path.join(RESULTS_DIR, f'{stem}_replay_{run["id"]}.md')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"  replay report : {out}")
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


def cmd_feedback(args):
    """运行 exploit 反馈迭代: 分析 -> 生成/装载初始脚本 -> 执行 -> LLM 修正重试。

    初始脚本来源: --script 指定, 或对 --crash 提供的崩溃数据自动生成草稿。
    反馈环内部以实际执行结果驱动, 连续相同错误提前终止。
    """
    from core.feedback_loop import run_feedback_loop
    from core.binary_info import get_binary_info

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print(f"error: not a file: {binary}", file=sys.stderr)
        return 1

    initial_script = args.script
    binfo = None
    try:
        binfo = get_binary_info(binary)
    except Exception as e:
        print(f"warn: 读取二进制信息失败, 反馈环继续: {e}", file=sys.stderr)

    if not initial_script:
        # 无初始脚本时用崩溃路径生成草稿(若提供), 否则说明需要手动指定
        print("info: 未提供 --script, 反馈环将以空载荷开始(实际执行即可见失败反馈)")
        initial_script = "#!/usr/bin/env python3\nfrom pwn import *\n"

    print(f"\n  Feedback loop — {binary}")
    print(f"  iterations : {args.iterations} (max), timeout={args.timeout}s")

    result = run_feedback_loop(
        binary, initial_script, binfo=binfo,
        max_iterations=args.iterations, timeout=args.timeout,
    )
    print(f"\n  success     : {result['success']}")
    print(f"  iterations  : {result['iterations']}")
    print(f"  root cause  : {result['root_cause'] or 'n/a'}")
    return 0 if result['success'] else 1


def cmd_version():
    print("binmind v1.4.0 — Binary Vulnerability Analysis Tool")
    print("https://github.com/binmind/binmind")
    return 0


def cmd_test():
    """运行测试套件——清理 sys.argv 避免 argparse 参数透传"""
    import sys as _sys
    _orig_argv = _sys.argv[:]
    _sys.argv = ['run_tests', '--all']
    try:
        from tests.run_tests import main as _test_main
        return _test_main()
    except ImportError:
        print("error: tests.run_tests 模块未找到", file=_sys.stderr)
        return 1
    except SystemExit as e:
        return e.code if e.code is not None else 0
    finally:
        _sys.argv = _orig_argv


def cmd_reverse_report(args):
    """生成逆向工程报告——先 set_report_data() 再 save_report()"""
    import json as _json
    from modules.analysis_tools.reverse_report import (
        ReportConfig, ReportData, ReverseReportGenerator
    )

    cfg = ReportConfig(language='zh', output_dir='./reports')
    gen = ReverseReportGenerator(cfg)

    # 从最近分析结果中读取数据
    import sqlite3
    from config import DB_PATH, RESULTS_DIR
    binary_path = getattr(args, 'binary', None) or ''

    report_data = ReportData()
    report_data.binary_info = {'binary_path': binary_path or 'unknown'}

    # 尝试从 DB 读取真实漏洞列表
    if binary_path and os.path.isfile(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM findings WHERE binary_path=? ORDER BY id DESC LIMIT 50",
            (binary_path,)).fetchall()
        conn.close()
        vulns = [{k: r[k] for k in r.keys()} for r in rows]
        for v in vulns:
            v.setdefault('type', v.get('vuln_type', '?'))
        report_data.vulnerability_list = vulns

    gen.set_report_data(report_data)
    output = gen.save_report()

    if output:
        print(f"  Reverse report saved: {output}")
        # simulation 标记
        from modules.llm_client import is_ai_configured
        if not is_ai_configured():
            print("  [simulation=true] 报告为模板生成，未经 LLM 研判")
        else:
            print("  [LLM 分析完成]")
        return 0
    else:
        print("  error: 报告生成失败", file=sys.stderr)
        return 1

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # 顶级 --test
    if getattr(args, 'test', False):
        return cmd_test()

    # 顶级 --reverse-report
    if getattr(args, 'reverse_report', False):
        return cmd_reverse_report(args)

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
    elif args.command == 'feedback':
        return cmd_feedback(args)
    elif args.command == 'debug':
        return cmd_debug(args)
    elif args.command == 'version':
        return cmd_version()
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
