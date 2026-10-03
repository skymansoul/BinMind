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
                   help='enable LLM-assisted vulnerability analysis (default: on)')
    p.add_argument('--no-ai', dest='ai_analysis', action='store_false',
                   help='disable LLM-assisted vulnerability analysis')
    p.set_defaults(ai_analysis=True)
    p.add_argument('--reverse-report', dest='reverse_report', action='store_true',
                   help='generate reverse engineering report (requires prior analysis)')
    p.add_argument('--binary', dest='binary', default=None,
                   help='binary path for --reverse-report')

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
                    default=argparse.SUPPRESS,
                    help='enable LLM-assisted vulnerability analysis (default: on)')
    ap.add_argument('--no-ai', dest='ai_analysis', action='store_false',
                    default=argparse.SUPPRESS,
                    help='disable LLM-assisted vulnerability analysis')

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
    dp.add_argument('--leak', action='append', default=[], metavar='SYM=ADDR',
                    help='libc runtime leak for debug libc; repeatable, e.g. --leak puts=0x7ffff7a5e5f0')

    # feedback — exploit 反馈迭代
    fp = sub.add_parser('feedback', help='run exploit feedback loop (analyze->execute->fix)')
    fp.add_argument('binary', help='path to ELF/PE/Mach-O file')
    fp.add_argument('--script', default='', help='initial exploit script; empty = use generated draft')
    fp.add_argument('--iterations', type=int, default=3, help='max iteration rounds')
    fp.add_argument('--timeout', type=int, default=30, help='per-execution timeout seconds')

    # review — 人工复核闭环
    rp = sub.add_parser('review', help='human review of pending findings')
    rp.add_argument('-o', '--output', default='./results',
                    help='output directory containing review_queue.json')
    rp.add_argument('--list', action='store_true',
                    help='list all pending review records')
    rp.add_argument('--verdict', choices=['confirmed', 'false_positive', 'pending'],
                    help='set human verdict for a record')
    rp.add_argument('--index', type=int, default=-1,
                    help='record index to update (0-based)')

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
        ai_analysis=getattr(args, 'ai_analysis', True),
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

    # 人工复核入队: 有漏洞发现时写入 review_queue.json, 不阻断 analyze 流程
    if result.get('total_vulns', 0) > 0:
        from core.review_gate import add_review_record
        output_dir = args.output
        vuln_list = result.get('all_vulns', [])
        if vuln_list:
            for vuln in vuln_list:
                add_review_record(
                    output_dir,
                    sample_name=os.path.basename(binary),
                    vuln_desc=vuln.get('type', 'unknown'),
                    evidence_addr=vuln.get('address', 'n/a'),
                    current_status='pending',
                )
            print(f"  Review queue  : {len(vuln_list)} record(s) pending")
        else:
            # all_vulns 不可用时创建一条汇总记录
            add_review_record(
                output_dir,
                sample_name=os.path.basename(binary),
                vuln_desc=f'{result.get("total_vulns", 0)} finding(s) pending review',
                evidence_addr=reports.get('markdown', 'n/a'),
                current_status='pending',
            )
            print(f"  Review queue  : 1 summary record pending")
        print(f"  Use 'python main.py review --list' to review")

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
                verbose=False, ai_analysis=True))
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
        from core.libc_identifier import identify_libc, parse_libc_leaks
        try:
            leaks = parse_libc_leaks(getattr(args, 'leak', []))
        except ValueError as exc:
            print(f'error: {exc}', file=sys.stderr)
            return 1
        out = identify_libc(args.binary, leaks=leaks)
    elif args.tool == 'symexec':
        from core.symexec import run_symbolic
        out = run_symbolic(args.binary)
    else:
        print('error: unknown tool', file=sys.stderr)
        return 1
    print(_json.dumps(out, ensure_ascii=False, indent=2, default=str))
    return 0


def _infer_vuln_type_for_feedback(binary):
    """从历史分析结果或文件名推断漏洞类型, 归一化为探测类别。"""
    raw = ''
    # 优先查询历史分析结果
    try:
        from core.vuln_db import search_similar
        findings = search_similar(binary_path=binary, limit=5)
        for f in findings:
            vt = (f.get('vuln_type') or '').lower()
            if vt:
                raw = vt
                break
    except Exception:
        pass
    # 退回文件名推断
    if not raw:
        try:
            from core.sample_manager_types import infer_vuln_type
            raw = (infer_vuln_type(binary) or '').lower()
        except Exception:
            pass
    # 归一化到探测类别
    t = raw
    if 'stack' in t or 'bof' in t or 'buffer' in t or 'rop' in t or 'code-reuse' in t:
        return 'stack-overflow'
    if 'format' in t or 'fmt' in t or 'fsb' in t:
        return 'format-string'
    if 'heap' in t or 'uaf' in t or 'use-after' in t or 'double' in t:
        return 'heap-corruption'
    return ''


def _generate_initial_exploit_script(binary, binfo):
    """根据二进制信息与推断的漏洞类型生成初始探测脚本。

    脚本仅探测崩溃行为, 不伪造偏移或地址, 供反馈环迭代修正。
    """
    from core.exploit_gen import _pwntools_arch

    arch = binfo.get('arch', 'unknown') if binfo else 'unknown'
    bits = binfo.get('bits', 64) if binfo else 64
    fmt = binfo.get('format', 'ELF') if binfo else 'ELF'
    pwntools_arch = _pwntools_arch(arch, bits)
    os_name = {'ELF': 'linux', 'PE': 'windows', 'Mach-O': 'macos'}.get(fmt, 'linux')
    vuln_type = _infer_vuln_type_for_feedback(binary)

    L = [
        '#!/usr/bin/env python3',
        f'# 初始探测脚本 — 推断漏洞类型: {vuln_type or "未知"}',
        f'# 目标: {arch} / {bits}-bit / {fmt}',
        'from pwn import *',
        'import sys',
        '',
        f"context.arch = '{pwntools_arch}'",
        f"context.os = '{os_name}'",
        "context.log_level = 'debug'",
        '',
        f'BINARY = {binary!r}',
        '',
        '',
        'def probe():',
    ]

    # 按漏洞类型选择探测载荷
    if vuln_type == 'stack-overflow':
        L += [
            '    # 栈溢出探测: 递增长度 padding 定位崩溃边界',
            '    for size in (32, 64, 128, 256, 512, 1024, 2048):',
            '        try:',
            '            p = process(BINARY)',
            "            p.sendline(b'A' * size)",
            '            resp = p.recvall(timeout=2)',
            '            print(f"[*] size={size} exit={p.poll()} resp={resp!r}")',
            '            p.close()',
            '        except Exception as e:',
            '            print(f"[!] size={size} exception: {e}")',
        ]
    elif vuln_type == 'format-string':
        L += [
            '    # 格式化字符串探测: 发送格式说明符泄露栈数据',
            "    for payload in (b'%p.' * 8, b'%x.' * 8, b'AAAA%p%p%p%p'):",
            '        try:',
            '            p = process(BINARY)',
            '            p.sendline(payload)',
            '            resp = p.recvall(timeout=2)',
            '            print(f"[*] payload={payload!r} resp={resp!r}")',
            '            p.close()',
            '        except Exception as e:',
            '            print(f"[!] exception: {e}")',
        ]
    elif vuln_type == 'heap-corruption':
        L += [
            '    # 堆破坏探测: 分配-释放-重用序列触发 UAF/double-free',
            '    try:',
            '        p = process(BINARY)',
            '        for _ in range(4):',
            "            p.sendline(b'M' * 64)",
            "        p.sendline(b'')",
            '        for _ in range(4):',
            "            p.sendline(b'U' * 64)",
            '        resp = p.recvall(timeout=2)',
            '        print(f"[*] exit={p.poll()} resp={resp!r}")',
            '        p.close()',
            '    except Exception as e:',
            '        print(f"[!] exception: {e}")',
        ]
    else:
        L += [
            '    # 通用探测: 发送超长输入触发崩溃并打印输出',
            '    try:',
            '        p = process(BINARY)',
            "        p.sendline(b'A' * 1024)",
            '        resp = p.recvall(timeout=2)',
            '        print(f"[*] exit={p.poll()} stdout={resp!r}")',
            '        p.close()',
            '    except Exception as e:',
            '        print(f"[!] exception: {e}")',
        ]

    # 崩溃信息收集: 读取 dmesg 尾部提取寄存器状态
    L += [
        '    # 崩溃信息收集: 读取 dmesg 尾部提取寄存器状态',
        '    try:',
        '        import subprocess',
        "        r = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5)",
        "        tail = r.stdout.strip().splitlines()[-10:]",
        '        if tail:',
        "            print('[*] recent dmesg:')",
        '            for line in tail:',
        "                print(f'    {line}')",
        '    except Exception:',
        '        pass',
        '',
        '',
        "if __name__ == '__main__':",
        '    probe()',
    ]

    return '\n'.join(L)


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
        vuln_type = _infer_vuln_type_for_feedback(binary)
        print(f"info: 未提供 --script, 生成初始探测脚本 (推断类型: {vuln_type or '未知'})")
        initial_script = _generate_initial_exploit_script(binary, binfo)

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


def cmd_review(args):
    """人工复核闭环: 列出待复核记录, 允许人工输入结论并更新。

    复核后结果写入 review_queue.json, 后续报告生成流程可读取该文件
    实现迭代闭环; --list 仅展示, --verdict 配合 --index 更新记录。
    """
    from core.review_gate import read_review_queue, update_review_record

    output_dir = args.output
    queue = read_review_queue(output_dir)

    if not queue:
        print("  (no review records found)")
        return 0

    if args.list or not args.verdict:
        print(f"  Review queue ({len(queue)} records):\n")
        for i, rec in enumerate(queue):
            status_mark = {'pending': '[ ]', 'reviewed': '[x]'}.get(
                rec.get('status', 'pending'), '[?]')
            verdict = rec.get('human_verdict', '') or 'n/a'
            print(f"  {i}: {status_mark} {rec.get('sample_name', '?')}")
            print(f"     vuln     : {rec.get('vuln_desc', 'n/a')}")
            print(f"     evidence : {rec.get('evidence_addr', 'n/a')}")
            print(f"     verdict  : {verdict}")
            print(f"     time     : {rec.get('timestamp', 'n/a')}")
            print()
        if not args.verdict:
            return 0

    if args.verdict:
        if args.index < 0 or args.index >= len(queue):
            print(f"error: invalid index {args.index}, range 0-{len(queue)-1}", file=sys.stderr)
            return 1
        ok = update_review_record(output_dir, args.index, args.verdict)
        if ok:
            rec = queue[args.index]
            print(f"  Updated record {args.index}: {rec.get('sample_name', '?')}")
            print(f"  verdict  : {args.verdict}")
            print(f"  复核结果已写入, 后续报告生成将读取此结论")
        else:
            print(f"error: failed to update record {args.index}", file=sys.stderr)
            return 1

    return 0


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

    # 获取完整二进制信息, 失败时回退到最小结构
    try:
        from core.binary_info import get_binary_info
        report_data.binary_info = get_binary_info(binary_path)
    except Exception:
        report_data.binary_info = {'binary_path': binary_path or 'unknown'}

    # 传递反编译证据与崩溃日志, 供 LLM 研判
    decomp_evidence = []
    crash_log_text = None

    # 尝试从 DB 读取真实漏洞列表
    if binary_path and os.path.isfile(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM findings WHERE binary_path=? ORDER BY id DESC LIMIT 50",
            (binary_path,)).fetchall()
        vulns = [{k: r[k] for k in r.keys()} for r in rows]
        for v in vulns:
            v.setdefault('type', v.get('vuln_type', '?'))
        report_data.vulnerability_list = vulns

        # 从 DB 读取反编译结果作为证据
        try:
            drows = conn.execute(
                "SELECT function_name, pseudocode, address FROM decompilation "
                "WHERE binary_path=? ORDER BY id DESC LIMIT 20",
                (binary_path,)).fetchall()
            decomp_evidence = [{k: r[k] for k in r.keys()} for r in drows]
        except Exception:
            pass
        conn.close()

    # 从结果目录读取崩溃日志原文
    if binary_path:
        stem = os.path.splitext(os.path.basename(binary_path))[0]
        for ext in ('.crash', '.log', '.txt'):
            candidate = os.path.join(RESULTS_DIR, stem + '_crash' + ext)
            if os.path.isfile(candidate):
                try:
                    with open(candidate, 'r', encoding='utf-8', errors='replace') as f:
                        crash_log_text = f.read()
                except Exception:
                    pass
                break

    report_data.decompilation_evidence = decomp_evidence
    report_data.crash_log = crash_log_text

    # simulation 由 LLM 配置状态决定
    from modules.llm_client import is_ai_configured
    simulation = not is_ai_configured()

    gen.set_report_data(report_data, simulation=simulation)
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
    elif args.command == 'review':
        return cmd_review(args)
    elif args.command == 'debug':
        return cmd_debug(args)
    elif args.command == 'version':
        return cmd_version()
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
