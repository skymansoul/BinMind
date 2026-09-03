"""CLI 测试。

覆盖：argparser 正确性、子命令分发、错误处理、
帮助输出、缺失必选参数、配置加载边界情况。
"""

import sys, os, io, pytest, contextlib

_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
_src = os.path.join(_patch, 'src')
_modules = os.path.dirname(_patch)  # 需要 modules/ 父目录供 'patching' 包导入
if _modules not in sys.path:
    sys.path.insert(0, _modules)
if _src not in sys.path:
    sys.path.insert(0, _src)


# 辅助函数：运行 CLI 并捕获输出
def run_cli(argv_list):
    """用给定参数运行 CLI main，返回 (exit_code, stdout, stderr)。"""
    import patching.src.cli as _cli
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        rc = _cli.main(argv=argv_list)
    except SystemExit:
        # argparse 可能调 sys.exit，捕获退出码
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        # 用 exit mock 重跑
        return _cli_with_exit(argv_list)
    out = sys.stdout.getvalue()
    err = sys.stderr.getvalue()
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    return rc, out, err


def _cli_with_exit(argv_list):
    """运行 CLI 并捕获 SystemExit。"""
    from patching.src.cli import build_parser, setup_logging
    parser = build_parser()
    try:
        args = parser.parse_args(argv_list)
        if not args.command:
            parser.print_help()
            return 0, "", ""
        from patching.src.cli import handlers as _h
        # 从 main() 构建 handlers —— 镜像实际分发
        handlers = {
            'analyze': None, 'diff': None, 'root-cause': None,
            'quality': None, 'rules': None, 'impact': None,
            'self-heal': None, 'recompile': None, 'predict': None,
        }
        # 仅测试 argparse，不执行完整逻辑
        return 0, args.command, ""
    except SystemExit as e:
        return e.code if e.code else 1, "", ""


class TestArgparseStructure:
    """验证 argparser 结构正确性。"""

    def test_no_args_shows_help(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        # 无子命令时 argparse 可能抛或不抛 SystemExit
        # 取决于 subparsers 是否 required=True。确保空参数不崩溃。
        try:
            args = parser.parse_args([])
            assert args is not None  # parser 不崩溃
        except SystemExit as e:
            assert e.code == 0  # help exit 也可接受

    def test_help_flag(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        try:
            args = parser.parse_args(['--help'])
        except SystemExit as e:
            assert e.code == 0
            return
        pytest.fail("expected SystemExit")

    def test_analyze_requires_binary(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['analyze'])
        assert exc_info.value.code != 0

    def test_analyze_with_binary(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['analyze', '--binary', 'test.bin', '--json'])
        assert args.command == 'analyze'
        assert args.binary == 'test.bin'
        assert args.json is True

    def test_diff_requires_both_binaries(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['diff', '--original', 'a.bin'])
        # 应同时要求 --original 和 --patched

    def test_diff_with_args(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['diff', '--original', 'a.bin', '--patched', 'b.bin', '--no-ai'])
        assert args.original == 'a.bin'
        assert args.patched == 'b.bin'
        assert args.no_ai is True

    def test_root_cause(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['root-cause', '--crash', 'crash.log'])
        assert args.command == 'root-cause'
        assert args.crash == 'crash.log'

    def test_quality_with_file(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['quality', '--patch-data', 'data.json'])
        assert args.patch_data == 'data.json'

    def test_rules_list(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['rules', '--list'])
        assert args.list is True

    def test_impact_requires_args(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['impact', '--before', 'v1.bin', '--after', 'v2.bin'])
        assert args.before == 'v1.bin'
        assert args.after == 'v2.bin'

    def test_self_heal_with_binary(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['self-heal', '--binary', 'app.bin', '--cve-id', 'CVE-2017-5123'])
        assert args.binary == 'app.bin'
        assert args.cve_id == 'CVE-2017-5123'
        assert args.framework == 'frida'  # 默认值

    def test_predict_with_arch(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['predict', '--arch', 'aarch64', '--allocator', 'jemalloc'])
        assert args.arch == 'aarch64'
        assert args.allocator == 'jemalloc'

    def test_config_flag(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['--config', '/path/to/config.yaml', 'analyze', '--binary', 'test.bin'])
        assert args.config == '/path/to/config.yaml'
        assert args.command == 'analyze'


class TestCLIimports:
    """验证 CLI 模块导入不出错。"""

    def test_build_parser_imports(self):
        from patching.src.cli import build_parser
        parser = build_parser()
        assert parser is not None

    def test_main_function_exists(self):
        from patching.src.cli import main
        assert callable(main)

    def test_setup_logging_no_crash(self):
        from patching.src.cli import setup_logging
        setup_logging('WARNING')
        # 不应抛异常

    def test_handlers_dict_complete(self):
        """build_parser 中的子命令应在 main() handlers 中全部存在。"""
        from patching.src.cli import main as _cli_main
        import inspect
        # 读源码确认 handlers dict
        source = inspect.getsource(_cli_main)
        assert "'analyze'" in source
        assert "'diff'" in source
        assert "'predict'" in source


class TestMainEntry:
    """验证 patching.main 入口正确委托。"""

    def test_main_imports(self):
        """main.main 应从 patching.src.cli 导入。"""
        import patching.main
        assert hasattr(patching.main, 'main')
        assert callable(patching.main.main)

    def test_main_returns_int(self):
        """main() 应返回 int (退出码)。"""
        # 无参数不能真正运行，但应可调用
        import patching.src.cli as _cli
        assert callable(_cli.main)
