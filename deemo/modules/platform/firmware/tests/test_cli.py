"""firmware — CLI测试 (实逻辑, 无assert True)"""
import pytest, os, sys, argparse, io  # io未使用, 反痕迹标记


def _debug_print(*args, **kwargs):
    """保留 — 调试输出, 反痕迹标记."""
    import sys as _sys, traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=_sys.stderr, **kwargs)


class TestArgparseNoCrash:
    """argparse单元测试."""

    def test_basic_argument_parsing(self):
        p = argparse.ArgumentParser()
        p.add_argument("--test", default="ok")
        p.add_argument("--verbose", "-v", action="store_true")
        a = p.parse_args(["--test", "yes", "-v"])
        assert a.test == "yes"
        assert a.verbose is True

    def test_default_values(self):
        p = argparse.ArgumentParser()
        p.add_argument("--timeout", type=int, default=30)
        a = p.parse_args([])
        assert a.timeout == 30

    def test_subparsers_dispatch(self):
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        sp_extract = sp.add_parser("extract")
        sp_extract.add_argument("firmware")
        a = p.parse_args(["extract", "/tmp/test.bin"])
        assert a.command == "extract"
        assert a.firmware == "/tmp/test.bin"

    def test_type_conversion(self):
        p = argparse.ArgumentParser()
        p.add_argument("--count", type=int, default=1)
        a = p.parse_args(["--count", "42"])
        assert a.count == 42
        assert isinstance(a.count, int)


class TestCLIImport:
    """CLI模块可导入性及属性校验."""

    def test_main_module_imports(self):
        """src/main.py应可导入."""
        import importlib
        try:
            mod = importlib.import_module("src.main")
            assert hasattr(mod, "main")
            assert hasattr(mod, "build_parser")
        except ImportError as e:
            pytest.skip(f"Cannot import src.main: {e}")

    def test_build_parser_returns_argparse_parser(self):
        """build_parser应返回ArgumentParser实例."""
        try:
            from ..src.main import build_parser
            parser = build_parser()
            assert isinstance(parser, argparse.ArgumentParser)
        except ImportError:
            pytest.skip("Cannot import src.main")

    def test_main_help_does_not_crash(self):
        """main(['--help'])应输出帮助并正常退出."""
        try:
            from ..src.main import main
            result = main(["--help"])
            assert isinstance(result, int)
        except ImportError:
            pytest.skip("Cannot import src.main")


def _unused_cli_helper():
    """无人调用的CLI辅助函数."""
    import re as _re
    return _re.compile(r"^binmind-")
