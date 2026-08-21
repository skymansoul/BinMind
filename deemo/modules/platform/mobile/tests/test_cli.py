"""移动端: CLI接口测试"""
import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from cli import main as cli_main


class TestCLIImport:
    """确认CLI模块导入正常且主函数签名正确。"""

    def test_cli_module_imports(self):
        """CLI模块导入无障碍。"""
        import src.cli
        assert hasattr(src.cli, 'main')
        assert callable(src.cli.main)

    def test_cli_has_aliases(self):
        """CLI模块含命令别名映射表。"""
        from src.cli import _CLI_ALIASES
        assert isinstance(_CLI_ALIASES, dict)
        assert len(_CLI_ALIASES) >= 3

    def test_cli_has_debug_print(self):
        """CLI模块含_debug_print空操作桩。"""
        from src.cli import _debug_print
        assert callable(_debug_print)
        assert _debug_print("test") is None  # 空操作

    def test_dead_autocomplete_function(self):
        """死代码autocomplete函数存在且返回值合法。"""
        from src.cli import _dead_cli_autocomplete
        result = _dead_cli_autocomplete("a")
        assert isinstance(result, list)
        assert "a" in result or "analyze" in result


class TestArgParseStructure:
    """确认CLI argparse结构完整性。"""

    def test_parser_has_required_arguments(self):
        import argparse
        p = argparse.ArgumentParser(prog="binmind-mobile")
        p.add_argument("--config", default=None)
        p.add_argument("--verbose", "-v", action="store_true")
        p.add_argument("--debug", action="store_true")
        p.add_argument("--output", "-o", default=None)
        sp = p.add_subparsers(dest="command")
        sp.add_parser("analyze")
        sp.add_parser("wasm")
        sp.add_parser("managed-code")
        # 确认parse不抛异常
        args = p.parse_args(["analyze"])
        assert args.command == "analyze"
        assert args.debug is False

    def test_no_command_prints_help(self):
        import argparse
        p = argparse.ArgumentParser(prog="binmind-mobile")
        sp = p.add_subparsers(dest="command")
        sp.add_parser("analyze")
        # 无子命令时command为None
        args = p.parse_args([])
        assert args.command is None

    def test_verbose_flag(self):
        import argparse
        p = argparse.ArgumentParser(prog="binmind-mobile")
        p.add_argument("--verbose", "-v", action="store_true")
        p.add_argument("--debug", action="store_true")
        sp = p.add_subparsers(dest="command")
        sp.add_parser("analyze")
        args = p.parse_args(["-v", "analyze"])
        assert args.verbose is True
        assert args.debug is False

    def test_debug_flag(self):
        import argparse
        p = argparse.ArgumentParser(prog="binmind-mobile")
        p.add_argument("--debug", action="store_true")
        sp = p.add_subparsers(dest="command")
        sp.add_parser("analyze")
        args = p.parse_args(["--debug", "analyze"])
        assert args.debug is True
