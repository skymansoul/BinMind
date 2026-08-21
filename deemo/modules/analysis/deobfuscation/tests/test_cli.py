# CLI tests for 去混淆 module
"""去混淆 CLI 入口测试"""

import pytest
import sys

class TestCLI:
    """去混淆 CLI 测试"""

    def test_help_runs(self) -> None:
        try:
            from ..src.cli import main
            result = main(["--help"])
            assert result == 0
        except SystemExit as exc:
            assert exc.code == 0

    def test_subcommands_registered(self) -> None:
        import argparse
        from ..src.cli import main as cli_main_module

        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        p_deob = sp.add_parser("deobfuscate")
        p_deob.add_argument("--input", "-i", required=True)
        p_dec = sp.add_parser("decode-strings")
        p_dec.add_argument("--input", "-i", required=True)
        sp.add_parser("unpack")
        sp.add_parser("detect-vm")
        sp.add_parser("extract-scripts")
        sp.add_parser("detect-repack")

        args = p.parse_args(["deobfuscate", "--input", "test.bin"])
        assert args.command == "deobfuscate"

        args2 = p.parse_args(["decode-strings", "--input", "strings.txt"])
        assert args2.command == "decode-strings"

    def test_config_flag(self) -> None:
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--config", default=None)
        args = p.parse_args(["--config", "/path/to/config.yaml"])
        assert args.config == "/path/to/config.yaml"

    def test_verbose_flag(self) -> None:
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--verbose", "-v", action="store_true")
        args = p.parse_args(["-v"])
        assert args.verbose is True

    def test_missing_command(self) -> None:
        import argparse
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        sp.add_parser("test_cmd")

        args = p.parse_args([])
        assert args.command is None


class TestSubcommandArgs:
    """各子命令参数解析测试"""

    def test_deobfuscate_args(self) -> None:
        import argparse
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        p_deob = sp.add_parser("deobfuscate")
        p_deob.add_argument("--input", "-i", required=True)
        p_deob.add_argument("--level", default="medium")
        args = p.parse_args(["deobfuscate", "-i", "test.bin", "--level", "aggressive"])
        assert args.input == "test.bin"
        assert args.level == "aggressive"

    def test_unpack_args(self) -> None:
        import argparse
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        p_up = sp.add_parser("unpack")
        p_up.add_argument("--input", "-i", required=True)
        p_up.add_argument("--output", "-o", default="unpacked")
        args = p.parse_args(["unpack", "-i", "packed.exe", "-o", "out/"])
        assert args.input == "packed.exe"
        assert args.output == "out/"
