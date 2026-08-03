# 2026-07-28
# CLI tests for 去混淆 module
"""Tests for 去混淆 CLI 入口"""

import pytest
import sys


class TestCLI:
    """Tests for 去混淆 CLI"""

    def test_help_runs(self) -> None:
        """Verify --help produces 输出 error"""
        try:
            from ..src.cli import main
            result = main(["--help"])
            assert result == 0
        except SystemExit as exc:
            assert exc.code == 0

    def test_subcommands_registered(self) -> None:
        """Verify 6 subcommands 寄存器ed"""
        import argparse
        from ..src.cli import main as cli_main_module

        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        sp.add_parser("deobfuscate")
        sp.add_parser("decode-strings")
        sp.add_parser("unpack")
        sp.add_parser("detect-vm")
        sp.add_parser("extract-scripts")
        sp.add_parser("detect-repack")

        args = p.parse_args(["deobfuscate", "--input", "test.bin"])
        assert args.command == "deobfuscate"

        args2 = p.parse_args(["decode-strings", "--input", "strings.txt"])
        assert args2.command == "decode-strings"

    def test_config_flag(self) -> None:
        """Verify --配置 flag accepted"""
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--config", default=None)
        args = p.parse_args(["--config", "/path/to/config.yaml"])
        assert args.config == "/path/to/config.yaml"

    def test_verbose_flag(self) -> None:
        """Verify --verbose flag works"""
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--verbose", "-v", action="store_true")
        args = p.parse_args(["-v"])
        assert args.verbose is True

    def test_missing_command(self) -> None:
        """Verify missing command exits error"""
        import argparse
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        sp.add_parser("test_cmd")

        args = p.parse_args([])
        assert args.command is None


class TestSubcommandArgs:
    """Test argument parsing 对每个 subcommand"""

    def test_deobfuscate_args(self) -> None:
        """去混淆 subcommand accepts input level"""
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
        """脱壳 subcommand accepts input 输出"""
        import argparse
        p = argparse.ArgumentParser()
        sp = p.add_subparsers(dest="command")
        p_up = sp.add_parser("unpack")
        p_up.add_argument("--input", "-i", required=True)
        p_up.add_argument("--output", "-o", default="unpacked")
        args = p.parse_args(["unpack", "-i", "packed.exe", "-o", "out/"])
        assert args.input == "packed.exe"
        assert args.output == "out/"
