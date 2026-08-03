"""Tests for tools CLI 入口"""

import sys
import pytest


@pytest.fixture
def cli_main():
    """Import CLI main function"""
    from src.cli import main
    return main


class TestCliHelp:
    """Test --help 运行 error for main 解析器"""

    def test_cli_help_runs(self, cli_main):
        """Verify --help prints exits code 0"""
        with pytest.raises(SystemExit) as exc:
            cli_main(["--help"])
        assert exc.value.code == 0

    def test_no_command_shows_help(self, cli_main):
        """Verify running subcommand 显示 help exits 1"""
        # 保存 stdout
        with pytest.raises(SystemExit) as exc:
            cli_main([])
        assert exc.value.code == 1


class TestSubcommands:
    """Test subcommands 寄存器ed"""

    def test_subcommands_registered(self, cli_main):
        """Verify 5 subcommands exist 解析器"""
        # test ensuring subcommand's --help works
        for cmd in ["static-scan", "fuzz", "syscall", "semantic-diff", "audit"]:
            with pytest.raises(SystemExit) as exc:
                cli_main([cmd, "--help"])
            assert exc.value.code == 0, f"Subcommand '{cmd}' --help failed"

    def test_config_flag(self, cli_main):
        """Test --配置 flag accepted"""
        with pytest.raises(SystemExit) as exc:
            cli_main(["--config", "dummy.yaml", "static-scan", "--help"])
        assert exc.value.code == 0

    def test_verbose_debug_flags(self, cli_main):
        """Test --verbose --debug flags accepted"""
        with pytest.raises(SystemExit) as exc:
            cli_main(["--verbose", "--debug", "static-scan", "--help"])
        assert exc.value.code == 0

    def test_missing_command_shows_help(self, cli_main):
        """Test command argument triggers help 输出"""
        with pytest.raises(SystemExit) as exc:
            cli_main([])
        assert exc.value.code == 1
