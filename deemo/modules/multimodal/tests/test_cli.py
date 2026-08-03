#!/usr/bin/env python3
# CLI 参数解析验证 — argparse 构建正确性、子命令分发与退出码
import sys
import os
import pytest
import importlib

_src = os.path.join(os.path.dirname(__file__), "..", "src")

# 显式加载 src/cli.py，避免与项目根 cli 模块冲突
_spec = importlib.util.spec_from_file_location(
    "multimodal_cli",
    os.path.join(_src, "cli.py"),
    submodule_search_locations=[])
_cli_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cli_mod)

main = _cli_mod.main
_build_parser = _cli_mod._build_parser


def test_cli_help_flag():
    """--help 应输出帮助信息并以码 0 退出。"""
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_cli_no_command_returns_1():
    """无子命令时返回 1 而非抛 SystemExit。"""
    rc = main([])
    assert rc == 1


def test_cli_analyze_requires_targets():
    """analyze 子命令强制要求 targets 位置参数。"""
    parser = _build_parser()
    args = parser.parse_args(["analyze", "bin1", "bin2"])
    assert args.targets == ["bin1", "bin2"]


def test_cli_stats_with_type():
    """stats 子命令接受 --type 选项指定统计类型。"""
    parser = _build_parser()
    args = parser.parse_args(["stats", "--type", "vulnerability_distribution", "input.json"])
    assert args.stat_type == "vulnerability_distribution"
    assert args.input == "input.json"


def test_cli_orchestrate_dry_run():
    """orchestrate 子命令支持 --dry-run 模拟执行。"""
    parser = _build_parser()
    args = parser.parse_args(["orchestrate", "--dry-run", "--target", "linux"])
    assert args.dry_run is True
    assert args.target == "linux"


def test_cli_orchestrate_strategy_validation():
    """--strategy 的 choices 约束非法值触发解析错误。"""
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["orchestrate", "--strategy", "invalid_strategy"])


def test_cli_adapt_with_template():
    """adapt 子命令接受 --template 指定漏洞利用模板名。"""
    parser = _build_parser()
    args = parser.parse_args(["adapt", "--template", "bof_chain", "targets.json"])
    assert args.template == "bof_chain"
    assert args.targets_file == "targets.json"


def test_cli_fusion_method_validation():
    """fusion --method 非法值触发 choices 约束。"""
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["fusion", "--method", "invalid_fusion", "f1.json"])


def test_cli_verbose_flag_sets_level():
    """--verbose 与 --debug 为独立的布尔标志。"""
    parser = _build_parser()
    args = parser.parse_args(["--verbose", "analyze", "test.bin"])
    assert args.verbose is True
    assert args.debug is False


def test_cli_debug_overrides_verbose():
    """--debug 独立启用不受 --verbose 影响。"""
    parser = _build_parser()
    args = parser.parse_args(["--debug", "analyze", "test.bin"])
    assert args.debug is True
