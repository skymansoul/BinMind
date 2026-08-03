# tests/test_cli.py — ai_ml CLI integration tests
import sys
import os
import json
import pytest
import subprocess

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


class TestCLIParsing:
    """CLI参数解析验证"""

    def test_parser_help_no_crash(self):
        """--help不崩溃且返回0"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py'), '--help'],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        assert 'mutation' in result.stdout.lower() or 'mutate' in result.stdout.lower()

    def test_no_subcommand_shows_help(self):
        """无子命令时显示帮助"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py')],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0

    def test_mutate_subcommand_help(self):
        """mutate子命令帮助"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py'), 'mutate', '--help'],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        assert 'seed' in result.stdout.lower() or 'count' in result.stdout.lower()

    def test_search_benchmark(self):
        """search --benchmark 执行成功"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py'), 'search', '--benchmark'],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        assert 'benchmark' in result.stdout


class TestCLIVulnPrediction:
    """漏洞预测CLI"""

    def test_vuln_default_prediction(self):
        """默认漏洞预测不崩溃"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py'), 'vuln'],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert 'severity' in data


class TestCLIConfig:
    """配置命令"""

    def test_config_show(self):
        """config --show 输出配置"""
        result = subprocess.run(
            [sys.executable, os.path.join(_src_dir, 'main.py'), 'config', '--show'],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert 'paths' in data or 'logging' in data
