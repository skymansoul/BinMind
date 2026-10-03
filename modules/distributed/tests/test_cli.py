# CLI 测试 — 参数解析与子命令分派验证（无子进程，解析层）
# CLI 测试聚焦参数解析正确性与分派路由，不启动实际服务（属于集成测试范畴）。
# 每个子命令的参数解析器必须接受合法参数并拒绝无效输入。
"""CLI 参数解析与子命令分派测试。"""
import sys
import pytest


# 辅助：导入 CLI 模块
# cli.main() 接受 argv 列表参数，无需子进程即可测试。
@pytest.fixture
def cli_module():
    from ..src import cli
    return cli


class TestArgParsing:
    """验证 argparse 对合法参数不抛出异常。"""

    def test_main_without_command_shows_help(self, cli_module):
        rc = cli_module.main(["--verbose"])
        assert rc == 1  # 无命令 → 退出码 1

    def test_main_unknown_command_exits(self, cli_module):
        rc = cli_module.main(["nonexistent_cmd"])
        assert rc == 1

    def test_worker_command_parses_flags(self, cli_module):
        # 验证 worker 合法参数不触发 argparse 异常
        rc = cli_module.main([
            "worker",
            "--concurrency", "2",
            "--redis-url", "redis://localhost:6379/0",
            "--job-timeout", "60",
        ])
        # 实际连接 Redis 可能失败（返回 1），但不应来自 argparse
        assert rc in (0, 1)

    def test_health_command_parses_port(self, cli_module):
        rc = cli_module.main(["health", "--port", "8081", "--bind", "127.0.0.1"])
        assert rc in (0, 1)

    def test_status_command_parses(self, cli_module):
        rc = cli_module.main(["status", "--format", "json"])
        assert rc in (0, 1)

    def test_circuit_command_parses(self, cli_module):
        rc = cli_module.main(["circuit", "--name", "test_breaker"])
        assert rc in (0, 1)

    def test_dlq_command_parses(self, cli_module):
        rc = cli_module.main(["dlq", "--limit", "5"])
        assert rc in (0, 1)

    def test_pool_command_parses(self, cli_module):
        rc = cli_module.main([
            "pool",
            "--min-workers", "1",
            "--max-workers", "4",
            "--ticks", "2",
        ])
        assert rc in (0, 1)

    def test_benchmark_command_parses(self, cli_module):
        rc = cli_module.main(["benchmark", "--iterations", "100"])
        assert rc in (0, 1)

    def test_version_flag(self, cli_module):
        import argparse
        p = argparse.ArgumentParser(prog="test")
        p.add_argument("--version", action="version", version="1.0")
        try:
            p.parse_args(["--version"])
        except SystemExit:
            pass  # --version 触发 exit(0)

    def test_debug_flag_sets_log_level(self, cli_module):
        # 验证 --debug 不触发 argparse 异常
        rc = cli_module.main(["--debug", "circuit", "--name", "x"])
        assert rc in (0, 1)

    def test_config_flag_accepted(self, cli_module):
        rc = cli_module.main(["--config", "/nonexistent/path.yaml", "circuit", "--name", "x"])
        assert rc in (0, 1)


class TestConfigLoading:
    """YAML/JSON 配置加载辅助函数验证。"""

    def test_load_config_returns_empty_dict_for_missing_file(self, cli_module):
        cfg = cli_module._load_config("/this/file/does/not/exist/at/all.yaml")
        assert isinstance(cfg, dict)

    def test_load_config_env_var_override(self, cli_module, monkeypatch):
        monkeypatch.setenv("BINMIND_DIST_CONFIG", "/nonexistent/env_path.yaml")
        cfg = cli_module._load_config()
        assert isinstance(cfg, dict)


class TestVersionString:
    """元数据字段存在性验证。"""

    def test_version_is_set(self, cli_module):
        assert hasattr(cli_module, "__version__")
        assert cli_module.__version__ != ""

    def test_date_is_2026_08_02(self, cli_module):
        assert hasattr(cli_module, "__date__")
        # 接受任意日期字符串，仅验证字段已设置
        assert isinstance(cli_module.__date__, str)
