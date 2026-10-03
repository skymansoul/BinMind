"""Tests for sandbox orchestrator."""
import os
import sys
import pytest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.dynamic_analysis.sandbox_orchestrator import (
    SandboxOrchestrator, SandboxConfig, SandboxBackend,
    ResourceLimits, NetworkMode, SandboxResult, ProcessSandboxDriver,
    SandboxState
)


class TestProcessDriver:
    """Unit tests for the process (lightweight) driver."""

    def test_basic_echo(self):
        config = SandboxConfig(
            backend=SandboxBackend.PROCESS,
            resources=ResourceLimits(timeout_seconds=10, memory_mb=128))
        driver = ProcessSandboxDriver(config)
        driver.start()
        result = driver.execute(['python', '-c', 'print("hello")'])
        driver.stop()
        assert result.success
        assert 'hello' in result.stdout

    def test_timeout(self):
        config = SandboxConfig(
            backend=SandboxBackend.PROCESS,
            resources=ResourceLimits(timeout_seconds=1))
        driver = ProcessSandboxDriver(config)
        driver.start()
        result = driver.execute(['python', '-c', 'import time; time.sleep(10)'])
        driver.stop()
        assert not result.success
        assert 'Timed out' in result.error

    def test_nonzero_exit(self):
        config = SandboxConfig(backend=SandboxBackend.PROCESS)
        driver = ProcessSandboxDriver(config)
        driver.start()
        result = driver.execute(['python', '-c', 'import sys; sys.exit(42)'])
        driver.stop()
        assert not result.success
        assert result.exit_code == 42

    def test_stderr_capture(self):
        config = SandboxConfig(backend=SandboxBackend.PROCESS)
        driver = ProcessSandboxDriver(config)
        driver.start()
        result = driver.execute(
            ['python', '-c', 'import sys; sys.stderr.write("errmsg")'])
        driver.stop()
        assert 'errmsg' in result.stderr


class TestOrchestrator:
    """Unit tests for the top-level orchestrator."""

    def test_configure_process(self):
        orch = SandboxOrchestrator()
        ok = orch.configure(SandboxConfig(backend=SandboxBackend.PROCESS))
        assert ok
        assert orch.driver is not None
        assert orch.driver.backend == SandboxBackend.PROCESS

    def test_run_and_summary(self):
        orch = SandboxOrchestrator()
        orch.configure(SandboxConfig(backend=SandboxBackend.PROCESS))
        orch.start()
        result = orch.run(['python', '-c', 'print("ok")'])
        orch.shutdown()
        assert result.success
        summary = orch.get_summary()
        assert summary['total_executions'] == 1
        assert summary['successful'] == 1

    def test_auto_select_backend(self):
        backend = SandboxOrchestrator.auto_select()
        assert backend in SandboxBackend.__members__.values()

    def test_list_available_backends(self):
        backends = SandboxOrchestrator.list_available_backends()
        assert 'process' in backends  # always available

    def test_run_without_start(self):
        orch = SandboxOrchestrator()
        orch.configure(SandboxConfig(backend=SandboxBackend.PROCESS))
        # Don't start
        result = orch.run(['echo', 'test'])
        assert not result.success
        assert 'not running' in result.error.lower()

    def test_resource_limits_default(self):
        limits = ResourceLimits()
        assert limits.cpu_count == 1.0
        assert limits.memory_mb == 512
        assert limits.timeout_seconds == 300

    def test_sandbox_config_defaults(self):
        config = SandboxConfig()
        assert config.backend == SandboxBackend.DOCKER
        assert config.network == NetworkMode.NAT
        assert config.enable_telemetry is True


class TestProcessDriverWithInput:
    def test_stdin_pipe(self):
        config = SandboxConfig(backend=SandboxBackend.PROCESS)
        driver = ProcessSandboxDriver(config)
        driver.start()
        result = driver.execute(
            ['python', '-c', 'import sys; print(sys.stdin.read().upper())'],
            stdin_data=b'hello world')
        driver.stop()
        assert 'HELLO WORLD' in result.stdout
