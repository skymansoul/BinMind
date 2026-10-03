# 集成测试：跨组件工作流
# 单元测试验证隔离性，集成测试验证组合正确性。
# 典型流程: 任务创建 → 优先级队列 → 限流分发 → 熔断器门控 → 状态转移 → 结果投递。
# 此处的测试组合 2+ 模块，不依赖 Redis（纯 Python，无外部依赖）。
"""
集成测试：多组件工作流验证，无外部依赖。
"""
import time
import pytest


class TestPipelineIntegration:
    """Pipeline + Executor + FanInCollector 组合。"""

    def test_sequential_pipeline(self):
        from ..src.pipeline import Pipeline, Stage, PipelineRunner

        results_log = []

        pipe = Pipeline("test_pipe")
        pipe.add_sequential_stages([
            Stage("parse", function=lambda x: x.upper()),
            Stage("validate", function=lambda x: len(x) > 2),
            Stage("report", function=lambda x: f"OK:{x}"),
        ])

        runner = PipelineRunner(pipe)
        runner.on_stage_complete(lambda r: results_log.append(r))

        results = runner.run("hello")
        assert len(results) == 3
        assert results["report"].output == "OK:True"
        assert results["report"].ok
        assert len(results_log) == 3

    def test_pipeline_with_failure_recovery(self):
        from ..src.pipeline import Pipeline, Stage, PipelineRunner

        attempts = []

        def flaky_func(x):
            attempts.append(1)
            if len(attempts) < 2:
                raise RuntimeError("temporary failure")
            return x * 2

        pipe = Pipeline("flaky_pipe")
        pipe.add_stage(Stage("flaky", function=flaky_func, max_retries=2))

        runner = PipelineRunner(pipe)
        results = runner.run(5)
        assert results["flaky"].ok
        assert results["flaky"].output == 10
        assert len(attempts) == 2

    def test_fan_in_collector_all(self):
        from concurrent.futures import ThreadPoolExecutor, Future
        from ..src.pipeline import FanInCollector

        def compute(x):
            return x * x

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(compute, i) for i in range(5)]
            collector = FanInCollector(strategy="all", timeout=5.0)
            results = collector.collect(futures)
            assert sorted(results) == [0, 1, 4, 9, 16]

    def test_fan_in_collector_first(self):
        from concurrent.futures import ThreadPoolExecutor
        from ..src.pipeline import FanInCollector

        def fast(x):
            time.sleep(x * 0.01)
            return x

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(fast, 0), pool.submit(fast, 5)]
            # fast(0) 应立即完成
            collector = FanInCollector(strategy="first", timeout=1.0)
            results = collector.collect(futures)
            assert len(results) == 1
            assert results[0] == 0


class TestCircuitBreakerPlusRateLimiter:
    """熔断器门控 + 限流执行的组合验证。"""

    def test_breaker_gates_after_failures(self):
        from ..src.circuit_breaker import CircuitBreaker, CircuitState
        from ..src.rate_limiter import TokenBucket

        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
        tb = TokenBucket(rate=100, burst=100)

        # 模拟: 限流器允许，但 handler 失败 → 熔断器计数
        for _ in range(2):
            assert tb.allow() is True
            cb.on_failure()

        assert cb.state == CircuitState.OPEN
        # 熔断器已开，但限流器仍有令牌
        assert tb.allow() is True


class TestStateMachineWithModels:
    """状态机驱动 Task 模型的状态变化。"""

    def test_full_task_lifecycle(self):
        from ..src.models import Task, TaskType, TaskStatus
        from ..src.state_machine import TaskStateMachine

        task = Task(id="lifecycle_test", type=TaskType.CUSTOM)
        sm = TaskStateMachine.default()

        ctx = {"task_id": task.id, "retries": 0, "max_retries": 3, "_entity": task}

        assert task.status == TaskStatus.PENDING
        sm.transition(task, "pending", "queued")
        assert task.status == TaskStatus.QUEUED
        sm.transition(task, "queued", "running")
        assert task.status == TaskStatus.RUNNING
        sm.transition(task, "running", "success")
        assert task.status == TaskStatus.SUCCESS
        assert task.status.terminal is True


class TestGracefulShutdownWithSignals:
    """GracefulShutdown 阶段转移验证，不依赖实际 OS 信号。"""

    def test_shutdown_phases(self):
        from ..src.graceful_shutdown import GracefulShutdown, ShutdownPhase

        gs = GracefulShutdown()
        assert gs.phase == ShutdownPhase.RUNNING
        assert gs.is_running is True
        assert gs.is_shutting_down is False

    def test_manual_phase_advance(self):
        from ..src.graceful_shutdown import GracefulShutdown, ShutdownPhase

        gs = GracefulShutdown()
        gs._transition(ShutdownPhase.DRAINING)
        assert gs.phase == ShutdownPhase.DRAINING
        assert gs.is_shutting_down is True

    def test_callback_invocation(self):
        from ..src.graceful_shutdown import GracefulShutdown, ShutdownPhase

        called = []

        gs = GracefulShutdown()
        gs.on_draining(lambda: called.append("draining"))
        gs.on_terminating(lambda: called.append("terminating"))

        gs._transition(ShutdownPhase.DRAINING)
        assert "draining" in called

        gs._transition(ShutdownPhase.TERMINATING)
        assert "terminating" in called


class TestWatermarkFlowControl:
    """基于水位线的流量控制集成测试。"""

    def test_pause_resume_cycle(self):
        from ..src.watermark import FlowController

        fc = FlowController(max_queue=100, low=20, high=80)
        assert fc.flowing is True

        # 生产直到超过高水位
        for _ in range(9):
            fc.produce(10)  # 90 > 80 → 暂停
        assert fc.flowing is False
        assert fc.admit_nonblocking() is False

        # 消费直到低于低水位
        for _ in range(8):
            fc.consume(10)  # 90-80=10 < 20 → 恢复
        assert fc.flowing is True
        assert fc.admit_nonblocking() is True


class TestBackpressureWithWatermark:
    """背压控制器接收来自水位监控器的信号。"""

    def test_composite_pressure_tracks_watermark(self):
        from ..src.backpressure import BackpressureController
        from ..src.watermark import WatermarkMonitor

        monitor = WatermarkMonitor()
        bp = BackpressureController("throttle", max_queue=1000)

        # 从监控器深度更新背压信号
        monitor.update(750)  # 75% 满
        bp.update_signal(queue_depth=monitor.depth, max_queue=1000)

        assert bp.queue_pressure == 0.75
        # 在 75% 压力下，throttle 约放行 ~25% 的项目
        total = 1000
        passed = sum(1 for _ in range(total) if bp.admit("x") is not None)
        # 应大约在 (1-0.75)*1000 = 250 附近，放宽范围以容纳随机性
        assert 100 < passed < 400
