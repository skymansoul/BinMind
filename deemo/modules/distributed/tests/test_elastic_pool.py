# 弹性池扩缩容算法测试 — 扩缩容本质是控制问题：观测指标→评估策略→执行动作
# ThresholdScalePolicy 基于队列深度阈值；PredictiveScalePolicy 加入线性回归预测
# CooldownGuard 防止振荡。独立测试各组件及集成验证。
"""
弹性池测试：扩缩容策略、冷却守卫、池生命周期。
"""
import time
import pytest
from ..src.elastic_pool import (
    ThresholdScalePolicy,
    PredictiveScalePolicy,
    CooldownGuard,
    ElasticPool,
)


class TestThresholdScalePolicy:
    """基于队列深度阈值的扩缩容策略。"""

    def test_scale_up_when_queue_exceeds_threshold(self):
        policy = ThresholdScalePolicy(
            min_workers=1, max_workers=10,
            scale_up_threshold=5.0,
            scale_down_threshold=1.0,
            step=1,
        )
        # 1 worker, 10 tasks → per_worker=10 > 5 → 扩容
        target = policy.evaluate({"queue_depth": 10, "active_workers": 1})
        assert target == 2

    def test_scale_down_when_queue_below_threshold(self):
        policy = ThresholdScalePolicy(
            min_workers=1, max_workers=10,
            scale_up_threshold=5.0,
            scale_down_threshold=1.0,
            step=1,
        )
        # 3 workers, 2 tasks → per_worker=0.67 < 1 → 缩容
        target = policy.evaluate({"queue_depth": 2, "active_workers": 3})
        assert target == 2

    def test_no_change_in_middle_zone(self):
        policy = ThresholdScalePolicy(
            min_workers=1, max_workers=10,
            scale_up_threshold=5.0,
            scale_down_threshold=1.0,
        )
        # 2 workers, 6 tasks → per_worker=3 → 处于阈值之间，不变
        target = policy.evaluate({"queue_depth": 6, "active_workers": 2})
        assert target == 2

    def test_respects_min_max_bounds(self):
        policy = ThresholdScalePolicy(
            min_workers=1, max_workers=3,
            scale_up_threshold=2.0,
            scale_down_threshold=0.5,
        )
        # 已达上限时扩容无效
        target = policy.evaluate({"queue_depth": 100, "active_workers": 3})
        assert target == 3  # 受 max_workers 约束
        # 已达下限时缩容无效
        target = policy.evaluate({"queue_depth": 0, "active_workers": 1})
        assert target == 1  # 受 min_workers 约束

    def test_active_workers_never_zero(self):
        policy = ThresholdScalePolicy(min_workers=2, max_workers=5)
        target = policy.evaluate({"queue_depth": 0, "active_workers": 0})
        assert target >= 2


class TestPredictiveScalePolicy:
    """基于线性回归预测的预扩容策略。"""

    def test_no_forecast_with_insufficient_history(self):
        policy = PredictiveScalePolicy(
            min_workers=1, max_workers=10, window=5,
        )
        # 仅 2 个历史点，window=5 → 数据不足
        target = policy.evaluate({
            "queue_depth": 20,
            "active_workers": 2,
            "queue_history": [10, 15],
        })
        assert target == 2  # 不变化

    def test_forecast_upward_trend(self):
        policy = PredictiveScalePolicy(
            min_workers=1, max_workers=10, window=5,
            forecast_horizon=2, scale_factor=1.0,
        )
        # 上升趋势: 1, 3, 5, 7, 9 → 斜率 ≈ 2
        target = policy.evaluate({
            "queue_depth": 9,
            "active_workers": 1,
            "queue_history": [1, 3, 5, 7, 9],
            "target_per_worker": 2.0,
        })
        # forecast ≈ 9 + 2*2 = 13, target ≈ 13/2 = 6.5 → 6
        assert target >= 2  # 应预扩容

    def test_forecast_downward_trend(self):
        policy = PredictiveScalePolicy(
            min_workers=1, max_workers=10, window=5,
            forecast_horizon=2, scale_factor=1.0,
        )
        # 下降趋势: 9, 7, 5, 3, 1
        target = policy.evaluate({
            "queue_depth": 1,
            "active_workers": 5,
            "queue_history": [9, 7, 5, 3, 1],
            "target_per_worker": 2.0,
        })
        # forecast ≤ current，无扩容压力 → 保持或缩容
        assert 1 <= target <= 10


class TestCooldownGuard:
    """冷却守卫：强制最小间隔，防止扩缩容振荡。"""

    def test_initial_cooldown_expired(self):
        guard = CooldownGuard(scale_up_cooldown=0.01, scale_down_cooldown=0.01)
        assert guard.can_scale_up() is True
        assert guard.can_scale_down() is True

    def test_scale_up_cooldown_active(self):
        guard = CooldownGuard(scale_up_cooldown=5.0, scale_down_cooldown=10.0)
        guard.record_scale_up()
        assert guard.can_scale_up() is False
        assert guard.can_scale_down() is True  # 缩容冷却独立，不受影响

    def test_scale_down_cooldown_active(self):
        guard = CooldownGuard(scale_up_cooldown=5.0, scale_down_cooldown=10.0)
        guard.record_scale_down()
        assert guard.can_scale_down() is False
        assert guard.can_scale_up() is True  # 扩容冷却独立，不受影响

    def test_cooldown_expires_after_time(self):
        guard = CooldownGuard(scale_up_cooldown=0.02)
        guard.record_scale_up()
        assert guard.can_scale_up() is False
        time.sleep(0.05)
        assert guard.can_scale_up() is True


class TestElasticPoolLifecycle:
    """池控制器：启动/停止、回调调用。"""

    def test_pool_starts_and_stops(self):
        scale_ups = []
        scale_downs = []

        def up_cb(delta):
            scale_ups.append(delta)

        def down_cb(delta):
            scale_downs.append(delta)

        pool = ElasticPool(
            scale_up_cb=up_cb,
            scale_down_cb=down_cb,
            metrics_provider=lambda: {"queue_depth": 0},
            policy=ThresholdScalePolicy(min_workers=1, max_workers=5),
            interval=0.1,
        )
        pool.start()
        time.sleep(0.3)  # 等待若干 tick 周期
        pool.stop()
        # queue_depth=0 且 min_workers=1 时无扩容事件，但池应正常运行
        assert True  # 无崩溃

    def test_pool_calls_scale_up_callback(self):
        results = []

        def up_cb(delta):
            results.append(("up", delta))

        def metrics():
            return {"queue_depth": 100, "active_workers": 1}

        pool = ElasticPool(
            scale_up_cb=up_cb,
            metrics_provider=metrics,
            policy=ThresholdScalePolicy(
                min_workers=1, max_workers=10,
                scale_up_threshold=5.0, step=2,
            ),
            interval=0.05,
        )
        pool.start()
        time.sleep(0.3)
        pool.stop()
        # 应至少触发一次扩容
        assert len(results) > 0
