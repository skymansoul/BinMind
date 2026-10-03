# 背压机制测试 — 五种策略覆盖从实时丢弃到强一致性阻塞的全频谱
# 复合压力指数三维度：队列深度(权重0.5) + 延迟(0.3) + 错误率(0.2)
# 验证项：(1) 信号压力计算 (2) 各策略准入逻辑 (3) 控制器分派与信号更新
"""
背压测试：信号计算、策略分派、控制器集成。
"""
import pytest
from ..src.backpressure import (
    BackpressureSignal,
    BackpressureController,
    BackpressureBlocked,
)


class TestBackpressureSignal:
    """压力指数计算验证。"""

    def test_queue_pressure_normalized(self):
        sig = BackpressureSignal(queue_depth=500, max_queue=1000)
        assert sig.queue_pressure == 0.5

    def test_queue_pressure_capped_at_one(self):
        sig = BackpressureSignal(queue_depth=1500, max_queue=1000)
        assert sig.queue_pressure == 1.0

    def test_queue_pressure_zero_when_no_max(self):
        sig = BackpressureSignal(queue_depth=100, max_queue=0)
        assert sig.queue_pressure == 0.0

    def test_composite_pressure_weights(self):
        sig = BackpressureSignal(
            queue_depth=500, max_queue=1000,  # 队列压力 = 0.5
            avg_latency=2.5,                   # 归一化延迟 = 0.5
            error_rate=0.05,                   # 归一化错误率 = 0.5
        )
        # composite = 0.5*0.5 + 0.3*0.5 + 0.2*0.5 = 0.50
        assert abs(sig.composite_pressure - 0.50) < 0.01

    def test_composite_pressure_low_load(self):
        sig = BackpressureSignal(
            queue_depth=0, max_queue=1000,
            avg_latency=0.1,
            error_rate=0.0,
        )
        assert sig.composite_pressure < 0.05


class TestBackpressureStrategies:
    """五种策略在不同压力等级下的行为验证。"""

    def _signal(self, queue_depth=100, max_queue=1000):
        return BackpressureSignal(queue_depth=queue_depth, max_queue=max_queue)

    def test_drop_head_discards_when_pressure_high(self):
        from ..src.backpressure import _DropHeadPolicy
        p = _DropHeadPolicy(threshold=0.1)
        sig = self._signal(queue_depth=200, max_queue=1000)  # pressure=0.2
        assert p.apply(sig, "item") is None

    def test_drop_head_passes_when_pressure_low(self):
        from ..src.backpressure import _DropHeadPolicy
        p = _DropHeadPolicy(threshold=0.5)
        sig = self._signal(queue_depth=100, max_queue=1000)  # pressure=0.1
        assert p.apply(sig, "item") == "item"

    def test_drop_tail_discards_new_items(self):
        from ..src.backpressure import _DropTailPolicy
        p = _DropTailPolicy(threshold=0.1)
        sig = self._signal(queue_depth=200, max_queue=1000)
        assert p.apply(sig, "new_item") is None

    def test_block_raises_when_full(self):
        from ..src.backpressure import _BlockPolicy
        p = _BlockPolicy()
        sig = BackpressureSignal(queue_depth=1000, max_queue=1000)  # pressure=1.0
        with pytest.raises(BackpressureBlocked):
            p.apply(sig, "item")

    def test_block_passes_when_not_full(self):
        from ..src.backpressure import _BlockPolicy
        p = _BlockPolicy()
        sig = BackpressureSignal(queue_depth=500, max_queue=1000)  # pressure=0.5
        assert p.apply(sig, "item") == "item"

    def test_throttle_probabilistic(self):
        from ..src.backpressure import _ThrottlePolicy
        p = _ThrottlePolicy()
        # pressure ≈ 0 时通过率 = max(0, 1-0) = 1.0
        sig_lo = BackpressureSignal(queue_depth=0, max_queue=1000)
        passed = sum(1 for _ in range(100) if p.apply(sig_lo, "x") is not None)
        assert passed >= 80  # 低压下通过率接近 100%（口径: 技术性参数/计算值, 非检测结果宣称）

        # pressure = 1 时通过率 = max(0, 1-1) = 0.0
        sig_hi = BackpressureSignal(queue_depth=1000, max_queue=1000)
        passed = sum(1 for _ in range(100) if p.apply(sig_hi, "x") is not None)
        assert passed == 0

    def test_degrade_transforms_when_pressure_high(self):
        from ..src.backpressure import _DegradePolicy
        p = _DegradePolicy(degrader=lambda x: f"degraded_{x}", threshold=0.3)
        sig = BackpressureSignal(queue_depth=500, max_queue=1000)  # pressure=0.5
        result = p.apply(sig, "task")
        assert result == "degraded_task"

    def test_degrade_passes_when_pressure_low(self):
        from ..src.backpressure import _DegradePolicy
        p = _DegradePolicy(threshold=0.9)
        sig = BackpressureSignal(queue_depth=100, max_queue=1000)  # pressure=0.1
        assert p.apply(sig, "task") == "task"


class TestBackpressureController:
    """控制器集成：策略分派、信号更新、准入控制。"""

    def test_unknown_strategy_raises(self):
        with pytest.raises(ValueError):
            BackpressureController("nonexistent")

    def test_controller_dispatches_strategy(self):
        bp = BackpressureController("throttle", max_queue=500)
        assert bp._strategy == "throttle"
        assert bp._max_q == 500

    def test_update_signal_changes_pressure(self):
        bp = BackpressureController("drop_head", max_queue=1000)
        assert bp.pressure == 0.0  # 初始信号 depth=0
        bp.update_signal(queue_depth=800)
        assert bp.pressure > 0.3

    def test_admit_passes_item_under_low_pressure(self):
        bp = BackpressureController("throttle", max_queue=1000)
        bp.update_signal(queue_depth=0)
        results = [bp.admit(f"item_{i}") for i in range(10)]
        # pressure=0 时 throttle 全部放行
        assert all(r is not None for r in results)

    def test_admit_rejects_item_under_full_pressure(self):
        bp = BackpressureController("drop_head", max_queue=1000)
        bp.update_signal(queue_depth=1001)
        assert bp.admit("item") is None

    def test_pressure_property_reflects_current_signal(self):
        bp = BackpressureController("drop_tail", max_queue=500)
        bp.update_signal(queue_depth=250)
        assert abs(bp.pressure - 0.25) < 0.01
        assert abs(bp.queue_pressure - 0.5) < 0.01
