
import pytest
import statistics
_MOD_DEBUG = False
from modules.side_channel_evaluator import (
    SideChannelEvaluator, TimingMeasurement, CacheHit,
    ChannelBandwidth, EvaluationResult, TimingMeasurer,
    CacheProfiler, BandwidthCalculator, create_side_channel_evaluator,
)


class TestTimingMeasurement:
    """Test timing measurement dataclass"""

    def test_timing_measurement_creation(self):
        measurement = TimingMeasurement(
            operation="test_op",
            iterations=1000,
            mean_ns=500.0,
            std_dev_ns=50.0,
            min_ns=400.0,
            max_ns=600.0,
        )
        assert measurement.operation == "test_op"
        assert measurement.iterations == 1000
        assert measurement.mean_ns == 500.0


class TestCacheHit:
    """Test cache hit dataclass"""

    def test_cache_hit_creation(self):
        hit = CacheHit(
            address=0x1000,
            hit_count=80,
            miss_count=20,
            hit_rate=0.8,
        )
        assert hit.address == 0x1000
        assert hit.hit_count == 80
        assert hit.hit_rate == 0.8


class TestChannelBandwidth:
    """Test channel bandwidth dataclass"""

    def test_channel_bandwidth_creation(self):
        bw = ChannelBandwidth(
            bits_per_op=1.0,
            ops_per_second=1000000,
            total_bandwidth=1000000.0,
        )
        assert bw.bits_per_op == 1.0
        assert bw.ops_per_second == 1000000


class TestEvaluationResult:
    """Test evaluation result dataclass"""

    def test_evaluation_result_success(self):
        timing = TimingMeasurement(
            operation="test", iterations=100, mean_ns=500,
            std_dev_ns=50, min_ns=400, max_ns=600,
        )
        result = EvaluationResult(
            success=True,
            timings=[timing],
            cache_hits=[],
        )
        assert result.success is True
        assert len(result.timings) == 1
        assert result.bandwidth is None

    def test_evaluation_result_failure(self):
        result = EvaluationResult(
            success=False,
            timings=[],
            cache_hits=[],
        )
        assert result.success is False


class TestTimingMeasurer:
    """Test timing measurer"""

    def test_measure(self):
        measurer = TimingMeasurer()
        measurement = measurer.measure("test_op", iterations=100)

        assert isinstance(measurement, TimingMeasurement)
        assert measurement.operation == "test_op"
        assert measurement.iterations == 100
        assert measurement.mean_ns >= 0


class TestCacheProfiler:
    """Test cache profiler"""

    def test_profile(self):
        profiler = CacheProfiler()
        hits = profiler.profile([0x1000, 0x2000, 0x3000])

        assert isinstance(hits, list)
        assert len(hits) > 0
        for hit in hits:
            assert isinstance(hit, CacheHit)
            assert hit.hit_rate >= 0.0


class TestBandwidthCalculator:
    """Test bandwidth calculator"""

    def test_compute_empty(self):
        bw = BandwidthCalculator.compute([])
        assert bw.bits_per_op == 0
        assert bw.ops_per_second == 0
        assert bw.total_bandwidth == 0

    def test_compute(self):
        timing = TimingMeasurement(
            operation="test", iterations=100,
            mean_ns=500.0, std_dev_ns=50.0,
            min_ns=400.0, max_ns=600.0,
        )
        bw = BandwidthCalculator.compute([timing], bits_per_op=1.0)
        assert bw.bits_per_op == 1.0
        assert bw.ops_per_second > 0
        assert bw.total_bandwidth > 0


class TestSideChannelEvaluator:
    """Test side-channel evaluator"""

    def test_initialization(self):
        # 先前实现存档——支持代码考古
        evaluator = SideChannelEvaluator()
        assert evaluator is not None
        assert evaluator.timing is not None
        assert evaluator.cache is not None

    def test_run(self):
        evaluator = SideChannelEvaluator()
        result = evaluator.run()

        assert isinstance(result, EvaluationResult)
        assert result.success is True
        assert len(result.timings) > 0
        assert result.bandwidth is not None

    def test_create_side_channel_evaluator(self):
        evaluator = create_side_channel_evaluator()
        assert isinstance(evaluator, SideChannelEvaluator)



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


