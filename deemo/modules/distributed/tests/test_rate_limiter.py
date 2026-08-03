# 限流器算法正确性验证
# 令牌桶是经典限流器；其正确性取决于
# (1) 惰性填充算术, (2) 线程安全, (3) 突发处理。
# 分别测试各项，以及装饰器和并发限制器。
"""
限流器测试：TokenBucket、ConcurrencyLimiter、装饰器、分布式回退。
"""
import time
import threading
import pytest


class TestTokenBucket:
    """惰性填充令牌桶正确性。"""

    def test_initial_burst_available(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=10, burst=5)
        # 前 5 次应成功 (burst=5)
        for _ in range(5):
            assert tb.allow() is True
        # 第 6 次应失败 (令牌耗尽，速率尚未补充)
        assert tb.allow() is False

    def test_refill_over_time(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=100, burst=1)
        assert tb.allow() is True   # 使用 1 个 burst 令牌
        assert tb.allow() is False  # 无令牌剩余
        time.sleep(0.02)  # 100 tokens/s * 0.02s = 2 令牌补充
        assert tb.allow() is True   # 消耗一个令牌

    def test_allow_n_bulk_consumption(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=100, burst=10)
        assert tb.allow_n(3) is True
        assert tb.allow_n(8) is False  # 仅剩 7 个
        assert tb.allow_n(7) is True   # 精确匹配

    def test_burst_default_equals_rate(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=7)
        assert tb._burst == 7

    def test_tokens_property_refills(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=1000, burst=100)
        assert tb.tokens >= 99  # 接近满

    def test_rate_zero_never_allows(self):
        from ..src.rate_limiter import TokenBucket
        tb = TokenBucket(rate=0.0, burst=0)
        assert tb.allow() is False


class TestConcurrencyLimiter:
    """基于信号量的并发上限。"""

    def test_basic_acquire_release(self):
        from ..src.rate_limiter import ConcurrencyLimiter
        cl = ConcurrencyLimiter(max_concurrent=2)
        assert cl.acquire() is True
        assert cl.active == 1
        assert cl.acquire() is True
        assert cl.active == 2
        assert cl.acquire(blocking=False) is False  # 已达上限
        cl.release()
        assert cl.active == 1
        cl.release()
        assert cl.active == 0

    def test_context_manager(self):
        from ..src.rate_limiter import ConcurrencyLimiter
        cl = ConcurrencyLimiter(max_concurrent=1)
        with cl:
            assert cl.active == 1
        assert cl.active == 0


class TestRateLimitDecorator:
    """函数级 rate_limit 装饰器。"""

    def test_allows_calls_within_limit(self):
        from ..src.rate_limiter import rate_limit, RateLimitExceeded

        call_count = 0

        @rate_limit(rate=100, burst=100, key="test_deco_1")
        def limited_func():
            nonlocal call_count
            call_count += 1

        for _ in range(5):
            limited_func()
        assert call_count == 5

    def test_exceeded_raises(self):
        from ..src.rate_limiter import rate_limit, RateLimitExceeded

        @rate_limit(rate=0.0, burst=0, key="test_deco_2")
        def never_works():
            pass

        with pytest.raises(RateLimitExceeded):
            never_works()


class TestDistributedTokenBucketFallback:
    """分布式令牌桶在 Redis 不可用时降级到本地。"""

    def test_fallback_when_no_redis(self):
        from ..src.rate_limiter import DistributedTokenBucket, REDIS_AVAILABLE
        if REDIS_AVAILABLE:
            pytest.skip("redis installed, fallback not testable in-process")

        # 即使 Redis 不可用，也应通过回退正常工作
        # 使用一个 mock redis 客户端
        class FakeRedis:
            def register_script(self, script):
                raise RuntimeError("no redis")

        fake = FakeRedis()
        tb = DistributedTokenBucket(fake, key="test", rate=10, burst=5)
        # 回退应正常工作
        assert tb.allow() is True
