"""API 调用与重试逻辑 — 集成断路器、令牌预算、自适应并发控制。"""
import time
import traceback
from typing import Optional
from parallel_deep_dev.config import CONFIG
from parallel_deep_dev.engine.prompts import build_api_messages

# 韧性层组件在模块加载时初始化（全局单例，跨 worker 共享）
_circuit_breaker = None
_token_budget = None
_adaptive_concurrency = None
_health_monitor = None


def _init_resilience():
    """延迟初始化韧性层——避免循环导入，且允许 config 被运行时修改。"""
    global _circuit_breaker, _token_budget, _adaptive_concurrency, _health_monitor
    if _circuit_breaker is not None:
        return
    if not CONFIG.RESILIENCE_ENABLED:
        return
    from parallel_deep_dev.engine.resilience import (
        CircuitBreaker, TokenBudget, AdaptiveConcurrency, CompositeHealth,
    )
    _circuit_breaker = CircuitBreaker(
        failure_threshold=CONFIG.CB_FAILURE_THRESHOLD,
        failure_rate_threshold=CONFIG.CB_FAILURE_RATE_THRESHOLD,
        cooldown_seconds=CONFIG.CB_COOLDOWN_SECONDS,
        window_seconds=CONFIG.CB_WINDOW_SECONDS,
    )
    _token_budget = TokenBudget(
        tokens_per_minute=CONFIG.TB_TOKENS_PER_MINUTE,
        tokens_per_session=CONFIG.TB_TOKENS_PER_SESSION,
    )
    _adaptive_concurrency = AdaptiveConcurrency(
        min_concurrency=CONFIG.AC_MIN_WORKERS,
        max_concurrency=CONFIG.AC_MAX_WORKERS,
        current=CONFIG.AC_INITIAL_WORKERS,
    )
    _health_monitor = CompositeHealth(
        circuit_breaker=_circuit_breaker,
        token_budget=_token_budget,
    )


def get_adaptive_workers() -> int:
    """返回自适应并发控制建议的 worker 数量。
    若禁用韧性层，回退到 CONFIG.MAX_WORKERS。"""
    _init_resilience()
    if _adaptive_concurrency is None:
        return CONFIG.MAX_WORKERS
    return _adaptive_concurrency.current


def get_health_score() -> float:
    """返回综合健康评分 0.0-1.0。1.0 = 完全健康。"""
    _init_resilience()
    if _health_monitor is None:
        return 1.0
    return _health_monitor.health_score()


def get_resilience_stats() -> dict:
    """返回韧性层统计信息，供 run.py 展示。"""
    _init_resilience()
    if _circuit_breaker is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "circuit_state": _circuit_breaker.state,
        "consecutive_failures": _circuit_breaker.consecutive_failures,
        "adaptive_workers": _adaptive_concurrency.current if _adaptive_concurrency else "N/A",
        "tokens_used_session": _token_budget.session_used() if _token_budget else 0,
        "tokens_remaining_session": _token_budget.session_remaining() if _token_budget else 0,
        "health_score": _health_monitor.health_score() if _health_monitor else 1.0,
    }


def call_api_with_retry(
    module_key: str,
    module_def: dict,
    max_retries: int | None = None,
) -> Optional[str]:
    """调用 Anthropic API，支持重试和超时。
    集成断路器：请求前检查断路器状态，成功后上报，失败后上报。
    集成令牌预算：估算 prompt + response 的 token 消耗，超限时拒绝或降级。"""
    if max_retries is None:
        max_retries = CONFIG.MAX_RETRIES

    # 韧性层延迟初始化
    _init_resilience()

    if CONFIG.DRY_RUN:
        _, user_msg = build_api_messages(module_key, module_def)
        print(f"[DRY-RUN] {module_key}: prompt 已生成 ({len(user_msg['content'])} 字符)")
        return None

    if not CONFIG.API_KEY:
        print(f"[警告] {module_key}: ANTHROPIC_API_KEY 未设置")

    # 断路器预检：跳闸时拒绝请求，避免浪费 API 配额
    if _circuit_breaker is not None:
        if not _circuit_breaker.before_request():
            print(f"[断路器] {module_key}: 断路器 OPEN，拒绝请求 (冷却中)")
            return None

    for attempt in range(max_retries + 1):
        t_start = time.time()
        try:
            import anthropic
            system_msg, user_msg = build_api_messages(module_key, module_def)

            # 令牌预算预检：估算输入 tokens（粗略：字符数/4）
            estimated_input_tokens = (
                len(system_msg["content"]) + len(user_msg["content"])
            ) // 4 + CONFIG.API_MAX_TOKENS
            if _token_budget is not None:
                if not _token_budget.consume(estimated_input_tokens):
                    remaining = _token_budget.minute_remaining()
                    print(
                        f"[令牌预算] {module_key}: 分钟配额不足 "
                        f"(需 ~{estimated_input_tokens}, 剩 {remaining}), 等待下一窗口"
                    )
                    time.sleep(15)
                    continue

            client = anthropic.Anthropic(api_key=CONFIG.API_KEY)
            response = client.messages.create(
                model=CONFIG.API_MODEL,
                max_tokens=CONFIG.API_MAX_TOKENS,
                temperature=CONFIG.API_TEMPERATURE,
                system=system_msg["content"],
                messages=[user_msg],
            )
            result_text = response.content[0].text
            latency_ms = (time.time() - t_start) * 1000

            # 上报成功到韧性层
            if _circuit_breaker is not None:
                _circuit_breaker.on_success(latency_ms)
            if _adaptive_concurrency is not None:
                _adaptive_concurrency.on_success(latency_ms, estimated_input_tokens)
            if _health_monitor is not None:
                _health_monitor.record_latency(latency_ms)

            print(f"[OK] {module_key}: API 调用成功 ({len(result_text)} 字符, {latency_ms:.0f}ms)")
            return result_text

        except anthropic.APIStatusError as e:
            latency_ms = (time.time() - t_start) * 1000
            is_rate_limit = hasattr(e, "status_code") and e.status_code == 429
            print(f"[错误] {module_key}: API 状态错误 (尝试 {attempt+1}/{max_retries+1}): {e}")
            if _circuit_breaker is not None:
                _circuit_breaker.on_failure(latency_ms)
            if _adaptive_concurrency is not None:
                _adaptive_concurrency.on_failure(latency_ms, is_rate_limit)
            if _health_monitor is not None:
                _health_monitor.record_latency(latency_ms)
            if attempt < max_retries:
                time.sleep(2 ** attempt * 5)

        except anthropic.APITimeoutError:
            latency_ms = (time.time() - t_start) * 1000
            print(f"[错误] {module_key}: API 超时 (尝试 {attempt+1}/{max_retries+1})")
            if _circuit_breaker is not None:
                _circuit_breaker.on_failure(latency_ms)
            if _adaptive_concurrency is not None:
                _adaptive_concurrency.on_failure(latency_ms, False)
            if attempt < max_retries:
                time.sleep(2 ** attempt * 10)

        except ImportError:
            print(f"[错误] {module_key}: anthropic 包未安装 — pip install anthropic")
            return None

        except Exception as ex:
            latency_ms = (time.time() - t_start) * 1000
            print(f"[错误] {module_key}: 未知错误 (尝试 {attempt+1}/{max_retries+1}): {ex}")
            traceback.print_exc()
            if _circuit_breaker is not None:
                _circuit_breaker.on_failure(latency_ms)
            if _adaptive_concurrency is not None:
                _adaptive_concurrency.on_failure(latency_ms, False)
            if attempt < max_retries:
                time.sleep(2 ** attempt * 5)

    print(f"[失败] {module_key}: 所有 {max_retries+1} 次尝试均失败")
    return None
