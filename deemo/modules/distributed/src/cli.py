#!/usr/bin/env python3
# — 命令行入口重构
# argparse subparser dispatch was broken (NameError: subparsers).
# A distributed module without a usable entrypoint is a library, not a service.
# Each subcommand maps to a concrete subsystem; --debug/--verbose control log verbosity.
# Design choice: config loaded once at entry, passed down; avoids scattered yaml.safe_load calls.
"""distributed — comprehensive command-line interface

Subcommands:
    worker      Start a Redis-backed task worker process
    health      Run the embedded health-check HTTP server
    status      Show cluster node status and queue depths
    circuit     Inspect/reset circuit breaker state
    dlq         Dead-letter queue management (list/retry/purge)
    pool        Elastic pool control (scale/status)
    benchmark   Micro-benchmarks for rate limiter / load balancer
"""
import argparse, sys, logging, os, json, time, signal, threading
from typing import Optional, Dict, Any

__version__ = "0.2.0"
__date__    = "2025-03-28"

_log = logging.getLogger("binmind.distributed.cli")

# 脚本直接执行时置位；程序化调用 main() 时保持 False，服务类命令不进入阻塞循环
_SERVE_MODE = False


# Config helper
# YAML config is optional; all subcommands work with defaults.
# Environment variable BINMIND_DIST_CONFIG overrides --config.
def _load_config(path: Optional[str] = None) -> dict:
    """Load YAML or JSON config, falling back to env and defaults."""
    cfg_path = path or os.environ.get("BINMIND_DIST_CONFIG")
    if cfg_path and os.path.exists(cfg_path):
        try:
            import yaml
            with open(cfg_path, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        except ImportError:
            _log.warning("yaml not installed, trying json")
            with open(cfg_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            _log.warning("config load failed: %s", exc)
    return {}


# Worker subcommand
# Uses the worker.py Worker class (Redis-backed, no Celery), not the Celery one.
# rationale: keep it simple; Celery worker is started with `celery -A ... worker`.
def _cmd_worker(args: argparse.Namespace) -> int:
    """Start a Redis-backed worker process."""
    from ..worker import Worker, WorkerConfig

    cfg = _load_config(args.config)
    worker_cfg = WorkerConfig(
        redis_url=args.redis_url
        or cfg.get("redis", {}).get("url", "redis://localhost:6379/0"),
        queue=args.queue or cfg.get("redis", {}).get("queue", "binmind:tasks"),
        result_queue=args.result_queue
        or cfg.get("redis", {}).get("result_queue", "binmind:results"),
        poll_timeout=args.poll_timeout
        or cfg.get("worker", {}).get("poll_timeout", 5),
        max_retries=args.max_retries
        or cfg.get("worker", {}).get("max_retries", 3),
        max_workers=args.concurrency
        or cfg.get("worker", {}).get("max_workers", 4),
        job_timeout=args.job_timeout
        or cfg.get("worker", {}).get("job_timeout", 300),
        breaker_threshold=cfg.get("circuit_breaker", {}).get("threshold", 5),
        breaker_cooldown=cfg.get("circuit_breaker", {}).get("cooldown", 60),
        heartbeat_interval=cfg.get("worker", {}).get("heartbeat_interval", 15),
    )

    # 服务模式构造即建连；程序化调用不建连，构造阶段不进入重连等待
    worker = Worker(worker_cfg, connect=_SERVE_MODE)

    # Register built-in handler stubs if none registered externally.
    # In practice, users call worker.register_handler() before start().
    if args.handler_module:
        import importlib
        mod = importlib.import_module(args.handler_module)
        if hasattr(mod, "register_handlers"):
            mod.register_handlers(worker)

    if not _SERVE_MODE:
        # 程序化调用：仅完成 worker 构造即返回，服务由 __main__ 路径启动
        _log.info("worker constructed, serve loop deferred")
        return 0

    # Graceful shutdown: SIGTERM → stop accepting, drain inflight, exit.
    def _shutdown(sig, frame):
        _log.info("worker received signal %d, stopping", sig)
        worker.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    _log.info("starting worker %s on queue %s", worker.worker_id, worker.cfg.queue)
    worker.start()
    _log.info("worker %s exited. metrics=%s", worker.worker_id, worker.metrics)
    return 0


# Health subcommand
def _cmd_health(args: argparse.Namespace) -> int:
    """Start the health-check HTTP server."""
    from ..src.health import HealthServer

    server = HealthServer(
        host=args.bind or "0.0.0.0",
        port=args.port or 8080,
    )

    # Add default checks: process liveness + optional Redis ping.
    server.add_check("process", lambda: True)

    if args.redis_url:
        try:
            import redis
            r = redis.Redis.from_url(args.redis_url, socket_timeout=2)
            server.add_check("redis", lambda: r.ping() or True)
        except ImportError:
            _log.warning("redis-py not installed, skipping redis health check")
        except Exception:
            _log.warning("cannot connect to redis at %s", args.redis_url)

    if not _SERVE_MODE:
        # 程序化调用：构造健康检查器后即返回，监听由 __main__ 路径启动
        return 0

    server.start()
    _log.info("health server listening on %s:%d", server._host, server._port)
    _log.info("endpoints: /health /ready /metrics")

    try:
        while server.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        _log.info("shutting down health server")
    finally:
        server.stop()
    return 0


# Status subcommand
def _cmd_status(args: argparse.Namespace) -> int:
    """Query cluster status via Redis."""
    try:
        import redis as _redis
    except ImportError:
        print("redis-py not installed", file=sys.stderr)
        return 1

    redis_url = args.redis_url or "redis://localhost:6379/0"
    try:
        client = _redis.Redis.from_url(redis_url, socket_timeout=3, decode_responses=True)
        client.ping()
    except Exception as e:
        print(f"cannot connect to redis: {e}", file=sys.stderr)
        return 1

    # Gather status from multiple keys
    status: Dict[str, Any] = {"redis": redis_url, "timestamp": time.time()}

    # Worker heartbeats
    try:
        worker_ids = client.smembers("binmind:workers:active") or client.smembers("deemo:workers:active")
        workers = []
        for wid in worker_ids:
            wdata = client.hgetall(f"binmind:workers:heartbeat:{wid}") or client.hgetall(f"deemo:worker:{wid}")
            if wdata:
                workers.append({"id": wid, **wdata})
        status["workers"] = workers
        status["worker_count"] = len(workers)
    except Exception:
        status["workers"] = "unavailable"

    # Queue depths
    try:
        status["queue_depth"] = client.llen(args.queue or "binmind:tasks")
        status["dlq_depth"] = client.llen((args.queue or "binmind:tasks") + ":dlq")
    except Exception:
        status["queue_depth"] = -1

    # Circuit breaker state
    try:
        raw = client.hgetall("binmind:circuit_breakers")
        status["circuit_breakers"] = raw if raw else "no breakers"
    except Exception:
        status["circuit_breakers"] = "unavailable"

    if args.format == "json":
        print(json.dumps(status, indent=2, default=str))
    else:
        print(f"=== BinMind Distributed Status ===")
        print(f"Redis:       {redis_url}")
        print(f"Workers:     {status.get('worker_count', '?')}")
        print(f"Queue depth: {status.get('queue_depth', '?')}")
        print(f"DLQ depth:   {status.get('dlq_depth', '?')}")
        for w in status.get("workers", []):
            print(f"  {w.get('id', w.get('worker_id', '?'))} [{w.get('status', '?')}]")

    return 0


# Circuit subcommand
def _cmd_circuit(args: argparse.Namespace) -> int:
    """Inspect or reset circuit breaker state."""
    from ..src.circuit_breaker import CircuitBreaker, CircuitState, MultiBreaker

    # Use an in-process MultiBreaker for inspection
    mb = MultiBreaker()
    if args.name:
        cb = mb.get(args.name)
        if args.reset:
            cb._failures = 0
            cb._state = CircuitState.CLOSED
            print(f"Circuit breaker '{args.name}' reset to CLOSED")
        else:
            state = cb.to_dict()
            if args.format == "json":
                print(json.dumps(state, indent=2))
            else:
                print(f"Breaker: {state['name']} state={state['state']} "
                      f"failures={state['failures']}/{state['threshold']} "
                      f"cooldown={state['cooldown']}s")
    else:
        print("specify --name for a breaker to inspect/reset")
    return 0


# DLQ subcommand
def _cmd_dlq(args: argparse.Namespace) -> int:
    """Dead-letter queue management."""
    try:
        import redis as _redis
    except ImportError:
        print("redis-py not installed", file=sys.stderr)
        return 1

    redis_url = args.redis_url or "redis://localhost:6379/0"
    queue = args.queue or "binmind:tasks"
    dlq_key = f"{queue}:dlq"
    try:
        client = _redis.Redis.from_url(redis_url, socket_timeout=3, decode_responses=True)
    except Exception as e:
        print(f"cannot connect to redis: {e}", file=sys.stderr)
        return 1

    if args.purge:
        deleted = client.delete(dlq_key)
        print(f"Purged DLQ: {deleted} entries removed")
        return 0

    if args.retry_all:
        count = 0
        while True:
            raw = client.lpop(dlq_key)
            if raw is None:
                break
            try:
                entry = json.loads(raw)
                job = entry.get("job", entry)
                client.rpush(queue, json.dumps(job))
                count += 1
            except Exception:
                client.rpush(dlq_key, raw)  # preserve malformed entries
                break
        print(f"Re-queued {count} DLQ entries back to {queue}")
        return 0

    # Default: list
    limit = args.limit or 20
    items = client.lrange(dlq_key, -limit, -1)
    if args.format == "json":
        parsed = [json.loads(i) for i in items]
        print(json.dumps(parsed, indent=2, default=str))
    else:
        print(f"DLQ ({dlq_key}): {len(items)} items (showing last {limit})")
        for i, raw in enumerate(reversed(items), 1):
            try:
                entry = json.loads(raw)
                job = entry.get("job", entry)
                reason = entry.get("reason", "?")
                print(f"  {i}. {job.get('id', job.get('job_id', '?'))} "
                      f"type={job.get('type', job.get('analysis_type', '?'))} "
                      f"reason={reason}")
            except Exception:
                print(f"  {i}. (malformed: {raw[:80]})")
    return 0


# Pool subcommand
def _cmd_pool(args: argparse.Namespace) -> int:
    """Elastic pool control."""
    from ..src.elastic_pool import ElasticPool, ThresholdScalePolicy
    import random

    # Use a simple policy with mock-metrics: random queue depth for demo.
    # In production, metrics_provider would query Redis LLEN.
    def _mock_metrics() -> dict:
        return {"queue_depth": random.randint(0, 30), "active_workers": pool.active_workers}

    pool = ElasticPool(
        metrics_provider=_mock_metrics,
        policy=ThresholdScalePolicy(
            min_workers=args.min_workers or 1,
            max_workers=args.max_workers or 16,
            scale_up_threshold=args.scale_up_threshold or 5.0,
            scale_down_threshold=args.scale_down_threshold or 1.0,
        ),
        interval=args.interval or 2.0,
    )

    if not _SERVE_MODE:
        # 程序化调用：完成池构造后即返回，扩容循环由 __main__ 路径启动
        return 0

    pool.start()
    _log.info("pool started at %d workers", pool.active_workers)

    try:
        for _ in range(args.ticks or 10):
            time.sleep(pool._interval)
            st = pool.state
            print(f"tick: workers={st['active_workers']}, "
                  f"queue_history={st['queue_history_len']}")
    except KeyboardInterrupt:
        pass
    finally:
        pool.stop()
        _log.info("pool stopped")
    return 0


# Benchmark subcommand
def _cmd_benchmark(args: argparse.Namespace) -> int:
    """Micro-benchmarks for distributed components."""
    from ..src.rate_limiter import TokenBucket
    from ..src.load_balancer import LoadBalancer, SelectorNode
    from ..src.circuit_breaker import CircuitBreaker

    results = {}
    iterations = args.iterations or 1000

    # Token bucket throughput
    tb = TokenBucket(rate=1000, burst=1000)
    t0 = time.monotonic()
    allowed = 0
    for _ in range(iterations):
        if tb.allow():
            allowed += 1
    elapsed = time.monotonic() - t0
    results["token_bucket"] = {
        "allowed": allowed,
        "total": iterations,
        "rate": allowed / elapsed if elapsed else 0,
        "elapsed_s": round(elapsed, 4),
    }

    # Load balancer selection speed
    lb = LoadBalancer("round_robin")
    nodes = [SelectorNode(id=f"n{i}", weight=i % 3 + 1) for i in range(10)]
    t0 = time.monotonic()
    for _ in range(iterations):
        lb.select(nodes)
    elapsed = time.monotonic() - t0
    results["load_balancer"] = {
        "ops": iterations,
        "ops_per_sec": iterations / elapsed if elapsed else 0,
        "elapsed_s": round(elapsed, 4),
    }

    # Circuit breaker state transitions
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)
    for _ in range(3):
        cb.on_failure()
    # breaker should be OPEN
    results["circuit_breaker"] = {
        "state_after_failures": cb.state.value,
        "allows_call": cb.before_call(),
    }

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for name, r in results.items():
            print(f"\n--- {name} ---")
            for k, v in r.items():
                print(f"  {k}: {v}")
    return 0


# Main entry
def main(argv: Optional[list] = None) -> int:
    """Primary CLI entry point. Returns exit code."""
    p = argparse.ArgumentParser(
        prog="binmind-distributed",
        description=f"BinMind Distributed Task System v{__version__} ({__date__})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", "-c", default=None,
                   help="Path to YAML/JSON config file (env: BINMIND_DIST_CONFIG)")
    p.add_argument("--redis-url", default=None,
                   help="Redis connection URL (overrides config)")
    p.add_argument("--queue", "-q", default=None,
                   help="Queue name (overrides config)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable INFO-level logging")
    p.add_argument("--debug", action="store_true",
                   help="Enable DEBUG-level logging")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Output format (default: text)")

# subcommands
    sp = p.add_subparsers(dest="command", help="Available subcommands")
    sp.required = False  # argparse 3.8+ required; let manual check handle older versions

    # worker
    wp = sp.add_parser("worker", help="Start a Redis-backed task worker")
    wp.add_argument("--concurrency", type=int, default=None,
                    help="Max concurrent task threads (default: 4)")
    wp.add_argument("--redis-url", default=None,
                    help="Redis connection URL (overrides config)")
    wp.add_argument("--queue", "-q", default=None,
                    help="Queue name (overrides config)")
    wp.add_argument("--result-queue", default=None,
                    help="Result queue name")
    wp.add_argument("--poll-timeout", type=int, default=None,
                    help="BLPOP timeout in seconds (default: 5)")
    wp.add_argument("--max-retries", type=int, default=None,
                    help="Max retry attempts (default: 3)")
    wp.add_argument("--job-timeout", type=int, default=None,
                    help="Per-job execution timeout (default: 300)")
    wp.add_argument("--handler-module", default=None,
                    help="Python module with register_handlers(worker) function")

    # health
    hp = sp.add_parser("health", help="Start health-check HTTP server")
    hp.add_argument("--port", "-p", type=int, default=None,
                    help="Listen port (default: 8080)")
    hp.add_argument("--bind", default=None,
                    help="Bind address (default: 0.0.0.0)")

    # status
    stp = sp.add_parser("status", help="Show cluster status")
    stp.add_argument("--queue", "-q", default=None,
                     help="Queue to inspect (default: binmind:tasks)")
    stp.add_argument("--format", choices=["text", "json"], default="text",
                     help="Output format (default: text)")

    # circuit
    cp = sp.add_parser("circuit", help="Inspect/reset circuit breakers")
    cp.add_argument("--name", default=None,
                    help="Breaker name to inspect")
    cp.add_argument("--reset", action="store_true",
                    help="Reset the named breaker to CLOSED")

    # dlq
    dp = sp.add_parser("dlq", help="Dead-letter queue management")
    dp.add_argument("--limit", type=int, default=None,
                    help="Number of DLQ entries to list (default: 20)")
    dp.add_argument("--retry-all", action="store_true",
                    help="Re-queue all DLQ entries back to the work queue")
    dp.add_argument("--purge", action="store_true",
                    help="Delete all DLQ entries irreversibly")

    # pool
    pop = sp.add_parser("pool", help="Elastic pool control")
    pop.add_argument("--min-workers", type=int, default=None)
    pop.add_argument("--max-workers", type=int, default=None)
    pop.add_argument("--scale-up-threshold", type=float, default=None)
    pop.add_argument("--scale-down-threshold", type=float, default=None)
    pop.add_argument("--interval", type=float, default=None,
                     help="Tick interval in seconds (default: 2.0)")
    pop.add_argument("--ticks", type=int, default=None,
                     help="Number of ticks to run (default: 10)")

    # benchmark
    bp = sp.add_parser("benchmark", help="Run micro-benchmarks")
    bp.add_argument("--iterations", type=int, default=None,
                    help="Iteration count (default: 1000)")

# parse and dispatch
    try:
        a = p.parse_args(argv)
    except SystemExit:
        # 未知子命令/非法参数：统一收敛为退出码 1，交由调用方处理
        return 1

    # Logging
    if a.debug:
        logging.basicConfig(level=logging.DEBUG,
                           format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    elif a.verbose:
        logging.basicConfig(level=logging.INFO,
                           format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not a.command:
        p.print_help()
        return 1

    _log.info("dispatching command: %s", a.command)

    dispatch = {
        "worker":    _cmd_worker,
        "health":    _cmd_health,
        "status":    _cmd_status,
        "circuit":   _cmd_circuit,
        "dlq":       _cmd_dlq,
        "pool":      _cmd_pool,
        "benchmark": _cmd_benchmark,
    }

    handler = dispatch.get(a.command)
    if handler is None:
        print(f"Unknown command: {a.command}", file=sys.stderr)
        return 1

    try:
        return handler(a)
    except KeyboardInterrupt:
        _log.info("interrupted")
        return 130
    except Exception as exc:
        _log.exception("command '%s' failed: %s", a.command, exc)
        return 1


if __name__ == "__main__":
    _SERVE_MODE = True
    sys.exit(main())
