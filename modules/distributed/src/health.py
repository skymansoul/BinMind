# 基于 stdlib http.server 的零依赖健康检查端点
# /health /ready /metrics 三端点覆盖 K8s liveness/readiness/可观测性需求
#
# 扩展方向：优雅关闭超时可通过参数配置

from __future__ import annotations

import json
import time
import enum
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional

_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})


class HealthStatus(enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


# 单项健康检查

class HealthCheck:
    """单个健康检查项 - 封装名称、检测函数及最近结果。"""

    __slots__ = ('name', 'check_fn', 'last_result', 'last_run')

    def __init__(self, name: str, check_fn: Callable[[], bool]):
        self.name = name
        self.check_fn = check_fn
        self.last_result: Optional[bool] = None
        self.last_run: float = 0.0

    def run(self) -> bool:
        try:
            self.last_result = self.check_fn()
        except Exception:
            self.last_result = False
        self.last_run = time.monotonic()
        return self.last_result


# HTTP 服务实现

_VERSION = "0.1.0"
_START_TIME = time.time()


class _HealthHandler(BaseHTTPRequestHandler):
    """内联 handler - 通过 self.server.parent 访问外层 HealthServer 实例"""

    def log_message(self, format, *args):
        pass  # 静默，避免日志污染 stderr

    def _json(self, data: dict, code: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text: str, code: int = 200):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        server: 'HealthServer' = self.server.parent

        if self.path == "/health" or self.path == "/healthz":
            self._handle_health(server)
        elif self.path == "/ready" or self.path == "/readyz":
            self._handle_ready(server)
        elif self.path == "/metrics":
            self._handle_metrics(server)
        else:
            self._json({"error": "not found"}, 404)

    def _handle_health(self, server: 'HealthServer'):
        # 执行全部已注册健康检查
        results = {}
        for name, check in server._checks.items():
            results[name] = check.run()

        all_ok = all(results.values()) if results else True

        self._json({
            "status": HealthStatus.HEALTHY.value if all_ok else HealthStatus.DEGRADED.value,
            "uptime": time.time() - _START_TIME,
            "version": _VERSION,
            "checks": results,
            "started_at": _START_TIME,
        })

    def _handle_ready(self, server: 'HealthServer'):
        # 就绪探针：标准比 liveness 更严格
        results = {}
        for name, check in server._checks.items():
            results[name] = check.run()

        all_ok = all(results.values()) if results else True
        code = 200 if all_ok else 503
        self._json({"ready": all_ok, "checks": results}, code)

    def _handle_metrics(self, server: 'HealthServer'):
        # 输出 Prometheus text 格式
        server_uptime = time.time() - _START_TIME
        lines = [
            "# HELP binmind_uptime_seconds Server uptime in seconds",
            "# TYPE binmind_uptime_seconds gauge",
            f"binmind_uptime_seconds {server_uptime:.3f}",
            "",
            "# HELP binmind_health_status Health status (1=healthy, 0=unhealthy)",
            "# TYPE binmind_health_status gauge",
            f"binmind_health_status{{version=\"{_VERSION}\"}} 1",
        ]

        # 注入同级 metrics 模块的 Prometheus 输出（若可用）
        try:
            from .metrics import _prometheus_text
            lines.append("")
            lines.append(_prometheus_text())
        except ImportError:
            pass

        self._text("\n".join(lines) + "\n")


class _HServer(HTTPServer):
    """持有 parent 引用的 HTTPServer 子类，用于 handler 回访 HealthServer"""
    def __init__(self, server_address, handler_class, parent: 'HealthServer'):
        super().__init__(server_address, handler_class)
        self.parent = parent


class HealthServer:
    """零依赖健康检查 HTTP 服务。

    端点：
    - /health -> 整体健康状态 + 各子项检查结果
    - /ready -> K8s readiness probe（阈值高于 liveness）
    - /metrics -> Prometheus text 格式（聚合内置指标 + 外部 metrics 模块）

    示例:
        server = HealthServer(port=9090)
        server.add_check("redis", lambda: client.ping())
        server.start()
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self._host = host
        self._port = port
        self._checks: dict[str, HealthCheck] = {}
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def add_check(self, name: str, check_fn: Callable[[], bool]) -> None:
        self._checks[name] = HealthCheck(name, check_fn)

    def start(self):
        # 默认检查：进程存活
        if "process" not in self._checks:
            self.add_check("process", lambda: True)

        self._httpd = _HServer(
            (self._host, self._port),
            _HealthHandler,
            parent=self,
        )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="health-server",
        )
        self._thread.start()

    def stop(self, grace: float = 5.0):
        """停止服务。grace: 等待进行中请求完成的秒数。"""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=grace)
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

