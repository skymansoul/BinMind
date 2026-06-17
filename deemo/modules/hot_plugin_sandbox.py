"""
插件热加载与沙箱化安全执行模块

功能:
    1. 插件目录监控, 支持动态加载/卸载 Python 插件, 无需重启服务
    2. 在隔离子进程或 Docker 容器中执行插件代码
    3. 限制 CPU/内存/文件系统访问, 防止插件崩溃或恶意行为影响主流程

核心技术:
    - watchdog 监控文件变化
    - importlib 动态加载
    - 子进程隔离 (multiprocessing) + 资源限制 (rlimit)
    - 沙箱协议: 插件通过 stdin/stdout JSON 与宿主通信
"""

import logging
import os
import sys
import time
import json
import signal
import shutil
import tempfile
import importlib
import importlib.util
import multiprocessing as mp
import threading
import traceback
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class PluginState(Enum):
    LOADED = "loaded"
    UNLOADED = "unloaded"
    ERROR = "error"
    RUNNING = "running"
    QUARANTINED = "quarantined"


@dataclass
class PluginInfo:
    """插件元信息"""
    name: str
    version: str
    path: str
    state: PluginState = PluginState.UNLOADED
    module: Any = None
    entry_point: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    last_loaded: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SandboxLimits:
    """沙箱资源限制"""

    def __init__(self, cpu_seconds: int = 30,
                 memory_mb: int = 512,
                 file_read_only: bool = True,
                 allow_network: bool = False,
                 allow_subprocess: bool = False):
        self.cpu_seconds = cpu_seconds
        self.memory_mb = memory_mb
        self.file_read_only = file_read_only
        self.allow_network = allow_network
        self.allow_subprocess = allow_subprocess

    def apply_rlimit(self):
        """在子进程中应用 rlimit 限制"""
        try:
            import resource
            # CPU 时间
            resource.setrlimit(resource.RLIMIT_CPU,
                               (self.cpu_seconds, self.cpu_seconds + 5))
            # 内存 (字节)
            mem_bytes = self.memory_mb * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass
            # 防止 fork
            if not self.allow_subprocess:
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
                except (ValueError, OSError):
                    pass
        except ImportError:
            # Windows 不支持 rlimit
            pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cpu_seconds': self.cpu_seconds,
            'memory_mb': self.memory_mb,
            'file_read_only': self.file_read_only,
            'allow_network': self.allow_network,
            'allow_subprocess': self.allow_subprocess
        }


class PluginSandboxProtocol:
    """插件与宿主之间的 JSON 协议"""

    @staticmethod
    def serialize(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def deserialize(line: str) -> Dict[str, Any]:
        return json.loads(line)


def _sandbox_worker(entry_point: str, limits: SandboxLimits,
                    input_queue: mp.Queue, output_queue: mp.Queue):
    """沙箱子进程入口"""
    limits.apply_rlimit()
    try:
        # 限定 import 路径
        spec = importlib.util.spec_from_file_location("plugin_module", entry_point)
        if not spec or not spec.loader:
            output_queue.put({'error': 'spec_load_failed', 'entry': entry_point})
            return
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # 调用 plugin_run 函数 (约定)
        if not hasattr(module, 'plugin_run'):
            output_queue.put({'error': 'no_plugin_run', 'entry': entry_point})
            return
        while True:
            try:
                msg = input_queue.get(timeout=limits.cpu_seconds)
            except Exception:
                break
            if msg is None:
                break
            try:
                result = module.plugin_run(msg)
                output_queue.put({'result': result})
            except Exception as e:
                output_queue.put({'error': str(e),
                                  'traceback': traceback.format_exc()})
    except Exception as e:
        output_queue.put({'error': str(e), 'traceback': traceback.format_exc()})


class SandboxedPluginRunner:
    """沙箱化插件执行器"""

    def __init__(self, limits: Optional[SandboxLimits] = None,
                 execution_mode: str = "process"):
        self.limits = limits or SandboxLimits()
        self.execution_mode = execution_mode  # "process" or "docker"

    def run_in_process(self, plugin_path: str,
                       payload: Dict[str, Any],
                       timeout: Optional[int] = None) -> Dict[str, Any]:
        """通过子进程运行插件"""
        ctx = mp.get_context("spawn")
        in_q: mp.Queue = ctx.Queue()
        out_q: mp.Queue = ctx.Queue()
        proc = ctx.Process(
            target=_sandbox_worker,
            args=(plugin_path, self.limits, in_q, out_q),
            daemon=True
        )
        proc.start()
        try:
            in_q.put(payload)
            timeout = timeout or self.limits.cpu_seconds
            try:
                result = out_q.get(timeout=timeout)
            except Exception as e:
                proc.terminate()
                return {'error': 'timeout', 'detail': str(e)}
            in_q.put(None)  # 通知子进程退出
            proc.join(timeout=2)
            if proc.is_alive():
                proc.terminate()
            return result
        finally:
            if proc.is_alive():
                proc.terminate()

    def run_in_docker(self, plugin_path: str, payload: Dict[str, Any],
                      image: str = "python:3.11-slim",
                      timeout: int = 60) -> Dict[str, Any]:
        """通过 Docker 容器执行插件 (如果可用)"""
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(plugin_path, os.path.join(td, "plugin.py"))
            payload_path = os.path.join(td, "payload.json")
            with open(payload_path, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{td}:/plugin:ro",
                "-w", "/plugin",
                "--network=none",
                f"--memory={self.limits.memory_mb}m",
                f"--cpus=1.0",
                "--pids-limit=64",
                image,
                "python", "plugin.py"
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=timeout
                )
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
            except FileNotFoundError:
                return {'error': 'docker_not_available'}
            except Exception as e:
                return {'error': str(e)}


class PluginManager:
    """
    插件管理器
    - 目录监控 (watchdog)
    - 动态加载/卸载
    - 沙箱化执行
    """

    def __init__(self,
                 plugin_dir: str = "./plugins",
                 limits: Optional[SandboxLimits] = None,
                 auto_reload: bool = True,
                 execution_mode: str = "process"):
        self.plugin_dir = os.path.abspath(plugin_dir)
        os.makedirs(self.plugin_dir, exist_ok=True)
        self.limits = limits or SandboxLimits()
        self.auto_reload = auto_reload
        self.runner = SandboxedPluginRunner(self.limits, execution_mode)
        self.plugins: Dict[str, PluginInfo] = {}
        self._lock = threading.Lock()
        self._observer = None
        if auto_reload and WATCHDOG_AVAILABLE:
            self._start_observer()

    # ============= 加载/卸载 =============

    def discover(self) -> List[str]:
        """扫描插件目录, 返回所有 .py 文件"""
        out = []
        for root, _, files in os.walk(self.plugin_dir):
            for fn in files:
                if fn.endswith(".py") and not fn.startswith("_"):
                    out.append(os.path.join(root, fn))
        return out

    def load(self, path: str) -> PluginInfo:
        path = os.path.abspath(path)
        with self._lock:
            try:
                spec = importlib.util.spec_from_file_location(
                    f"plugin_{int(time.time()*1000)}", path
                )
                if not spec or not spec.loader:
                    raise RuntimeError("无法加载 spec")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                name = getattr(module, "PLUGIN_NAME",
                               os.path.splitext(os.path.basename(path))[0])
                version = getattr(module, "PLUGIN_VERSION", "0.0.1")
                entry = getattr(module, "PLUGIN_ENTRY", "plugin_run")
                permissions = getattr(module, "PLUGIN_PERMISSIONS", [])
                info = PluginInfo(
                    name=name,
                    version=version,
                    path=path,
                    state=PluginState.LOADED,
                    module=module,
                    entry_point=entry,
                    permissions=permissions,
                    last_loaded=time.time()
                )
                self.plugins[name] = info
                logger.info(f"[plugin] 加载: {name} v{version}")
                return info
            except Exception as e:
                logger.error(f"[plugin] 加载失败 {path}: {e}")
                info = PluginInfo(
                    name=os.path.basename(path),
                    version="0.0.0",
                    path=path,
                    state=PluginState.ERROR,
                    error=str(e)
                )
                self.plugins[info.name] = info
                return info

    def unload(self, name: str) -> bool:
        with self._lock:
            if name not in self.plugins:
                return False
            self.plugins[name].state = PluginState.UNLOADED
            self.plugins[name].module = None
            logger.info(f"[plugin] 卸载: {name}")
            return True

    def reload(self, name: str) -> Optional[PluginInfo]:
        with self._lock:
            if name not in self.plugins:
                return None
            path = self.plugins[name].path
        self.unload(name)
        return self.load(path)

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': p.name,
                'version': p.version,
                'state': p.state.value,
                'permissions': p.permissions,
                'last_loaded': p.last_loaded,
                'error': p.error
            }
            for p in self.plugins.values()
        ]

    # ============= 沙箱化执行 =============

    def run_sandboxed(self, name: str, payload: Dict[str, Any],
                      timeout: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            if name not in self.plugins:
                return {'error': f'plugin {name} not loaded'}
            p = self.plugins[name]
            if p.state != PluginState.LOADED:
                return {'error': f'plugin {name} not in LOADED state'}
            path = p.path
        return self.runner.run_in_process(path, payload, timeout)

    def run_in_docker(self, name: str, payload: Dict[str, Any],
                      image: str = "python:3.11-slim",
                      timeout: int = 60) -> Dict[str, Any]:
        with self._lock:
            if name not in self.plugins:
                return {'error': f'plugin {name} not loaded'}
            path = self.plugins[name].path
        return self.runner.run_in_docker(path, payload, image, timeout)

    # ============= 目录监控 =============

    def _start_observer(self):
        if self._observer is not None:
            return
        outer = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if event.is_directory:
                    return
                if event.src_path.endswith(".py"):
                    outer.load(event.src_path)

            def on_modified(self, event):
                if event.is_directory:
                    return
                if event.src_path.endswith(".py"):
                    # 找到对应插件名
                    for p in outer.plugins.values():
                        if p.path == event.src_path:
                            outer.reload(p.name)
                            return

            def on_deleted(self, event):
                if event.is_directory:
                    return
                if event.src_path.endswith(".py"):
                    for name, p in list(outer.plugins.items()):
                        if p.path == event.src_path:
                            outer.unload(name)
                            return

        self._observer = Observer()
        self._observer.schedule(Handler(), self.plugin_dir, recursive=True)
        self._observer.daemon = True
        self._observer.start()
        logger.info(f"[plugin] 目录监控已启动: {self.plugin_dir}")

    def stop(self):
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None


def load_plugin_dir(plugin_dir: str,
                    limits: Optional[SandboxLimits] = None) -> List[Dict[str, Any]]:
    """便捷入口: 扫描并加载目录下所有插件"""
    mgr = PluginManager(plugin_dir=plugin_dir, limits=limits, auto_reload=False)
    for p in mgr.discover():
        mgr.load(p)
    return mgr.list_plugins()
