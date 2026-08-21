# 沙箱编排 —— 多后端统一接口，自动选择最优执行环境
# 设计思路：Docker 优先（隔离性好），QEMU 次之（全系统模拟）
# Process 兜底（轻量但隔离弱），Windows 沙箱 仅 Windows 下可用
# 同时提供面向测试/工具的轻量 ProcessSandboxDriver 驱动接口

import os
import sys
import time
import json
import shutil
import signal
import glob as globmod
import logging
import platform
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from io import BytesIO

import subprocess

_log = logging.getLogger(__name__)


# 后端枚举与资源/网络/状态模型

class SandboxBackend(Enum):
    """沙箱后端枚举"""
    DOCKER = "docker"
    QEMU = "qemu"
    PROCESS = "process"
    WINDOWS = "windows_sandbox"


class NetworkMode(Enum):
    """网络模式枚举"""
    NONE = "none"
    NAT = "nat"
    BRIDGE = "bridge"
    HOST = "host"


class SandboxState(Enum):
    """沙箱生命周期状态"""
    UNINITIALIZED = "uninitialized"
    CONFIGURED = "configured"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ResourceLimits:
    """进程资源限制"""
    cpu_count: float = 1.0
    memory_mb: int = 512
    timeout_seconds: int = 300
    max_processes: int = 1
    no_new_privileges: bool = True


# 配置与结果数据类

@dataclass
class SandboxConfig:
    """一次沙箱执行的完整配置。

    兼容两种构造方式：
      - backend/resources/network 面向驱动接口
      - image/executable_path/memory_limit 等保留给 Docker/QEMU 后端
    """
    backend: SandboxBackend = SandboxBackend.DOCKER
    resources: Optional[ResourceLimits] = None
    network: NetworkMode = NetworkMode.NAT
    enable_telemetry: bool = True
    image: Optional[str] = None          # Docker 镜像 或 QEMU 磁盘镜像路径
    executable_path: Optional[str] = None
    timeout: int = 60
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    network_enabled: bool = False
    volume_mounts: Dict[str, str] = field(default_factory=dict)
    env_vars: Dict[str, str] = field(default_factory=dict)
    working_dir: str = "/tmp"
    capture_stdout: bool = True
    capture_stderr: bool = True
    artifact_paths: List[str] = field(default_factory=list)

    @property
    def resource_limits(self) -> ResourceLimits:
        """返回资源限制对象；未显式设置时从 memory_limit 推导。"""
        if self.resources is not None:
            return self.resources
        return ResourceLimits(
            memory_mb=_parse_memory_mb(self.memory_limit),
            timeout_seconds=self.timeout,
        )

    def to_docker_kwargs(self) -> List[str]:
        """生成 docker run 附加参数"""
        args: List[str] = []
        # 内存限制
        args += ["--memory", self.memory_limit]
        # CPU 限制: --cpus 支持浮点数
        if self.cpu_limit > 0:
            args += ["--cpus", str(self.cpu_limit)]
        # 网络
        if not self.network_enabled:
            args.append("--network=none")
        # 卷挂载
        for host_path, container_path in self.volume_mounts.items():
            args += ["-v", f"{os.path.abspath(host_path)}:{container_path}"]
        # 环境变量
        for k, v in self.env_vars.items():
            args += ["-e", f"{k}={v}"]
        # 工作目录
        args += ["-w", self.working_dir]
        return args


def _parse_memory_mb(raw: str) -> int:
    """将内存限制字符串解析为 MB 数值。"""
    if not raw:
        return 512
    s = str(raw).lower().strip()
    try:
        if s.endswith("g"):
            return int(float(s[:-1]) * 1024)
        if s.endswith("k"):
            return max(1, int(float(s[:-1]) / 1024))
        if s.endswith("m"):
            return int(float(s[:-1]))
        return int(float(s))
    except (ValueError, TypeError):
        return 512


@dataclass
class SandboxResult:
    """单次沙箱执行结果"""
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    artifacts: Dict[str, bytes] = field(default_factory=dict)
    duration: float = 0.0
    backend_used: str = ""

    @property
    def success(self) -> bool:
        """执行是否成功：返回码为 0 且未超时。"""
        return self.returncode == 0

    @property
    def error(self) -> str:
        """错误描述 —— 超时或非零返回码时提供可读信息。"""
        if self.returncode == -1 and 'timeout' in self.stderr.lower():
            return f"Timed out: {self.stderr}"
        return self.stderr

    @property
    def exit_code(self) -> int:
        """退出码别名。"""
        return self.returncode


# 抽象驱动器（保留原接口）

class SandboxDriver(ABC):
    @abstractmethod
    def setup(self, config: SandboxConfig) -> bool: ...

    @abstractmethod
    def run(self, command: str, config: SandboxConfig) -> SandboxResult: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]: ...

    @abstractmethod
    def cleanup(self) -> None: ...


# 轻量进程驱动 —— 面向直接调用的 start/execute/stop 接口

class ProcessSandboxDriver:
    """基于子进程的轻量沙箱驱动。

    生命周期：start() → execute(cmd[, stdin_data]) → stop()。
    与 SandboxOrchestrator 配合时由编排器统一管理状态。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config if config is not None else SandboxConfig(
            backend=SandboxBackend.PROCESS)
        self.backend = SandboxBackend.PROCESS
        self.state = SandboxState.UNINITIALIZED
        self._proc: Optional[subprocess.Popen] = None
        self._execution_count = 0
        self._success_count = 0

    def start(self) -> None:
        """进入运行状态。"""
        self.state = SandboxState.RUNNING

    def stop(self) -> None:
        """终止当前子进程并进入停止状态。"""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._proc = None
        self.state = SandboxState.STOPPED

    def execute(self, command: List[str],
                stdin_data: Optional[bytes] = None) -> SandboxResult:
        """执行命令并捕获输出。

        参数: command 命令行参数列表, stdin_data 可选标准输入
        字节流; 返回 SandboxResult, 调用方通过
        success/exit_code/stderr 判定。
        """
        if self.state != SandboxState.RUNNING:
            return SandboxResult(
                stderr="Sandbox not running",
                returncode=-1, backend_used="process")
        limits = self.config.resource_limits
        timeout = limits.timeout_seconds
        t0 = time.perf_counter()
        try:
            self._proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=True,
            )
            out, err = self._proc.communicate(input=stdin_data, timeout=timeout)
            rc = self._proc.returncode if self._proc.returncode is not None else -1
            self._execution_count += 1
            if rc == 0:
                self._success_count += 1
            return SandboxResult(
                stdout=out.decode(errors='replace') if out else "",
                stderr=err.decode(errors='replace') if err else "",
                returncode=rc,
                duration=round(time.perf_counter() - t0, 3),
                backend_used="process",
            )
        except subprocess.TimeoutExpired:
            self.stop()
            self._execution_count += 1
            return SandboxResult(
                stderr="Timed out",
                returncode=-1,
                duration=round(time.perf_counter() - t0, 3),
                backend_used="process",
            )
        except Exception as exc:
            self._execution_count += 1
            return SandboxResult(
                stderr=str(exc),
                returncode=-1,
                backend_used="process",
            )

    def get_summary(self) -> Dict[str, Any]:
        """输出执行统计。"""
        return {
            'total_executions': self._execution_count,
            'successful': self._success_count,
            'state': self.state,
        }


# Docker 沙箱（保留原实现）

class DockerSandbox(SandboxDriver):
    """
    Docker 容器沙箱 —— 最常用的后端
    完整实现：拉镜像、创建容器、执行、收集产物、清理
    """

    def __init__(self):
        self._container_id: Optional[str] = None
        self._image_pulled: bool = False
        self._active_config: Optional[SandboxConfig] = None

    @staticmethod
    def _docker_available() -> bool:
        """检查 docker CLI 是否可调用"""
        try:
            r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _ensure_image(self, image: str) -> bool:
        # inspect 本地 image
        r = subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True, text=True)
        if r.returncode == 0:
            self._image_pulled = True
            return True
        # 本地没有就 pull
        _log.info("拉取镜像 %s ...", image)
        r = subprocess.run(["docker", "pull", image], check=False)
        if r.returncode != 0:
            _log.error("拉取镜像失败 %s", image)
            return False
        self._image_pulled = True
        return True

    def setup(self, config: SandboxConfig) -> bool:
        self._active_config = config
        if not config.image:
            _log.error("Docker 后端需要指定镜像")
            return False
        if not self._ensure_image(config.image):
            return False

        # 创建容器（不启动），用 cat 保持存活
        base_args = ["docker", "create"]
        base_args += config.to_docker_kwargs()
        base_args += ["--name", self._random_name()]
        base_args += ["--entrypoint", "cat"]
        base_args.append(config.image)
        r = subprocess.run(base_args, capture_output=True, text=True)
        if r.returncode != 0:
            _log.error("docker create 失败: %s", r.stderr.strip())
            return False
        self._container_id = r.stdout.strip()[:12]
        # 启动容器让守护进程运行
        subprocess.run(["docker", "start", self._container_id], check=False, capture_output=True)
        return True

    def run(self, command: str, config: SandboxConfig) -> SandboxResult:
        t0 = time.perf_counter()
        if not self._container_id:
            if not self.setup(config):
                return SandboxResult(stderr="setup failed", returncode=-1, backend_used="docker")
        exec_args = ["docker", "exec", "-i"]
        if config.working_dir:
            exec_args += ["-w", config.working_dir]
        for k, v in config.env_vars.items():
            exec_args += ["-e", f"{k}={v}"]
        exec_args.append(self._container_id)
        shell_cmd = f"timeout {config.timeout} sh -c {_shlex_join([command])}"
        exec_args += ["sh", "-c", shell_cmd]
        try:
            r = subprocess.run(exec_args, capture_output=True, text=True,
                              timeout=config.timeout + 5)
        except subprocess.TimeoutExpired:
            self.stop()
            elapsed = time.perf_counter() - t0
            return SandboxResult(stdout="", stderr="timeout", returncode=-1,
                                duration=elapsed, backend_used="docker")
        elapsed = time.perf_counter() - t0
        return SandboxResult(
            stdout=r.stdout, stderr=r.stderr, returncode=r.returncode,
            duration=elapsed, backend_used="docker"
        )

    def stop(self) -> None:
        if self._container_id:
            subprocess.run(["docker", "stop", "-t", "3", self._container_id],
                          capture_output=True, check=False)

    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]:
        artifacts: Dict[str, bytes] = {}
        if not self._container_id:
            return artifacts
        for pattern in config.artifact_paths:
            find_args = ["docker", "exec", self._container_id,
                        "find", "/", "-path", pattern, "-type", "f"]
            r = subprocess.run(find_args, capture_output=True, text=True)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                tmp = tempfile.mktemp()
                subprocess.run(["docker", "cp",
                               f"{self._container_id}:{line}", tmp],
                              check=False, capture_output=True)
                if os.path.isfile(tmp):
                    with open(tmp, "rb") as fh:
                        artifacts[line] = fh.read()
                    os.unlink(tmp)
        return artifacts

    def cleanup(self) -> None:
        cid = self._container_id
        if cid:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)
        self._container_id = None
        self._image_pulled = False

    @staticmethod
    def _random_name() -> str:
        import random, string
        return "sandbox-" + "".join(random.choices(string.ascii_lowercase, k=8))


# QEMU 沙箱（保留原实现）

class QemuSandbox(SandboxDriver):
    """
    QEMU 全系统模拟沙箱
    用于固件、嵌入式二进制等无法在容器中运行的场景
    """

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._disk_path: Optional[str] = None
        self._pid: Optional[int] = None

    @staticmethod
    def _qemu_available() -> bool:
        for arch in ["x86_64", "i386", "arm", "aarch64"]:
            if shutil.which(f"qemu-system-{arch}"):
                return True
        return False

    def _create_temp_disk(self, size_mb: int = 512) -> str:
        path = tempfile.mktemp(suffix=".qcow2")
        subprocess.run(["qemu-img", "create", "-f", "qcow2", path, f"{size_mb}M"],
                      check=True, capture_output=True)
        return path

    def setup(self, config: SandboxConfig) -> bool:
        self._disk_path = self._create_temp_disk()
        _log.info("QEMU 磁盘镜像: %s", self._disk_path)
        return True

    def run(self, command: str, config: SandboxConfig) -> SandboxResult:
        t0 = time.perf_counter()
        qemu = shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-i386") or "qemu-system-x86_64"
        qargs = [
            qemu,
            "-kernel", config.executable_path or config.image or "",
            "-nographic",
            "-m", config.memory_limit.replace("m", "M").replace("g", "G"),
            "-drive", f"file={self._disk_path},format=qcow2,if=virtio",
            "-append", f"console=ttyS0 init=/bin/sh -- -c {_shlex_join([command])}",
        ]
        if not config.network_enabled:
            qargs.append("-nic")
            qargs.append("none")
        try:
            self._proc = subprocess.Popen(
                qargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True
            )
            self._pid = self._proc.pid
            out, err = self._proc.communicate(timeout=config.timeout)
            rc = self._proc.returncode if self._proc.returncode is not None else -1
        except subprocess.TimeoutExpired:
            self.stop()
            elapsed = time.perf_counter() - t0
            return SandboxResult(stderr="qemu timeout", returncode=-1,
                                duration=elapsed, backend_used="qemu")
        elapsed = time.perf_counter() - t0
        return SandboxResult(
            stdout=out or "", stderr=err or "", returncode=rc,
            duration=elapsed, backend_used="qemu"
        )

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._proc = None

    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]:
        artifacts: Dict[str, bytes] = {}
        if not self._disk_path or not os.path.exists(self._disk_path):
            return artifacts
        raw_path = tempfile.mktemp(suffix=".raw")
        subprocess.run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw",
                       self._disk_path, raw_path], check=False, capture_output=True)
        if os.path.exists(raw_path):
            with open(raw_path, "rb") as fh:
                for pat in config.artifact_paths:
                    artifacts[f"disk:/{pat}"] = fh.read(4096)
            os.unlink(raw_path)
        return artifacts

    def cleanup(self) -> None:
        self.stop()
        if self._disk_path and os.path.exists(self._disk_path):
            os.unlink(self._disk_path)
        self._disk_path = None


# Windows 沙箱（保留原实现）

class WindowsSandbox(SandboxDriver):
    """
    Windows Sandbox 集成 —— 生成.wsb 配置文件并启动
    仅 Windows 10 Pro/Enterprise (构建 18362+) 可用
    """

    def __init__(self):
        self._wsb_path: Optional[str] = None
        self._shared_folder: Optional[str] = None
        self._mapped_drive: str = "C:\\wsb_share"

    @staticmethod
    def _wsb_available() -> bool:
        if sys.platform != "win32":
            return False
        wsb_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "System32", "WindowsSandbox.exe")
        return os.path.isfile(wsb_exe)

    def _write_wsb_config(self, config: SandboxConfig) -> str:
        self._shared_folder = tempfile.mkdtemp(prefix="wsb_share_")
        mapped_xml = ""
        for host_path, _container_path in config.volume_mounts.items():
            mapped_xml += f"    <MappedFolder>\n"
            mapped_xml += f"      <HostFolder>{host_path}</HostFolder>\n"
            mapped_xml += f"      <ReadOnly>false</ReadOnly>\n"
            mapped_xml += f"    </MappedFolder>\n"
        mapped_xml += f"    <MappedFolder>\n"
        mapped_xml += f"      <HostFolder>{self._shared_folder}</HostFolder>\n"
        mapped_xml += f"      <ReadOnly>false</ReadOnly>\n"
        mapped_xml += f"    </MappedFolder>\n"

        net = "Enable" if config.network_enabled else "Disable"
        wsb_xml = f"""<Configuration>
  <VGpu>Default</VGpu>
  <Networking>{net}</Networking>
  <MappedFolders>
{mapped_xml}  </MappedFolders>
  <LogonCommand>
    <Command>{config.executable_path or 'cmd.exe'} {config.working_dir or ''}</Command>
  </LogonCommand>
  <MemoryInMB>{int(config.memory_limit.replace('m','').replace('g','000'))}</MemoryInMB>
</Configuration>"""
        wsb_path = tempfile.mktemp(suffix=".wsb")
        with open(wsb_path, "w", encoding="utf-8") as fh:
            fh.write(wsb_xml)
        return wsb_path

    def setup(self, config: SandboxConfig) -> bool:
        self._wsb_path = self._write_wsb_config(config)
        return os.path.isfile(self._wsb_path)

    def run(self, command: str, config: SandboxConfig) -> SandboxResult:
        t0 = time.perf_counter()
        if not self._wsb_path:
            if not self.setup(config):
                return SandboxResult(stderr="wsb setup failed", returncode=-1, backend_used="windows_sandbox")
        try:
            subprocess.run(["cmd.exe", "/c", "start", "/wait", self._wsb_path],
                          timeout=config.timeout, check=False)
        except subprocess.TimeoutExpired:
            self.stop()
            elapsed = time.perf_counter() - t0
            return SandboxResult(stderr="wsb timeout", returncode=-1,
                                duration=elapsed, backend_used="windows_sandbox")
        elapsed = time.perf_counter() - t0
        return SandboxResult(returncode=0, duration=elapsed, backend_used="windows_sandbox")

    def stop(self) -> None:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
                          capture_output=True, check=False)

    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]:
        artifacts: Dict[str, bytes] = {}
        if not self._shared_folder or not os.path.isdir(self._shared_folder):
            return artifacts
        for pat in config.artifact_paths:
            for f in globmod.glob(os.path.join(self._shared_folder, pat), recursive=True):
                if os.path.isfile(f):
                    with open(f, "rb") as fh:
                        artifacts[f] = fh.read()
        return artifacts

    def cleanup(self) -> None:
        if self._wsb_path and os.path.isfile(self._wsb_path):
            os.unlink(self._wsb_path)
        if self._shared_folder and os.path.isdir(self._shared_folder):
            shutil.rmtree(self._shared_folder, ignore_errors=True)
        self._wsb_path = None


# 进程沙箱（保留原实现，兼容 SandboxDriver 接口）

class ProcessSandbox(SandboxDriver):
    # 最轻量后端 —— 直接子进程执行，带超时和资源限制
    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._validated_binary: Optional[str] = None

    def setup(self, config: SandboxConfig) -> bool:
        exe = config.executable_path or ""
        if not exe:
            _log.error("Process sandbox 需要 executable_path")
            return False
        if not os.path.isfile(exe) and not shutil.which(exe):
            _log.error("二进制不存在: %s", exe)
            return False
        self._validated_binary = exe
        return True

    def run(self, command: str, config: SandboxConfig) -> SandboxResult:
        t0 = time.perf_counter()
        self._active_cfg = config
        exe = self._validated_binary or config.executable_path or command.split()[0]
        full_cmd = [exe] + command.split()[1:] if command.startswith(exe) else command
        if isinstance(full_cmd, str):
            full_cmd = _shlex_split(full_cmd)
        env = os.environ.copy()
        env.update(config.env_vars)
        try:
            self._proc = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE if config.capture_stdout else None,
                stderr=subprocess.PIPE if config.capture_stderr else None,
                env=env,
                cwd=config.working_dir or None,
                text=True,
                start_new_session=True,
            )
            out, err = self._proc.communicate(timeout=config.timeout)
            rc = self._proc.returncode if self._proc.returncode is not None else -1
        except subprocess.TimeoutExpired:
            self.stop()
            elapsed = time.perf_counter() - t0
            return SandboxResult(stderr="process timeout", returncode=-1,
                                duration=elapsed, backend_used="process")
        elapsed = time.perf_counter() - t0
        return SandboxResult(
            stdout=out or "", stderr=err or "", returncode=rc,
            duration=elapsed, backend_used="process"
        )

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()

    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]:
        artifacts: Dict[str, bytes] = {}
        cwd = config.working_dir or "."
        for pat in config.artifact_paths:
            for f in globmod.glob(os.path.join(cwd, pat), recursive=True):
                if os.path.isfile(f):
                    with open(f, "rb") as fh:
                        artifacts[f] = fh.read()
        return artifacts

    def cleanup(self) -> None:
        self.stop()
        self._validated_binary = None


# 编排器 —— 兼容原 execute 接口与测试的 configure/run 接口

class SandboxOrchestrator:
    """
    自动检测可用后端并选择最优
    优先级: Docker > QEMU > Process > Windows沙箱
    同时提供轻量驱动接口：configure → start → run → shutdown
    """

    BACKEND_REGISTRY = {
        SandboxBackend.DOCKER.value: DockerSandbox,
        SandboxBackend.QEMU.value: QemuSandbox,
        SandboxBackend.PROCESS.value: ProcessSandbox,
        SandboxBackend.WINDOWS.value: WindowsSandbox,
    }

    _AVAILABILITY_CACHE: Dict[str, bool] = {}

    def __init__(self):
        self._backends: Dict[str, SandboxDriver] = {}
        self.driver: Optional[ProcessSandboxDriver] = None
        self._state = SandboxState.UNINITIALIZED
        self._execution_count = 0
        self._success_count = 0
        self._detect_backends()

    @classmethod
    def auto_select(cls) -> SandboxBackend:
        """返回最优可用后端（静态方法，测试直接调用）。"""
        for name in [SandboxBackend.DOCKER, SandboxBackend.QEMU,
                     SandboxBackend.PROCESS, SandboxBackend.WINDOWS]:
            if cls._AVAILABILITY_CACHE.get(name.value) or cls._probe_backend(name):
                return name
        return SandboxBackend.PROCESS

    @classmethod
    def list_available_backends(cls) -> List[str]:
        """列出当前可用后端名称。

        未探测过的后端按需探测；PROCESS 兜底后端恒可用。
        """
        available = set(cls._AVAILABILITY_CACHE)
        for name in [SandboxBackend.DOCKER, SandboxBackend.QEMU,
                     SandboxBackend.PROCESS, SandboxBackend.WINDOWS]:
            if name.value not in available:
                cls._probe_backend(name)
        return [backend for backend, ok in cls._AVAILABILITY_CACHE.items() if ok]

    @classmethod
    def _probe_backend(cls, name: SandboxBackend) -> bool:
        """探测指定后端是否可用。"""
        checks = {
            SandboxBackend.DOCKER: DockerSandbox._docker_available,
            SandboxBackend.QEMU: QemuSandbox._qemu_available,
            SandboxBackend.PROCESS: lambda: True,
            SandboxBackend.WINDOWS: WindowsSandbox._wsb_available,
        }
        check_fn = checks.get(name)
        if check_fn is None:
            return False
        try:
            ok = bool(check_fn())
        except Exception:
            ok = False
        cls._AVAILABILITY_CACHE[name.value] = ok
        return ok

    def _detect_backends(self):
        for name in [SandboxBackend.DOCKER, SandboxBackend.QEMU,
                     SandboxBackend.PROCESS, SandboxBackend.WINDOWS]:
            self._probe_backend(name)

    def configure(self, config: SandboxConfig) -> bool:
        """配置轻量驱动（当前仅支持 PROCESS 后端）。"""
        if config.backend != SandboxBackend.PROCESS:
            return False
        self.driver = ProcessSandboxDriver(config)
        self._state = SandboxState.CONFIGURED
        return True

    def start(self) -> None:
        """启动已配置的驱动。"""
        if self.driver is None:
            self._state = SandboxState.ERROR
            return
        self.driver.start()
        self._state = SandboxState.RUNNING

    def run(self, command: List[str], **kwargs) -> SandboxResult:
        """在已配置驱动上执行命令；未启动时返回失败结果。"""
        if self.driver is None or self._state != SandboxState.RUNNING:
            return SandboxResult(
                stderr="Sandbox not running",
                returncode=-1, backend_used="process")
        result = self.driver.execute(command, **kwargs)
        self._execution_count += 1
        if result.success:
            self._success_count += 1
        return result

    def shutdown(self) -> None:
        """停止驱动并复位状态。"""
        if self.driver is not None:
            self.driver.stop()
        self._state = SandboxState.STOPPED

    def get_summary(self) -> Dict[str, Any]:
        """输出编排器执行统计。"""
        return {
            'total_executions': self._execution_count,
            'successful': self._success_count,
            'state': self._state,
        }

    # 原 execute 接口（Docker/QEMU 等后端）

    def get_backend(self, name) -> SandboxDriver:
        if isinstance(name, SandboxBackend):
            name = name.value
        if name not in self.BACKEND_REGISTRY:
            raise ValueError(f"未知后端: {name}. 可用: {list(self.BACKEND_REGISTRY)}")
        if name not in self._backends:
            self._backends[name] = self.BACKEND_REGISTRY[name]()
        return self._backends[name]

    def available_backends(self) -> List[str]:
        return [n for n, ok in self._AVAILABILITY_CACHE.items() if ok]

    def execute(self, config: SandboxConfig, command: str,
                backend: Optional[str] = None) -> SandboxResult:
        """setup → 运行 → collect_artifacts → cleanup 完整流程。"""
        backend_name = backend or self.auto_select().value
        driver = self.get_backend(backend_name)
        t0 = time.perf_counter()
        if not driver.setup(config):
            return SandboxResult(stderr="backend setup failed", returncode=-1,
                                duration=time.perf_counter()-t0, backend_used=backend_name)
        result = driver.run(command, config)
        if config.artifact_paths:
            result.artifacts = driver.collect_artifacts(config)
        result.backend_used = backend_name
        result.duration = time.perf_counter() - t0
        try:
            driver.cleanup()
        except Exception:
            _log.exception("cleanup 异常")
        return result


# 命令行快速测试

def _shlex_join(parts: List[str]) -> str:
    """兼容 Python <3.8 的 shell 拼接（当前环境无需，保留工具）。"""
    import shlex
    return shlex.join(parts)


def _shlex_split(cmd: str) -> List[str]:
    import shlex
    return shlex.split(cmd)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    orch = SandboxOrchestrator()
    print(f"可用后端: {orch.available_backends()}")
    print(f"最优选择: {orch.auto_select()}")
