# 2026-07-14
# 沙箱编排 —— 多后端统一接口，自动选择最优执行环境
# 设计思路：Docker 优先（隔离性好），QEMU 次之（全系统模拟）
# Process 兜底（轻量但隔离弱），Windows 沙箱 仅 Windows 下可用

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
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from io import BytesIO

import subprocess

_log = logging.getLogger(__name__)


# 配置与结果数据类

@dataclass
class SandboxConfig:
    """一次沙箱执行的完整配置"""
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
    telemetry_enabled: bool = False

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


@dataclass
class SandboxResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    artifacts: Dict[str, bytes] = field(default_factory=dict)
    duration: float = 0.0
    backend_used: str = ""


# 抽象驱动器

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


# Docker 沙箱

class DockerSandbox(SandboxDriver):
    """
    Docker 容器沙箱 —— 最常用的后端
    完整实现：拉镜像、创建容器、执行、收集产物、清理
    """

    def __init__(self):
        self._container_id: Optional[str] = None
        self._image_pulled: bool = False
        self._active_config: Optional[SandboxConfig] = None

# 检查 docker 是否可用
    @staticmethod
    def _docker_available() -> bool:
        """检查 docker CLI 是否可调用"""
        try:
            r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

# 拉取镜像（若本地不存在）
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
        # docker exec 在运行中的容器里执行命令
        exec_args = ["docker", "exec", "-i"]
        if config.working_dir:
            exec_args += ["-w", config.working_dir]
        for k, v in config.env_vars.items():
            exec_args += ["-e", f"{k}={v}"]
        exec_args.append(self._container_id)
        # shell 包装: 确保 timeout 等可以生效
        shell_cmd = f"timeout {config.timeout} sh -c {shlex.join([command])}"
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
            # 容器内 find
            find_args = ["docker", "exec", self._container_id,
                        "find", "/", "-path", pattern, "-type", "f"]
            r = subprocess.run(find_args, capture_output=True, text=True)
            for line in r.stdout.strip().splitlines():
                if not line.strip():
                    continue
                # docker cp
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


# QEMU 沙箱

class QemuSandbox(SandboxDriver):
    """
    QEMU 全系统模拟沙箱
    用于固件、嵌入式二进制等无法在容器中运行的场景
    QMP 支持标记为 TODO —— 当前通过进程信号控制
    """

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._disk_path: Optional[str] = None
        self._pid: Optional[int] = None

    # //// 检查 qemu-system 是否可用 ////
    @staticmethod
    def _qemu_available() -> bool:
        for arch in ["x86_64", "i386", "arm", "aarch64"]:
            if shutil.which(f"qemu-system-{arch}"):
                return True
        return False

    # //// 为 QEMU 创建临时磁盘镜像 ////
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
        # 最小化启动参数
        qargs = [
            qemu,
            "-kernel", config.executable_path or config.image or "",
            "-nographic",
            "-m", config.memory_limit.replace("m", "M").replace("g", "G"),
            "-drive", f"file={self._disk_path},format=qcow2,if=virtio",
            "-append", f"console=ttyS0 init=/bin/sh -- -c {shlex.join([command])}",
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
        """终止 QEMU 进程
        TODO: 实现 QMP (QEMU Machine 协议) 优雅关机
        当前方案: SIGTERM → wait 3s → SIGKILL
        """
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._proc = None

    def collect_artifacts(self, config: SandboxConfig) -> Dict[str, bytes]:
        # QEMU 场景产物从磁盘镜像提取
        artifacts: Dict[str, bytes] = {}
        if not self._disk_path or not os.path.exists(self._disk_path):
            return artifacts
        # 尝试用 guestmount 或直接读 qcow2
        # 简化: 用 qemu-img 转换 转成 raw 再搜索
        raw_path = tempfile.mktemp(suffix=".raw")
        subprocess.run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw",
                       self._disk_path, raw_path], check=False, capture_output=True)
        if os.path.exists(raw_path):
            with open(raw_path, "rb") as fh:
                for pat in config.artifact_paths:
                    artifacts[f"disk:/{pat}"] = fh.read(4096)  # 简化: 只读前4K
            os.unlink(raw_path)
        return artifacts

    def cleanup(self) -> None:
        self.stop()
        if self._disk_path and os.path.exists(self._disk_path):
            os.unlink(self._disk_path)
        self._disk_path = None


# Windows 沙箱

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

# 生成 WSB 配置 XML
    def _write_wsb_config(self, config: SandboxConfig) -> str:
        self._shared_folder = tempfile.mkdtemp(prefix="wsb_share_")
        # 组装映射目录: 把 volume_mounts 转换为 MappedFolder
        mapped_xml = ""
        for host_path, _container_path in config.volume_mounts.items():
            mapped_xml += f"    <MappedFolder>\n"
            mapped_xml += f"      <HostFolder>{host_path}</HostFolder>\n"
            mapped_xml += f"      <ReadOnly>false</ReadOnly>\n"
            mapped_xml += f"    </MappedFolder>\n"
        # 默认共享目录
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
        # 启动 Windows 沙箱
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
        """终止 Windows沙箱.exe 进程"""
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


# 进程沙箱

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

    def _apply_limits(self):
        """设置进程资源限制 (类unix)"""
        if sys.platform == "win32":
            return
        try:
            import resource
            # 内存限制解析
            mem = 512 * 1024 * 1024  # 默认 512MB
            cfg = getattr(self, '_active_cfg', None)
            if cfg:
                raw = cfg.memory_limit.lower()
                if raw.endswith("g"):
                    mem = int(float(raw[:-1]) * 1024 * 1024 * 1024)
                elif raw.endswith("m"):
                    mem = int(float(raw[:-1]) * 1024 * 1024)
                elif raw.endswith("k"):
                    mem = int(float(raw[:-1]) * 1024)
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        except Exception:
            pass

    def run(self, command: str, config: SandboxConfig) -> SandboxResult:
        t0 = time.perf_counter()
        self._active_cfg = config
        exe = self._validated_binary or config.executable_path or command.split()[0]
        # 构建完整命令
        full_cmd = [exe] + command.split()[1:] if command.startswith(exe) else command
        if isinstance(full_cmd, str):
            full_cmd = shlex.split(full_cmd)
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
                preexec_fn=self._apply_limits if sys.platform != "win32" else None,
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


# 编排器

class SandboxOrchestrator:
    """
    自动检测可用后端并选择最优
    优先级: Docker > QEMU > Process > Windows沙箱
    """

    BACKEND_REGISTRY = {
        "docker":          DockerSandbox,
        "qemu":            QemuSandbox,
        "process":         ProcessSandbox,
        "windows_sandbox": WindowsSandbox,
    }

    _AVAILABILITY_CACHE: Dict[str, bool] = {}

    def __init__(self):
        self._backends: Dict[str, SandboxDriver] = {}
        self._detect_backends()

    # //// 检测哪些后端可用 ////
    def _detect_backends(self):
        checks = {
            "docker":          DockerSandbox._docker_available,
            "qemu":            QemuSandbox._qemu_available,
            "process":         lambda: True,  # 总是可用
            "windows_sandbox": WindowsSandbox._wsb_available,
        }
        for name, check_fn in checks.items():
            try:
                ok = check_fn()
            except Exception:
                ok = False
            self._AVAILABILITY_CACHE[name] = ok
            if ok:
                _log.info("沙箱后端可用: %s", name)

    def auto_select(self) -> str:
        """按优先级返回最优可用后端名"""
        for name in ["docker", "qemu", "process", "windows_sandbox"]:
            if self._AVAILABILITY_CACHE.get(name):
                return name
        return "process"  # 兜底

    def get_backend(self, name: str) -> SandboxDriver:
        if name not in self.BACKEND_REGISTRY:
            raise ValueError(f"未知后端: {name}. 可用: {list(self.BACKEND_REGISTRY)}")
        if name not in self._backends:
            self._backends[name] = self.BACKEND_REGISTRY[name]()
        return self._backends[name]

    def available_backends(self) -> List[str]:
        return [n for n, ok in self._AVAILABILITY_CACHE.items() if ok]

# 完整执行生命周期
    def execute(self, config: SandboxConfig, command: str,
                backend: Optional[str] = None) -> SandboxResult:
        """
        setup → 运行 → collect_artifacts → cleanup 完整流程
        返回 沙箱Result 包含 stdout/stderr/returncode/artifacts/d
        """
        backend_name = backend or self.auto_select()
        driver = self.get_backend(backend_name)
        t0 = time.perf_counter()
# setup
        if not driver.setup(config):
            return SandboxResult(stderr="backend setup failed", returncode=-1,
                                duration=time.perf_counter()-t0, backend_used=backend_name)
# 运行
        result = driver.run(command, config)
# collect
        if config.artifact_paths:
            result.artifacts = driver.collect_artifacts(config)
        result.backend_used = backend_name
        result.duration = time.perf_counter() - t0
# cleanup
        try:
            driver.cleanup()
        except Exception:
            _log.exception("cleanup 异常")
        return result


# 命令行快速测试
import shlex as _shlex_mod
shlex = _shlex_mod

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    orch = SandboxOrchestrator()
    print(f"可用后端: {orch.available_backends()}")
    print(f"最优选择: {orch.auto_select()}")
