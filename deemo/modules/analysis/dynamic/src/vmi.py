from __future__ import annotations

import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class VMIBackend(str, Enum):
    LIBVMI = "libvmi"
    QEMU = "qemu"
    SIMULATED = "simulated"


@dataclass
class VMINode:
    name: str
    domain_id: int
    memory_mb: int
    vcpus: int
    state: str  # "running", "paused", "shutoff"
    os_type: str = ""

@dataclass
class VMIProcess:
    pid: int
    name: str
    dtb: int  # Directory table base (CR3 value)
    modules: List[Dict[str, Any]] = field(default_factory=list)
    vads: List[Dict[str, Any]] = field(default_factory=list)  # 虚拟地址描述符


class VMIAccessError(Exception):
    pass


class VMIAnalyzer:

    def __init__(
        self,
        backend: str = "simulated",
        socket_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._backend = VMIBackend(backend)
        self._socket_path = socket_path
        self._config = config or {}
        self._connected: bool = False
        self._current_domain_id: int = 0
        self._current_domain_name: str = ""

# 连接管理

    def connect(self, domain_name: str) -> bool:
        log.info("Connecting to VM domain: %s (backend=%s)", domain_name, self._backend.value)
        self._current_domain_name = domain_name

        if self._backend == VMIBackend.SIMULATED:
            self._connected = True
            self._current_domain_id = 1
            return True

        if self._backend == VMIBackend.LIBVMI:
            return self._connect_libvmi(domain_name)

        if self._backend == VMIBackend.QEMU:
            return self._connect_qemu(domain_name)

        return False

    def _connect_libvmi(self, domain_name: str) -> bool:
        try:
            # production: import libvmi; vmi = libvmi.VMI(domain_name)
            log.info("LibVMI connection initiated for %s", domain_name)
            self._connected = True
            self._current_domain_id = hash(domain_name) % 1000
            return True
        except Exception:
            log.error("LibVMI connection failed", exc_info=True)
            return False

    def _connect_qemu(self, domain_name: str) -> bool:
        if not self._socket_path:
            self._socket_path = f"/var/run/qemu/{domain_name}.monitor"
        log.info("QEMU monitor socket: %s", self._socket_path)
        if not os.path.exists(self._socket_path or ""):
            log.warning("QEMU socket not found: %s", self._socket_path)
            return False
        self._connected = True
        self._current_domain_id = hash(domain_name) % 1000
        return True

    def disconnect(self) -> None:
        log.info("Disconnecting from domain %s", self._current_domain_name)
        self._connected = False
        self._current_domain_name = ""

# VM 发现

    def list_domains(self) -> List[VMINode]:
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        return [
            VMINode(
                name=self._current_domain_name,
                domain_id=self._current_domain_id,
                memory_mb=4096,
                vcpus=4,
                state="running",
                os_type="Windows 10",
            )
        ]

# 内存读取

    def read_physical_memory(self, paddr: int, size: int) -> bytes:
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.debug("VMI read physical: %#x (%d bytes)", paddr, size)
        # 仿真模式：返回零填充占位数据
        return b"\x00" * size

    def read_virtual_memory(self, vaddr: int, size: int, pid: int = 0) -> bytes:
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.debug("VMI read virtual: %#x (%d bytes, PID=%d)", vaddr, size, pid)

        if self._backend == VMIBackend.SIMULATED:
            # 仿真模式：返回模拟 PE 头部供演示
            return b"MZ\x90\x00" + b"\x00" * (size - 4)

        return b"\x00" * size

    def read_memory_string(self, vaddr: int, max_len: int = 256, pid: int = 0) -> str:
        data = self.read_virtual_memory(vaddr, max_len, pid)
        null_byte = data.find(b"\x00")
        if null_byte >= 0:
            data = data[:null_byte]
        return data.decode("utf-8", errors="replace")

# 进程枚举

    def list_processes(self) -> List[VMIProcess]:
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.info("Enumerating processes in domain %s", self._current_domain_name)

        # 仿真进程列表
        processes = [
            VMIProcess(pid=4, name="System", dtb=0x187000),
            VMIProcess(pid=360, name="csrss.exe", dtb=0x1A7000),
            VMIProcess(pid=488, name="winlogon.exe", dtb=0x1B8000),
            VMIProcess(pid=620, name="services.exe", dtb=0x1C9000),
            VMIProcess(pid=720, name="lsass.exe", dtb=0x1DA000),
            VMIProcess(pid=828, name="svchost.exe", dtb=0x1EB000),
            VMIProcess(pid=1024, name="explorer.exe", dtb=0x1FC000),
            VMIProcess(pid=1536, name="cmd.exe", dtb=0x20D000),
        ]
        return sorted(processes, key=lambda p: p.pid)

    def get_process_by_name(self, name: str) -> Optional[VMIProcess]:
        for proc in self.list_processes():
            if proc.name.lower() == name.lower():
                return proc
        return None

    def get_process_by_pid(self, pid: int) -> Optional[VMIProcess]:
        for proc in self.list_processes():
            if proc.pid == pid:
                return proc
        return None

# 进程内存

    def read_process_memory(self, pid: int, vaddr: int, size: int) -> bytes:
        proc = self.get_process_by_pid(pid)
        if not proc:
            raise VMIAccessError(f"Process PID={pid} not found")

        return self.read_virtual_memory(vaddr, size, pid)

# 内核检查

    def get_kernel_base(self) -> int:
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")
        return 0xFFFFF80000000000  # 典型 x64 Windows 内核基址

    def read_kernel_symbol(self, symbol_name: str, size: int = 8) -> bytes:
        log.debug("Reading kernel symbol: %s", symbol_name)
        # 仿真内核符号
        _KNOWN_SYMBOLS = {
            "PsActiveProcessHead": 0xFFFFF80001234560,
            "PsLoadedModuleList": 0xFFFFF80002345670,
            "NtBuildNumber": 0xFFFFF80003456780,
        }
        addr = _KNOWN_SYMBOLS.get(symbol_name, 0)
        if addr:
            return self.read_virtual_memory(addr, size)
        return b"\x00" * size

# VM 控制

    def pause_vm(self) -> bool:
        log.info("Pausing VM %s", self._current_domain_name)
        return True

    def resume_vm(self) -> bool:
        log.info("Resuming VM %s", self._current_domain_name)
        return True

# 状态

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def domain_name(self) -> str:
        return self._current_domain_name
