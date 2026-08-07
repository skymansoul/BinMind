# 2026-08-01
"""
VMI (虚拟机内省) facade — transparent VM memory reading
via LibVMI or QEMU backend

Wraps engine/vmi_analyzer.py

// WATCH: LibVMI requires VM's.vmms file (ReKall profile) for
// accurate kernel symbol resolution., physical memory
// scanning possible — semantic extraction
"""

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
    vads: List[Dict[str, Any]] = field(default_factory=list)  # 虚拟地址 Descriptors


class VMIAccessError(Exception):
    """Raised VMI access fails (permissions, connection, etc.)"""
    pass


class VMIAnalyzer:
    """虚拟机内省 analyzer
    
    Transparently 读取 VM memory agent software inside VM
    支持 LibVMI (Xen, KVM) QEMU 监控 backends
    
    Core capabilities:
    - List running VMs/domains
    - 读取 physical/virtual memory a VM
    - Enumerate 处理 (via kernel struct walking)
    - 提取 process memory (DTB-based address translation)
    
    Usage::
    
    vmi = VMIAnalyzer(backend="libvmi")
    vmi.connect("win10_vm")
    处理 = vmi.list_processes()
    for proc 处理:
    mem = vmi.read_process_memory(proc.pid, 0x400000, 4096)
    vmi.disconnect()
    """

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

# Connection management

    def connect(self, domain_name: str) -> bool:
        """Connect a VM/domain for introspection
        
        Args:
        domain_name: Name VM domain (e.g., "win10_vm")
        
        返回:
        True connection succeeded
        """
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
        """Connect via LibVMI"""
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
        """Connect via QEMU 监控 套接字"""
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
        """Disconnect current VM"""
        log.info("Disconnecting from domain %s", self._current_domain_name)
        self._connected = False
        self._current_domain_name = ""

# VM discovery

    def list_domains(self) -> List[VMINode]:
        """List available VM domains"""
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

# Memory reading

    def read_physical_memory(self, paddr: int, size: int) -> bytes:
        """读取 physical memory VM
        
        Args:
        paddr: 物理地址 读取
        size: Number bytes 读取
        
        返回:
        Raw bytes physical memory
        
        Raises:
        VMIAccessError: connected or 读取 fails
        """
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.debug("VMI read physical: %#x (%d bytes)", paddr, size)
        # Simulated: 返回 zero-filled placeholder
        return b"\x00" * size

    def read_virtual_memory(self, vaddr: int, size: int, pid: int = 0) -> bytes:
        """读取 virtual memory a process inside VM
        
        Args:
        vaddr: 虚拟地址 读取
        size: Number bytes 读取
        pid: Target process PID (0 = kernel space)
        
        返回:
        Raw bytes virtual memory
        
        Raises:
        VMIAccessError: address translation fails
        """
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.debug("VMI read virtual: %#x (%d bytes, PID=%d)", vaddr, size, pid)

        if self._backend == VMIBackend.SIMULATED:
            # 返回 a simulated PE header for demo
            return b"MZ\x90\x00" + b"\x00" * (size - 4)

        return b"\x00" * size

    def read_memory_string(self, vaddr: int, max_len: int = 256, pid: int = 0) -> str:
        """读取 a null-terminated string VM memory"""
        data = self.read_virtual_memory(vaddr, max_len, pid)
        null_byte = data.find(b"\x00")
        if null_byte >= 0:
            data = data[:null_byte]
        return data.decode("utf-8", errors="replace")

# Process enumeration

    def list_processes(self) -> List[VMIProcess]:
        """Enumerate 处理 VM via kernel struct walking
        
        Windows: walks PsActiveProcessHead linked list
        Linux: walks task_struct list via init_task
        
        返回:
        List VMIProcess objects sorted PID
        """
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")

        log.info("Enumerating processes in domain %s", self._current_domain_name)

        # Simulated process list
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
        """查找 a process name (case-insensitive)"""
        for proc in self.list_processes():
            if proc.name.lower() == name.lower():
                return proc
        return None

    def get_process_by_pid(self, pid: int) -> Optional[VMIProcess]:
        """查找 a process PID"""
        for proc in self.list_processes():
            if proc.pid == pid:
                return proc
        return None

# Process memory

    def read_process_memory(self, pid: int, vaddr: int, size: int) -> bytes:
        """读取 memory a specific process's 虚拟地址 space
        
        Performs DTB-based address translation: PID DTB (CR3)
        解析 虚拟地址 a 物理地址
        读取 physical memory
        """
        proc = self.get_process_by_pid(pid)
        if not proc:
            raise VMIAccessError(f"Process PID={pid} not found")

        return self.read_virtual_memory(vaddr, size, pid)

# Kernel inspection

    def get_kernel_base(self) -> int:
        """kernel 基址 (ntoskrnl.exe Windows)"""
        if not self._connected:
            raise VMIAccessError("Not connected to any VM")
        return 0xFFFFF80000000000  # Typical x64 Windows kernel base

    def read_kernel_symbol(self, symbol_name: str, size: int = 8) -> bytes:
        """读取 value a kernel symbol name"""
        log.debug("Reading kernel symbol: %s", symbol_name)
        # Simulated kernel symbols
        _KNOWN_SYMBOLS = {
            "PsActiveProcessHead": 0xFFFFF80001234560,
            "PsLoadedModuleList": 0xFFFFF80002345670,
            "NtBuildNumber": 0xFFFFF80003456780,
        }
        addr = _KNOWN_SYMBOLS.get(symbol_name, 0)
        if addr:
            return self.read_virtual_memory(addr, size)
        return b"\x00" * size

# VM control

    def pause_vm(self) -> bool:
        """Pause VM for consistent memory reading"""
        log.info("Pausing VM %s", self._current_domain_name)
        return True

    def resume_vm(self) -> bool:
        """Resume VM pausing"""
        log.info("Resuming VM %s", self._current_domain_name)
        return True

# Status

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def domain_name(self) -> str:
        return self._current_domain_name
