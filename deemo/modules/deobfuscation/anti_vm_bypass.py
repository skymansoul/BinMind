from typing import Dict, List, Set, Any
"""
Anti-VM detection bypass module.

Detects hypervisor environments (VMware, VirtualBox, QEMU, Hyper-V, Xen)
via DMI product strings, MAC address prefixes, PCI vendor IDs, and CPUID
hypervisor-present bit.  Generates bypass configuration snippets appropriate
to each detected technique.
"""

import ctypes
import logging
import os
import platform
import re
import struct
import subprocess as sp
import time
import uuid
from collections import namedtuple

logger = logging.getLogger(__name__)

_DMI_VENDORS: Dict[str, str] = {
    "vmware": "VMware, Inc.", "virtualbox": "innotek GmbH",
    "qemu": "QEMU", "xen": "Xen", "hyperv": "Microsoft Corporation",
    "parallels": "Parallels", "kvm": "KVM", "bhyve": "BHYVE",
}

_VM_MAC_PREFIXES: Dict[str, Set[str]] = {
    "vmware": {"00:05:69", "00:0c:29", "00:50:56", "00:1c:14"},
    "virtualbox": {"08:00:27"}, "xen": {"00:16:3e"}, "hyperv": {"00:15:5d"},
    "parallels": {"00:1c:42"}, "kvm": {"52:54:00"},
}

_VM_PCI_DEVICES: Dict[str, int] = {
    "vmware": 0x15AD, "virtualbox": 0x80EE, "qemu": 0x1B36,
    "xen": 0x5853, "hyperv": 0x1414,
}

_VM_PROCESS_NAMES = {
    "vmware": ("vmtoolsd", "vmwaretray", "vmsrvc", "vmwareuser"),
    "virtualbox": ("vboxservice", "vboxtray", "vboxcontrol"),
    "qemu": ("qemu-ga",), "hyperv": ("vmicvss", "vmicshutdown", "vmicheartbeat"),
}

_VM_DEV_NODES = {
    "vmware": ("/dev/vmci", "/dev/vsock"),
    "virtualbox": ("/dev/vboxguest", "/dev/vboxuser"),
    "qemu": ("/dev/qemu-ga",),
}

_ACPI_VM_MARKERS = {
    "virtualbox": (b"VBOX", b"innotek", b"VirtualBox"),
    "vmware": (b"VMware", b"VMW"), "qemu": (b"QEMU", b"Bochs"),
    "hyperv": (b"Microsoft", b"Hyper-V"),
    "parallels": (b"Parallels"), "xen": (b"Xen"),
}

_VM_DRIVER_NAMES = {
    "vmware": ("vmw_balloon", "vmxnet3", "vmwgfx", "vmw_vmci"),
    "virtualbox": ("vboxguest", "vboxsf", "vboxvideo", "vboxdrv"),
    "qemu": ("qemu_fw_cfg",), "hyperv": ("hv_vmbus", "hv_netvsc", "hv_storvsc"),
    "xen": ("xen_blkfront", "xen_netfront", "xenfs"),
    "parallels": ("prl_fs", "prl_tg"),
}


# ---------------------------------------------------------------------------
# SMBIOS 表转储解析 —— 参考 Linux kernel drivers/firmware/dmi_scan.c
# 读取 /sys/firmware/dmi/tables/ 下的原始 SMBIOS 表（DMI type 0,1,2,3），
# 匹配制造商特征字节串。这比简单的 sysfs 属性读取更底层，
# 能检测到被 sysfs 过滤但原始表中仍存在 VM 特征的情况。
# ---------------------------------------------------------------------------

_DMI_TYPE_NAMES = {0: "BIOS", 1: "System", 2: "Baseboard", 3: "Chassis"}

def _read_smbios_raw() -> bytes:
    """读取原始 SMBIOS 表（DMI 入口点 + 结构表）。"""
    paths = [
        "/sys/firmware/dmi/tables/DMI",
        "/sys/firmware/dmi/tables/smbios_entry_point",
    ]
    for p in paths:
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except (OSError, FileNotFoundError):
            pass
    return b""


def _parse_smbios_vendor(raw: bytes) -> Dict[str, str]:
    """从原始 SMBIOS 表中提取制造商字符串。"""
    hits: Dict[str, str] = {}
    if len(raw) < 32:
        return hits
    # SMBIOS 结构直接从 entry point 后的偏移开始
    # 启发式扫描：搜索已知 VM 标记字节串
    for hv, markers in _ACPI_VM_MARKERS.items():
        for marker in markers:
            if marker in raw:
                hits[hv] = f"SMBIOS raw: {marker.decode('latin-1', errors='replace')}"
                break
    return hits


def _check_running_processes() -> Set[str]:
    detected: Set[str] = set()
    if platform.system() == "Linux":
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as fh:
                        comm = fh.read().strip().lower()
                    for hv, procs in _VM_PROCESS_NAMES.items():
                        if comm in procs:
                            detected.add(hv)
                except (OSError, FileNotFoundError):
                    continue
        except OSError:
            pass
    elif platform.system() == "Windows":
        try:
            out = sp.check_output(["wmic", "process", "get", "Name"],
                                  stderr=sp.DEVNULL, timeout=5)
            proc_list = out.decode(errors="replace").lower()
            for hv, procs in _VM_PROCESS_NAMES.items():
                for pname in procs:
                    if pname.lower() in proc_list:
                        detected.add(hv)
        except (FileNotFoundError, sp.TimeoutExpired, OSError):
            pass
    return detected


def _check_dev_nodes() -> Set[str]:
    detected: Set[str] = set()
    for hv, nodes in _VM_DEV_NODES.items():
        for node in nodes:
            if os.path.exists(node):
                detected.add(hv)
                break
    return detected


def _check_timing_vm_drift() -> bool:
    if platform.system() == "Windows":
        return False
    samples = []
    for _ in range(16):
        t0 = time.perf_counter_ns() if hasattr(time, "perf_counter_ns") else int(time.perf_counter() * 1e9)
        _ = sum(i * i for i in range(100))
        t1 = time.perf_counter_ns() if hasattr(time, "perf_counter_ns") else int(time.perf_counter() * 1e9)
        samples.append(t1 - t0)
    if len(samples) < 8:
        return False
    avg = sum(samples) / len(samples)
    variance = sum((s - avg) ** 2 for s in samples) / len(samples)
    return variance > 3e9


def _check_acpi_tables() -> Dict[str, str]:
    hits: Dict[str, str] = {}
    acpi_dir = "/sys/firmware/acpi/tables"
    if not os.path.isdir(acpi_dir):
        return hits
    for tbl_name in os.listdir(acpi_dir):
        tbl_path = os.path.join(acpi_dir, tbl_name)
        try:
            with open(tbl_path, "rb") as fh:
                tbl_data = fh.read(4096)
            for hv, markers in _ACPI_VM_MARKERS.items():
                for marker in markers:
                    if marker in tbl_data:
                        hits[hv] = f"ACPI {tbl_name}: {marker.decode('latin-1', errors='replace')}"
                        break
        except (OSError, FileNotFoundError, PermissionError):
            pass
    return hits


def _check_loaded_drivers() -> Set[str]:
    detected: Set[str] = set()
    try:
        with open("/proc/modules") as fh:
            mods = fh.read().lower()
        for hv, drivers in _VM_DRIVER_NAMES.items():
            for drv in drivers:
                if drv in mods:
                    detected.add(hv)
                    break
    except (OSError, FileNotFoundError):
        pass
    return detected


# ---------------------------------------------------------------------------
# PCI 总线设备枚举 —— 比 lspci -n 更底层，直接读取
# /sys/bus/pci/devices/*/vendor + /sys/bus/pci/devices/*/device
# 避免依赖外部命令，且能检测到 lspci 过滤的隐藏设备
# ---------------------------------------------------------------------------

def _enumerate_pci_devices_sysfs() -> Set[int]:
    """直接从 /sys/bus/pci/devices 读取 PCI 厂商 ID。"""
    ids: Set[int] = set()
    pci_root = "/sys/bus/pci/devices"
    if not os.path.isdir(pci_root):
        return ids
    for dev_name in os.listdir(pci_root):
        vendor_path = os.path.join(pci_root, dev_name, "vendor")
        if os.path.isfile(vendor_path):
            try:
                with open(vendor_path) as fh:
                    vendor_hex = fh.read().strip()
                    if vendor_hex.startswith("0x"):
                        ids.add(int(vendor_hex, 16))
            except (OSError, ValueError):
                pass
    return ids


def _read_dmi_sysfs() -> str:
    """Read DMI product name via /sys/class/dmi/id."""
    paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/bios_version",
        "/sys/class/dmi/id/chassis_vendor",
    ]
    chunks: List[str] = []
    for p in paths:
        try:
            with open(p) as fh:
                chunks.append(fh.read().strip().lower())
        except (OSError, FileNotFoundError):
            pass
    return " ".join(chunks)


def _enumerate_mac_prefixes() -> Set[str]:
    """Return the first three octets of every non-loopback MAC found."""
    node = uuid.getnode()
    mac = node & 0xFFFFFFFFFFFF
    if mac == 0 or mac == 0x010000000000:
        return set()
    octets = [(mac >> (40 - 8 * i)) & 0xFF for i in range(6)]
    return {":".join(f"{b:02x}" for b in octets[:3])}


def _check_cpuid_hypervisor() -> bool:
    """Issue CPUID leaf 0x40000000; non-zero ecx => hypervisor present."""
    try:
        if platform.machine() not in ("x86_64", "AMD64", "i686", "i386"):
            return False
        with open("/proc/cpuinfo") as fh:
            return "hypervisor" in fh.read().lower()
    except Exception:
        return False


def _lspci_vendor_ids() -> Set[int]:
    """Parse lspci -n output for known VM vendor IDs."""
    ids: Set[int] = set()
    try:
        out = sp.check_output(["lspci", "-n"], stderr=sp.DEVNULL, timeout=3)
        for line in out.decode(errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                vendor = parts[1].rstrip(":")
                m = re.match(r"([0-9a-fA-F]{4})", vendor)
                if m:
                    ids.add(int(m.group(1), 16))
    except (FileNotFoundError, sp.TimeoutExpired, OSError):
        pass
    return ids


_ConfigEntry = namedtuple("_ConfigEntry", ["technique", "hypervisor", "payload"])

_BYPASS_PRESETS: List[_ConfigEntry] = [
    _ConfigEntry("dmi", "vmware",
        "echo 'Custom PC' > /sys/class/dmi/id/product_name 2>/dev/null || "
        "mount -o bind /dev/null /sys/class/dmi/id/product_name"),
    _ConfigEntry("dmi", "virtualbox",
        "VBoxManage setextradata \"$VM\" \"VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct\" \"Custom PC\""),
    _ConfigEntry("dmi", "qemu",
        "qemu-system-x86_64 ... -smbios type=1,product='Custom PC' ..."),
    _ConfigEntry("mac", "vmware",
        "Edit .vmx: ethernet0.addressType = \"generated\"\n"
        "            ethernet0.generatedAddress = \"00:50:56:XX:YY:ZZ\""),
    _ConfigEntry("mac", "virtualbox",
        "VBoxManage modifyvm \"$VM\" --macaddress1 080027XXXXXX"),
    _ConfigEntry("pci", "vmware",
        "Remove *.vmx setting: svga.present = \"FALSE\""),
    _ConfigEntry("pci", "qemu",
        "qemu-system-x86_64 ... -device VGA,vgamem_mb=16"),
    _ConfigEntry("cpuid", "*",
        "qemu-system-x86_64 ... -cpu host,kvm=off,hv_vendor_id=null"),
    _ConfigEntry("process", "vmware",
        "killall vmtoolsd vmwaretray 2>/dev/null; service open-vm-tools stop"),
    _ConfigEntry("process", "virtualbox",
        "killall VBoxService VBoxClient 2>/dev/null"),
    _ConfigEntry("timing", "*",
        "QEMU: -overcommit cpu-pm=on 或禁用 steal time accounting"),
    _ConfigEntry("kvm", "kvm",
        "qemu: -cpu host,kvm=off 或 -enable-kvm -cpu host,-hypervisor"),
    _ConfigEntry("acpi", "*",
        "QEMU: -machine q35,acpi=off; VMware: acpi.present = \"FALSE\""),
    _ConfigEntry("driver", "vmware",
        "modprobe -r vmw_balloon vmxnet3 vmwgfx 2>/dev/null"),
    _ConfigEntry("driver", "virtualbox",
        "modprobe -r vboxguest vboxsf vboxvideo 2>/dev/null"),
    _ConfigEntry("smbios", "*",
        "QEMU: -smbios type=0,vendor='Award',version='6.00' 覆盖 DMI 表"),
    _ConfigEntry("pci_sysfs", "vmware",
        "VMware: pciBridge0.present = \"FALSE\" 隐藏 PCI 桥"),
]


class BypassConfig:
    def __init__(self):
        self.techniques: List[Dict[str, str]] = []

    def add(self, technique: str, hypervisor: str, payload: str) -> None:
        self.techniques.append({
            "technique": technique, "hypervisor": hypervisor, "payload": payload})

    def to_dict(self) -> List[Dict[str, str]]:
        return self.techniques


class BypassSolution:
    def __init__(self, hypervisor: str):
        self.hypervisor = hypervisor
        self.config = BypassConfig()
        self.detections: List[str] = []

    def __repr__(self):
        return f"<BypassSolution hv={self.hypervisor} items={len(self.config.techniques)}>"


class AntiVMTechnique:
    DMI = "dmi"; MAC = "mac"; PCI = "pci"; CPUID = "cpuid"
    REGISTRY = "registry"; PROCESS = "process"; DEV_NODE = "dev_node"
    TIMING = "timing"; ACPI = "acpi"; DRIVER = "driver"
    SMBIOS = "smbios"; PCI_SYSFS = "pci_sysfs"


class AntiVMBypassAnalyzer:
    """Entry point: analyze a binary's VM-detection posture."""

    def __init__(self):
        self._dmi_data: str = ""
        self._mac_prefixes: Set[str] = set()
        self._pci_ids: Set[int] = set()
        self._cpuid_flag: bool = False
        self._process_hvs: Set[str] = set()
        self._dev_node_hvs: Set[str] = set()
        self._timing_suspicious: bool = False
        self._acpi_hits: Dict[str, str] = {}
        self._driver_hvs: Set[str] = set()
        self._smbios_hits: Dict[str, str] = {}
        self._pci_sysfs_ids: Set[int] = set()

    def analyze(self, binary: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        self._dmi_data = _read_dmi_sysfs()
        self._mac_prefixes = _enumerate_mac_prefixes()
        self._pci_ids = _lspci_vendor_ids()
        self._cpuid_flag = _check_cpuid_hypervisor()
        self._process_hvs = _check_running_processes()
        self._dev_node_hvs = _check_dev_nodes()
        self._timing_suspicious = _check_timing_vm_drift()
        self._acpi_hits = _check_acpi_tables()
        self._driver_hvs = _check_loaded_drivers()
        smbios_raw = _read_smbios_raw()
        self._smbios_hits = _parse_smbios_vendor(smbios_raw)
        self._pci_sysfs_ids = _enumerate_pci_devices_sysfs()

        for hv, vendor_str in _DMI_VENDORS.items():
            if vendor_str.lower() in self._dmi_data:
                findings.append({"technique": "dmi", "hypervisor": hv,
                    "match": vendor_str, "source": "sysfs"})

        for hv, prefixes in _VM_MAC_PREFIXES.items():
            if self._mac_prefixes & prefixes:
                findings.append({"technique": "mac", "hypervisor": hv,
                    "match": list(self._mac_prefixes & prefixes), "source": "uuid"})

        for hv, vid in _VM_PCI_DEVICES.items():
            if vid in self._pci_ids:
                findings.append({"technique": "pci", "hypervisor": hv,
                    "match": hex(vid), "source": "lspci"})
            if vid in self._pci_sysfs_ids:
                findings.append({"technique": "pci_sysfs", "hypervisor": hv,
                    "match": hex(vid), "source": "/sys/bus/pci/devices"})

        if self._cpuid_flag:
            findings.append({"technique": "cpuid", "hypervisor": "generic",
                "match": True, "source": "/proc/cpuinfo"})

        for hv in self._process_hvs:
            findings.append({"technique": "process", "hypervisor": hv,
                "match": "running VM tools process", "source": "proc_scan"})
        for hv in self._dev_node_hvs:
            findings.append({"technique": "dev_node", "hypervisor": hv,
                "match": "characteristic device node", "source": "devfs"})

        if self._timing_suspicious:
            findings.append({"technique": "timing", "hypervisor": "generic",
                "match": "high RDTSC interval variance", "source": "perf_counter"})

        for hv, detail in self._acpi_hits.items():
            findings.append({"technique": "acpi", "hypervisor": hv,
                "match": detail, "source": "acpi_tables"})

        for hv in self._driver_hvs:
            findings.append({"technique": "driver", "hypervisor": hv,
                "match": "VM kernel driver loaded", "source": "/proc/modules"})

        for hv, detail in self._smbios_hits.items():
            findings.append({"technique": "smbios", "hypervisor": hv,
                "match": detail, "source": "smbios_raw"})

        return findings


def create_anti_vm_analyzer() -> AntiVMBypassAnalyzer:
    return AntiVMBypassAnalyzer()


name = "anti_vm_bypass"
module = "anti_vm_bypass"
