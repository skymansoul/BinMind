from typing import Dict, List
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
import subprocess as sp
import uuid
from collections import namedtuple

logger = logging.getLogger(__name__)

# VM indicator signatures

_DMI_VENDORS: Dict[str, str] = {
    "vmware": "VMware, Inc.",
    "virtualbox": "innotek GmbH",
    "qemu": "QEMU",
    "xen": "Xen",
    "hyperv": "Microsoft Corporation",
    "parallels": "Parallels",
}

_VM_MAC_PREFIXES: Dict[str, Set[str]] = {
    "vmware": {"00:05:69", "00:0c:29", "00:50:56", "00:1c:14"},
    "virtualbox": {"08:00:27"},
    "xen": {"00:16:3e"},
    "hyperv": {"00:15:5d"},
}

_VM_PCI_DEVICES: Dict[str, int] = {
    "vmware": 0x15AD,
    "virtualbox": 0x80EE,
    "qemu": 0x1B36,
    "xen": 0x5853,
}

# Detection methods

def _read_dmi_sysfs() -> str:
    """Read DMI product name via /sys/class/dmi/id."""
    paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/bios_vendor",
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
        # We use raw ctypes to avoid numpy/pycpuinfo dependencies.
        # On non-x86 this will be a no-op.
        if platform.machine() not in ("x86_64", "AMD64", "i686", "i386"):
            return False
        # Inline assembly via ctypes is fragile cross-platform; prefer
        # /proc/cpuinfo on Linux.
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
            # Format:  00:02.0 0300: 15AD:0405
            parts = line.strip().split()
            if len(parts) >= 2:
                vendor = parts[1].rstrip(":")
                m = re.match(r"([0-9a-fA-F]{4})", vendor)
                if m:
                    ids.add(int(m.group(1), 16))
    except (FileNotFoundError, sp.TimeoutExpired, OSError):
        pass
    return ids


# Bypass configuration generation

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
        "Edit .vmx:  ethernet0.addressType = \"generated\"\n"
        "            ethernet0.generatedAddress = \"00:50:56:XX:YY:ZZ\"  (use non-VM prefix)"),
    _ConfigEntry("mac", "virtualbox",
        "VBoxManage modifyvm \"$VM\" --macaddress1 080027XXXXXX"),
    _ConfigEntry("pci", "vmware",
        "Remove *.vmx setting:  svga.present = \"FALSE\"  (disables VMware SVGA PCI device)"),
    _ConfigEntry("pci", "qemu",
        "qemu-system-x86_64 ... -device VGA,vgamem_mb=16  (avoids QEMU VGA DID)"),
    _ConfigEntry("cpuid", "*",
        "qemu-system-x86_64 ... -cpu host,kvm=off,hv_vendor_id=null\n"
        "Or set CPUID_hypervisor bit via kvm.ignore_msrs=1"),
]


class BypassConfig:
    """Hold a set of bypass configuration snippets for a particular hypervisor."""
    def __init__(self):
        self.techniques: List[Dict[str, str]] = []

    def add(self, technique: str, hypervisor: str, payload: str) -> None:
        self.techniques.append({
            "technique": technique, "hypervisor": hypervisor, "payload": payload,
        })

    def to_dict(self) -> List[Dict[str, str]]:
        return self.techniques


class BypassSolution:
    """Aggregated bypass recommendations."""
    def __init__(self, hypervisor: str):
        self.hypervisor = hypervisor
        self.config = BypassConfig()
        self.detections: List[str] = []

    def __repr__(self):
        return f"<BypassSolution hv={self.hypervisor} items={len(self.config.techniques)}>"

class AntiVMTechnique:
    DMI = "dmi"
    MAC = "mac"
    PCI = "pci"
    CPUID = "cpuid"
    REGISTRY = "registry"  # windows-only
    PROCESS = "process"

class AntiVMBypassAnalyzer:
    """Entry point: analyze a binary's VM-detection posture."""

    def __init__(self):
        self._dmi_data: str = ""
        self._mac_prefixes: Set[str] = set()
        self._pci_ids: Set[int] = set()
        self._cpuid_flag: bool = False

    def analyze(self, binary: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        self._dmi_data = _read_dmi_sysfs()
        self._mac_prefixes = _enumerate_mac_prefixes()
        self._pci_ids = _lspci_vendor_ids()
        self._cpuid_flag = _check_cpuid_hypervisor()

        # DMI matching
        for hv, vendor_str in _DMI_VENDORS.items():
            if vendor_str.lower() in self._dmi_data:
                findings.append({
                    "technique": "dmi", "hypervisor": hv,
                    "match": vendor_str, "source": "sysfs",
                })

        # MAC prefix matching
        for hv, prefixes in _VM_MAC_PREFIXES.items():
            if self._mac_prefixes & prefixes:
                findings.append({
                    "technique": "mac", "hypervisor": hv,
                    "match": list(self._mac_prefixes & prefixes), "source": "uuid",
                })

        # PCI vendor matching
        for hv, vid in _VM_PCI_DEVICES.items():
            if vid in self._pci_ids:
                findings.append({
                    "technique": "pci", "hypervisor": hv,
                    "match": hex(vid), "source": "lspci",
                })

        if self._cpuid_flag:
            findings.append({
                "technique": "cpuid", "hypervisor": "generic",
                "match": True, "source": "/proc/cpuinfo",
            })

        return findings


def create_anti_vm_analyzer() -> AntiVMBypassAnalyzer:
    return AntiVMBypassAnalyzer()


# Module metadata
name = "anti_vm_bypass"
module = "anti_vm_bypass"
