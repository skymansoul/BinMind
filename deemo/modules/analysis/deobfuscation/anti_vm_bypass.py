from typing import Dict, List, Set, Any

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


_DMI_TYPE_NAMES = {0: "BIOS", 1: "System", 2: "Baseboard", 3: "Chassis"}

def _read_smbios_raw() -> bytes:
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
    hits: Dict[str, str] = {}
    if len(raw) < 32:
        return hits
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


def _enumerate_pci_devices_sysfs() -> Set[int]:
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
    node = uuid.getnode()
    mac = node & 0xFFFFFFFFFFFF
    if mac == 0 or mac == 0x010000000000:
        return set()
    octets = [(mac >> (40 - 8 * i)) & 0xFF for i in range(6)]
    return {":".join(f"{b:02x}" for b in octets[:3])}


def _check_cpuid_hypervisor() -> bool:
    try:
        if platform.machine() not in ("x86_64", "AMD64", "i686", "i386"):
            return False
        with open("/proc/cpuinfo") as fh:
            return "hypervisor" in fh.read().lower()
    except Exception:
        return False
        with open("/proc/cpuinfo") as fh:
            return "hypervisor" in fh.read().lower()
    except Exception:
        return False


def _lspci_vendor_ids() -> Set[int]:
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
    def __init__(self, output_dir=None, generate_scripts=True,
                 max_analysis_time=300, use_unicorn=True,
                 target_functions=None, **kwargs):
        self.techniques: List[Dict[str, str]] = []
        self.output_dir = output_dir
        self.generate_scripts = generate_scripts
        self.max_analysis_time = max_analysis_time
        self.use_unicorn = use_unicorn
        self.target_functions = list(target_functions) if target_functions else []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def validate(self) -> bool:
        return True

    def add(self, technique: str, hypervisor: str, payload: str) -> None:
        self.techniques.append({
            "technique": technique, "hypervisor": hypervisor, "payload": payload})

    def to_dict(self) -> List[Dict[str, str]]:
        return self.techniques


class BypassSolution:
    def __init__(self, technique=None, solved_values=None, script="",
                 script_type="", hypervisor="", **kwargs):
        self.technique = technique
        self.solved_values = solved_values if solved_values is not None else {}
        self.script = script
        self.script_type = script_type
        self.hypervisor = hypervisor
        self.config = BypassConfig()
        self.detections: List[str] = []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique.to_dict() if hasattr(self.technique, "to_dict") else str(self.technique),
            "solution_type": getattr(self, "solution_type", ""),
            "constraints": list(getattr(self, "constraints", [])),
            "script": self.script,
            "script_type": self.script_type,
            "solved_values": dict(self.solved_values),
            "confidence": getattr(self, "confidence", 0.0),
        }

    def __repr__(self):
        return f"<BypassSolution hv={self.hypervisor} items={len(self.config.techniques)}>"


class AntiVMTechnique:
    DMI = "dmi"; MAC = "mac"; PCI = "pci"; CPUID = "cpuid"
    REGISTRY = "registry"; PROCESS = "process"; DEV_NODE = "dev_node"
    TIMING = "timing"; ACPI = "acpi"; DRIVER = "driver"
    SMBIOS = "smbios"; PCI_SYSFS = "pci_sysfs"

    def __init__(self, name="", address="", detection_type="", description="",
                 severity="", bypass_possible=False, **kwargs):
        self.name = name
        self.address = address
        self.detection_type = detection_type
        self.description = description
        self.severity = severity
        self.bypass_possible = bypass_possible
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": self.address,
            "detection_type": self.detection_type,
            "description": self.description,
            "severity": self.severity,
            "bypass_possible": self.bypass_possible,
        }


class AntiVMBypassAnalyzer:

    def __init__(self, config=None, **kwargs):
        self.config = config if config is not None else BypassConfig()
        self.binary_path: str = ""
        self.binary_data: bytes = b""
        self.solutions: List[BypassSolution] = []
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

    def analyze(self, binary: str) -> dict:
        self.load_binary(binary)
        self._last_techniques = self.detect_anti_vm_techniques()
        return {
            'binary_path': self.binary_path,
            'techniques_detected': [t.to_dict() for t in self._last_techniques],
            'summary': self._generate_summary(),
        }

    def load_binary(self, binary_path: str) -> bool:
        try:
            with open(binary_path, 'rb') as fh:
                self.binary_data = fh.read()
            self.binary_path = binary_path
            return True
        except OSError:
            return False

    def detect_anti_vm_techniques(self) -> List[AntiVMTechnique]:
        techniques: List[AntiVMTechnique] = []
        data = self.binary_data
        if b'cpuid' in data:
            techniques.append(AntiVMTechnique(
                name='cpuid_check', detection_type='cpuid_check',
                description='CPUID 指令检测虚拟机', severity='High', bypass_possible=True))
        if b'VMware' in data or b'vmware' in data:
            techniques.append(AntiVMTechnique(
                name='vmware_detect', detection_type='string_check',
                description='VMware 字符串特征', severity='Medium', bypass_possible=True))
        if b'/proc/cpuinfo' in data or b'/sys/hypervisor' in data:
            techniques.append(AntiVMTechnique(
                name='file_check', detection_type='file_check',
                description='虚拟化文件系统路径检测', severity='Medium', bypass_possible=True))
        return techniques

    def generate_bypass_scripts(self) -> List[BypassSolution]:
        solutions: List[BypassSolution] = []
        for tech in getattr(self, '_last_techniques', []):
            sol = BypassSolution(technique=tech)
            if tech.detection_type == 'cpuid_check':
                sol.script = self._generate_cpuid_frida_script(sol)
                sol.script_type = 'frida'
            elif tech.detection_type == 'file_check':
                sol.script = self._generate_ldpreload_script(sol)
                sol.script_type = 'ld_preload'
            elif tech.detection_type == 'timing_check':
                sol.script = self._generate_timing_frida_script(sol)
                sol.script_type = 'frida'
            solutions.append(sol)
        self.solutions = solutions
        return solutions

    def _generate_cpuid_frida_script(self, solution) -> str:
        return ("Interceptor.attach(Module.findExportByName(null, 'CPUID'), {\n"
                "  onEnter: function(args) { console.log('CPUID intercepted'); }\n"
                "});")

    def _generate_timing_frida_script(self, solution) -> str:
        return ("Interceptor.attach(Module.findExportByName(null, 'rdtsc'), {\n"
                "  onEnter: function(args) { console.log('rdtsc intercepted'); }\n"
                "});")

    def _generate_ldpreload_script(self, solution) -> str:
        return ("#define _GNU_SOURCE\n"
                "#include <stdio.h>\n"
                "#include <unistd.h>\n"
                "int access(const char *p, int m) { return 0; }\n"
                "FILE *fopen(const char *p, const char *m) { return NULL; }")

    def save_scripts(self) -> List[str]:
        saved = []
        for idx, sol in enumerate(self.solutions):
            if not sol.script:
                continue
            path = os.path.join(self.config.output_dir or '.', 'bypass_%d.%s' % (idx, sol.script_type or 'txt'))
            try:
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(sol.script)
                saved.append(path)
            except OSError:
                pass
        return saved

    def generate_report(self) -> dict:
        return {
            'binary_path': self.binary_path,
            'techniques_detected': [t.to_dict() for t in getattr(self, '_last_techniques', [])],
            'summary': self._generate_summary(),
        }

    def _generate_summary(self) -> str:
        n = len(getattr(self, '_last_techniques', []))
        return '检测到 %d 种反虚拟机技术' % n

    def _generate_recommendations(self) -> List[str]:
        return ['打补丁', '升级到最新版本', '隔离虚拟化检测代码']


def create_anti_vm_analyzer(config=None) -> AntiVMBypassAnalyzer:
    return AntiVMBypassAnalyzer(config)


name = "anti_vm_bypass"
module = "anti_vm_bypass"
