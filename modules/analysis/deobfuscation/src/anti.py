# 反分析 反虚拟机检测

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AntiAnalysis:

    ANTI_DEBUG_PATTERNS: Dict[str, List[str]] = {
        "ptrace": [
            "ptrace",
            "PTRACE_TRACEME",
            "PTRACE_ATTACH",
            "PTRACE_DETACH",
        ],
        "proc_status": [
            "/proc/self/status",
            "TracerPid",
            "tracer_pid",
        ],
        "timing": [
            "rdtsc",
            "time",
            "clock_gettime",
            "QueryPerformanceCounter",
            "GetTickCount",
        ],
        "ld_preload": [
            "LD_PRELOAD",
        ],
        "debugger_present": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "DebugActiveProcess",
        ],
        "int3": [
            "int 3",
            "int3",
            "int 0x3",
        ],
    }

    DEBUGGER_PORTS: List[int] = [1234, 2345, 4444, 23946, 31337, 9999]

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def detect_ptrace(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code)

        for pattern in self.ANTI_DEBUG_PATTERNS["ptrace"]:
            if pattern.lower() in combined.lower():
                findings.append({
                    "technique": "ptrace_anti_debug",
                    "pattern": pattern,
                    "severity": "high",
                    "recommendation": "Hook ptrace() via LD_PRELOAD or use patched libc",
                })

        return findings

    def detect_proc_checks(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code)

        has_proc = "/proc/self/status" in combined
        has_tracer = "TracerPid" in combined.lower()

        if has_proc and has_tracer:
            findings.append({
                "technique": "proc_tracerpid_check",
                "pattern": "/proc/self/status + TracerPid",
                "severity": "medium",
                "recommendation": "Hook fopen/fread to return fake TracerPid: 0",
            })
        elif has_proc:
            findings.append({
                "technique": "proc_status_read",
                "pattern": "/proc/self/status",
                "severity": "low",
                "recommendation": "Monitor /proc access patterns",
            })

        return findings

    def detect_timing_checks(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code).lower()

        timing_hits = []
        for pattern in self.ANTI_DEBUG_PATTERNS["timing"]:
            if pattern.lower() in combined:
                timing_hits.append(pattern)

        if timing_hits:
            findings.append({
                "technique": "timing_anti_debug",
                "patterns": timing_hits,
                "severity": "medium",
                "recommendation": (
                    "Add timing jitter (random 0-50ms delay) to defeat "
                    "simple timing checks; hook rdtsc to return incrementing values"
                ),
            })

        return findings

    def detect_env_checks(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code)

        if "LD_PRELOAD" in combined:
            findings.append({
                "technique": "ld_preload_check",
                "pattern": "LD_PRELOAD",
                "severity": "low",
                "recommendation": (
                    "Unset LD_PRELOAD before execution or use direct syscalls"
                ),
            })

        return findings

    def detect_debugger_check(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code).lower()

        for pattern in self.ANTI_DEBUG_PATTERNS["debugger_present"]:
            if pattern.lower() in combined:
                findings.append({
                    "technique": "debugger_check",
                    "pattern": pattern,
                    "severity": "high",
                    "recommendation": (
                        "Hook IsDebuggerPresent to return FALSE; "
                        "patch PEB.BeingDebugged to 0"
                    ),
                })

        return findings

    def analyze(
        self, strings_or_code: List[str]
    ) -> Dict[str, Any]:
        all_findings: List[Dict[str, Any]] = []
        all_findings.extend(self.detect_ptrace(strings_or_code))
        all_findings.extend(self.detect_proc_checks(strings_or_code))
        all_findings.extend(self.detect_timing_checks(strings_or_code))
        all_findings.extend(self.detect_env_checks(strings_or_code))
        all_findings.extend(self.detect_debugger_check(strings_or_code))

        recommendations = self.generate_bypass_recommendations(all_findings)

        return {
            "detected": all_findings,
            "count": len(all_findings),
            "recommendations": recommendations,
            "has_anti_debug": len(all_findings) > 0,
        }

    def generate_bypass_recommendations(
        self, detected: List[Dict[str, Any]]
    ) -> List[str]:
        seen: set = set()
        recommendations: List[str] = []
        for finding in detected:
            rec = finding.get("recommendation", "")
            if rec and rec not in seen:
                seen.add(rec)
                recommendations.append(rec)
        return recommendations

    def _check_ptrace_fallback(self, code: List[str]) -> bool:
        for line in code:
            if "101" in line and ("syscall" in line.lower() or "int 0x80" in line.lower()):
                return True
        return False




class AntiVMBypass:

    VM_SIGNATURES: Dict[str, Dict[str, Any]] = {
        "VMware": {
            "dmi": ["VMware", "VMware Virtual Platform", "Mware"],
            "mac_prefixes": ["00:0c:29", "00:50:56", "00:05:69"],
            "pci_vendor": 0x15AD,
            "cpuid_hypervisor": "VMwareVMware",
            "registry_keys": [
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\vmx86",
            ],
        },
        "VirtualBox": {
            "dmi": ["VirtualBox", "VBOX", "innotek GmbH"],
            "mac_prefixes": ["08:00:27"],
            "pci_vendor": 0x80EE,
            "cpuid_hypervisor": "VBoxVBoxVBox",
            "registry_keys": [
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
            ],
        },
        "QEMU": {
            "dmi": ["QEMU", "KVM", "QEMU Virtual CPU"],
            "mac_prefixes": ["52:54:00"],
            "pci_vendor": 0x1AF4,
            "cpuid_hypervisor": "KVMKVMKVM",
        },
        "Hyper-V": {
            "dmi": ["Hyper-V", "Virtual Machine", "Microsoft Corporation"],
            "mac_prefixes": ["00:15:5d"],
            "cpuid_hypervisor": "Microsoft Hv",
        },
        "Xen": {
            "dmi": ["Xen", "XEN", "Xen Project"],
            "mac_prefixes": ["00:16:3e"],
            "cpuid_hypervisor": "XenVMMXenVMM",  # noqa: E501
        },
    }

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def _check_vm_vendor(
        self,
        strings_or_code: List[str],
        vm_name: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        sigs = self.VM_SIGNATURES.get(vm_name)
        if not sigs:
            return findings

        combined = " ".join(strings_or_code)
        combined_lower = combined.lower()

        # 检查 DMI strings
        for dmi_str in sigs.get("dmi", []):
            if dmi_str.lower() in combined_lower:
                findings.append({
                    "vm": vm_name,
                    "technique": "dmi_check",
                    "evidence": dmi_str,
                    "confidence": 0.70,
                })

        # 检查 MAC prefixes
        mac_prefixes = sigs.get("mac_prefixes", [])
        for prefix in mac_prefixes:
            if prefix.lower() in combined_lower:
                findings.append({
                    "vm": vm_name,
                    "technique": "mac_check",
                    "evidence": prefix,
                    "confidence": 0.65,
                })

        # 检查 CPUID 虚拟机监控器 string
        cpuid_str = sigs.get("cpuid_hypervisor", "")
        if cpuid_str and cpuid_str.lower() in combined_lower:
            findings.append({
                "vm": vm_name,
                "technique": "cpuid_check",
                "evidence": cpuid_str,
                "confidence": 0.90,
            })

        # 检查 registry keys
        for reg_key in sigs.get("registry_keys", []):
            if reg_key.lower() in combined_lower:
                findings.append({
                    "vm": vm_name,
                    "technique": "registry_check",
                    "evidence": reg_key,
                    "confidence": 0.80,
                })

        return findings

    def detect_vmware(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        return self._check_vm_vendor(strings_or_code, "VMware")

    def detect_virtualbox(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        return self._check_vm_vendor(strings_or_code, "VirtualBox")

    def detect_qemu(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        return self._check_vm_vendor(strings_or_code, "QEMU")

    def detect_hyperv(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        return self._check_vm_vendor(strings_or_code, "Hyper-V")

    def detect_xen(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        return self._check_vm_vendor(strings_or_code, "Xen")

    def detect_generic_vm(
        self, strings_or_code: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        combined = " ".join(strings_or_code).lower()

        generic_strings = [
            "hypervisor",
            "cpuid",
            "sandbox",
            "sandboxie",
            "wine",
            "cuckoo",
            "vbox",
            "vmtools",
        ]

        for gs in generic_strings:
            if gs in combined:
                findings.append({
                    "vm": "Generic",
                    "technique": "generic_string",
                    "evidence": gs,
                    "confidence": 0.50,
                })

        return findings

    def analyze(
        self, strings_or_code: List[str]
    ) -> Dict[str, Any]:
        all_findings: List[Dict[str, Any]] = []
        all_findings.extend(self.detect_vmware(strings_or_code))
        all_findings.extend(self.detect_virtualbox(strings_or_code))
        all_findings.extend(self.detect_qemu(strings_or_code))
        all_findings.extend(self.detect_hyperv(strings_or_code))
        all_findings.extend(self.detect_xen(strings_or_code))
        all_findings.extend(self.detect_generic_vm(strings_or_code))

        recommendations = self.generate_bypass_recommendations(all_findings)

        vm_types: Dict[str, float] = {}
        for f in all_findings:
            vm = f.get("vm", "Unknown")
            conf = f.get("confidence", 0.0)
            vm_types[vm] = max(vm_types.get(vm, 0.0), conf)

        primary_vm = max(vm_types, key=vm_types.get) if vm_types else "None"

        return {
            "detected": all_findings,
            "count": len(all_findings),
            "primary_vm": primary_vm,
            "confidence": vm_types.get(primary_vm, 0.0),
            "recommendations": recommendations,
            "is_vm": len(all_findings) > 0,
        }

    def generate_bypass_recommendations(
        self, detected: List[Dict[str, Any]]
    ) -> List[str]:
        recs: List[str] = []
        seen: set = set()

        vm_specific_recs: Dict[str, str] = {
            "VMware": "Patch VMware backdoor I/O port (0x5658); spoof MAC to non-VMware prefix",
            "VirtualBox": "Patch VBoxGuest IOCTL; modify DMI BIOS vendor string",
            "QEMU": "Patch CPUID leaf 0x40000000; modify /sys/class/dmi/id/product_name",
            "Hyper-V": "Patch hypervisor CPUID bit (leaf 0x1, bit 31); remove Hyper-V enlightenments",
            "Xen": "Patch Xen-specific CPUID leaves (0x40000000+); spoof DMI strings",
        }

        for finding in detected:
            vm_name = finding.get("vm", "")
            technique = finding.get("technique", "")

            if vm_name in vm_specific_recs:
                rec = vm_specific_recs[vm_name]
                if rec not in seen:
                    seen.add(rec)
                    recs.append(rec)

        if not recs:
            recs.append(
                "No VM detected. If running in a VM, consider patching "
                "CPUID hypervisor-present bit and spoofing DMI/MAC values."
            )

        return recs
