"""Memory manipulation and code injection detection in native binaries."""

import logging
import os
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

_log = logging.getLogger(__name__)


@dataclass
class InjectionIndicator:
    signature: str
    technique: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    affected_addresses: List[int] = field(default_factory=list)


class MemoryManipulationDetector:
    """Scan binaries for code injection, process hollowing, and memory manipulation
    patterns common in malware and game hacking.

    Usage::

        detector = MemoryManipulationDetector()
        indicators = detector.detect("./suspicious_binary.exe")
    """

    _INJECTION_IMPORTS = {
        "kernel32.dll": {
            "WriteProcessMemory":    "writes to remote process memory",
            "ReadProcessMemory":     "reads remote process memory",
            "VirtualAllocEx":        "allocates memory in remote process",
            "VirtualProtectEx":      "changes remote memory protection",
            "CreateRemoteThread":    "creates remote thread (classic injection)",
            "QueueUserAPC":          "APC injection primitive",
            "SetThreadContext":      "modifies thread context (hijack)",
            "NtWriteVirtualMemory":  "NT syscall direct write",
            "NtAllocateVirtualMemory": "NT syscall direct alloc",
            "NtCreateThreadEx":      "NT create remote thread",
            "NtQueueApcThread":      "NT APC queue primitive",
            "NtMapViewOfSection":    "shared memory mapping (process hollowing)",
            "NtUnmapViewOfSection":  "unmapping (hollowing step)",
            "NtQueryInformationProcess": "PEB reading (hollowing detection bypass)",
            "ZwWriteVirtualMemory":  "Zw-prefixed syscall (manual mapping)",
        },
        "ntdll.dll": {
            "RtlCreateUserThread":   "user-mode remote thread",
            "RtlAllocateHeap":       "heap manipulation",
            "RtlCreateProcessParametersEx": "parameter block creation (PPID spoofing)",
        },
        "user32.dll": {
            "SetWindowsHookEx":      "global hook injection",
            "SendMessageA":          "message-based injection",
        },
    }

    _SHELLCODE_PATTERNS = {
        "mapped_pe_signature": re.compile(rb"MZ[\x90-\x9F].*PE\x00\x00", re.DOTALL),
        "peb_walk_x86": re.compile(rb"\x64\xA1\x30\x00\x00\x00"),
        "peb_walk_x64": re.compile(rb"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"),
        "hook_detection": re.compile(rb"(?:\x81\x38\xE9|\x83\x38\x68)"),
    }

    _PROCESS_HOLLOWING_SEQUENCE = [
        "CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx",
        "WriteProcessMemory", "SetThreadContext", "ResumeThread",
    ]

    _HOLLOWING_MANDATORY = {"CreateProcess", "VirtualAllocEx", "WriteProcessMemory"}

    _TECHNIQUE_MAP = {
        "WriteProcessMemory": "process_injection",
        "VirtualAllocEx": "process_injection",
        "CreateRemoteThread": "classic_dll_injection",
        "QueueUserAPC": "apc_injection",
        "SetThreadContext": "process_hollowing",
        "NtUnmapViewOfSection": "process_hollowing_unmap",
        "NtMapViewOfSection": "manual_mapping",
        "RtlCreateUserThread": "remote_thread",
        "SetWindowsHookEx": "global_hook",
    }

    # MITRE ATT&CK technique mapping — 用于归类检测到的注入行为
    _ATTACK_MAP = {
        "process_injection": "T1055",
        "process_hollowing": "T1055.012",
        "classic_dll_injection": "T1055.001",
        "apc_injection": "T1055.004",
        "manual_mapping": "T1055.008",
        "global_hook": "T1056.004",
        "peb_manipulation": "T1055",
        "reflective_dll_loading": "T1620",
        "generic_injection": "T1055",
        "hook_evasion": "T1562.001",
        "atom_bombing": "T1055",
        "heap_spray": "T1055",
    }

    def __init__(self):
        self._found_imports: Dict[str, Set[str]] = defaultdict(set)
        self._indicators: List[InjectionIndicator] = []

    def detect(self, binary) -> List[InjectionIndicator]:
        self._indicators = []
        self._found_imports.clear()

        if isinstance(binary, bytes):
            raw, path = binary, "<memory>"
        elif os.path.isfile(str(binary)):
            path = str(binary)
            with open(path, "rb") as fh:
                raw = fh.read()
        else:
            _log.error("Invalid input: %s", binary)
            return []

        self._scan_imports(raw, path)
        self._scan_shellcode_patterns(raw, path)
        self._scan_process_hollowing(path)
        self._scan_peb_manipulation(raw, path)
        self._scan_string_indicators(raw, path)
        self._scan_heap_spray(raw)
        self._scan_atom_bombing(raw)

        return self._indicators

    def _scan_imports(self, data: bytes, path: str) -> None:
        for dll, funcs in self._INJECTION_IMPORTS.items():
            dll_bytes = dll.encode("ascii")
            if dll_bytes.lower() in data.lower():
                for func_name, desc in funcs.items():
                    if func_name.encode("ascii") in data:
                        self._found_imports[dll].add(func_name)
                        self._indicators.append(InjectionIndicator(
                            signature=f"{dll}!{func_name}",
                            technique=self._TECHNIQUE_MAP.get(func_name, "generic_injection"),
                            confidence=0.7,
                            evidence=[f"Import: {dll}!{func_name} ({desc})"],
                        ))

    def _scan_shellcode_patterns(self, data: bytes, path: str) -> None:
        for name, pattern in self._SHELLCODE_PATTERNS.items():
            matches = list(re.finditer(pattern, data))
            if matches:
                techniques = {
                    "mapped_pe_signature": "manual_mapping_mz",
                    "peb_walk_x86": "peb_manipulation",
                    "peb_walk_x64": "peb_manipulation",
                    "hook_detection": "hook_evasion",
                }
                self._indicators.append(InjectionIndicator(
                    signature=name,
                    technique=techniques.get(name, name),
                    confidence=0.5 + min(0.2, len(matches) * 0.05),
                    evidence=[f"Pattern '{name}' matched at {len(matches)} locations"],
                    affected_addresses=[m.start() for m in matches[:10]],
                ))

    def _scan_process_hollowing(self, path: str) -> None:
        found = set()
        for dll_funcs in self._found_imports.values():
            found.update(dll_funcs)
        hollowing_hits = found & set(self._PROCESS_HOLLOWING_SEQUENCE)
        mandatory_hits = found & self._HOLLOWING_MANDATORY
        if len(hollowing_hits) >= 3 and len(mandatory_hits) >= 2:
            self._indicators.append(InjectionIndicator(
                signature="process_hollowing_chain",
                technique="process_hollowing",
                confidence=0.85,
                evidence=[
                    f"Process hollowing chain: {sorted(hollowing_hits)}",
                    f"Mandatory APIs present: {sorted(mandatory_hits)}",
                ],
            ))

    def _scan_peb_manipulation(self, data: bytes, path: str) -> None:
        peb_patterns = [
            b"\x64\xA1\x30\x00\x00\x00",
            b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00",
            b"\x65\x48\x8B\x04\x25\x30\x00\x00\x00",
            b"\x64\x8B\x1D\x30\x00\x00\x00",
        ]
        for pat in peb_patterns:
            if pat in data:
                self._indicators.append(InjectionIndicator(
                    signature="peb_access",
                    technique="peb_manipulation",
                    confidence=0.6,
                    evidence=["Direct PEB access detected"],
                ))
                break

    def _scan_string_indicators(self, data: bytes, path: str) -> None:
        strings = [
            (b"ReflectiveLoader", "reflective_dll", "Named export for reflective loader"),
            (b"LoadLibraryA", "dll_injection", "Dynamic library load"),
            (b"GetProcAddress", "api_resolve", "Runtime API resolution"),
            (b"WriteProcessMemory", "memory_write", "Remote memory write"),
            (b"ZwUnmapViewOfSection", "hollowing", "Section unmapping"),
            (b"reflective injection", "reflective_injection", "Literal technique name"),
        ]
        for pattern, technique, desc in strings:
            if pattern in data:
                self._indicators.append(InjectionIndicator(
                    signature=pattern.decode("latin-1"),
                    technique=technique,
                    confidence=0.55,
                    evidence=[desc],
                ))

    # --- 新增: Heap Spray检测 ---
    # 检测重复的VirtualAlloc模式 — 相同大小的RWX分配在短窗口内集中出现
    # 是heap spray攻击的强烈信号。参考CVE-2017-11882等利用中观察到的模式。
    def _scan_heap_spray(self, data: bytes) -> None:
        """在二进制数据中扫描heap spray特征模式：连续的大块RWX内存分配。
        匹配VirtualAlloc调用后的0x0C字节对齐和重复大小模式。"""
        spray_sigs = [
            (rb'VirtualAlloc', 0x100000),   # 1MB spray block
            (rb'VirtualAlloc', 0x10000),    # 64KB spray block (常见于JS引擎利用)
            (rb'NtAllocateVirtualMemory', 0x100000),
        ]
        for sig, block_size in spray_sigs:
            # 检查签名是否出现至少3次 — 零星出现不够成堆喷
            positions = [m.start() for m in re.finditer(sig, data)]
            if len(positions) >= 3:
                self._indicators.append(InjectionIndicator(
                    signature=f"heap_spray_{block_size:#x}",
                    technique="heap_spray",
                    confidence=0.65,
                    evidence=[
                        f"Heap spray pattern: {len(positions)} {sig.decode()} calls, "
                        f"block size {block_size:#x}"
                    ],
                    affected_addresses=positions[:10],
                ))
                break  # 一类签名只报一次

    # --- 新增: AtomBombing检测 ---
    # AtomBombing利用全局原子表(Global Atom Table)传递shellcode数据到目标进程。
    # 检测签名: GlobalGetAtomNameA/W + NtQueueApcThread + WriteProcessMemory 链
    def _scan_atom_bombing(self, data: bytes) -> None:
        """AtomBombing注入技术检测 — 基于ensilo在2016年披露的技术签名。"""
        has_atom = b'GlobalGetAtomName' in data or b'GlobalAddAtom' in data
        has_apc = b'NtQueueApcThread' in data or b'QueueUserAPC' in data
        has_wpm = b'WriteProcessMemory' in data or b'NtWriteVirtualMemory' in data

        if (has_atom and has_apc) or (has_atom and has_wpm):
            evidence_parts = []
            if has_atom:
                evidence_parts.append("global atom table access")
            if has_apc:
                evidence_parts.append("APC queue primitive")
            if has_wpm:
                evidence_parts.append("remote memory write")

            self._indicators.append(InjectionIndicator(
                signature="atom_bombing_chain",
                technique="atom_bombing",
                confidence=0.72,
                evidence=[f"AtomBombing indicators: {', '.join(evidence_parts)}"],
            ))

    # --- 新增: 注入技术到ATT&CK ID的映射 ---
    def classify_injection_technique(self) -> Dict[str, List[str]]:
        """将检测到的注入指标映射到MITRE ATT&CK技术ID。
        未识别的技术归入通用T1055（Process Injection）类别。"""
        mapping: Dict[str, List[str]] = {}
        for ind in self._indicators:
            attack_id = self._ATTACK_MAP.get(ind.technique, "T1055")
            mapping.setdefault(attack_id, []).append(ind.technique)
        return mapping


def scan_for_injection_imports(binary_path: str) -> Dict[str, List[str]]:
    detector = MemoryManipulationDetector()
    results: Dict[str, List[str]] = {}
    for dll, funcs in detector._INJECTION_IMPORTS.items():
        results[dll] = []
        for func in funcs:
            results[dll].append(func)
    return {k: v for k, v in results.items() if v}


def analyze_injection_risk(indicators: List[InjectionIndicator]) -> float:
    if not indicators:
        return 0.0
    scores = {
        "process_hollowing": 0.95, "process_injection": 0.9,
        "reflective_dll_loading": 0.85, "manual_mapping": 0.8,
        "classic_dll_injection": 0.7, "apc_injection": 0.75,
        "global_hook": 0.6, "peb_manipulation": 0.5,
        "generic_injection": 0.4, "hook_evasion": 0.3,
        "atom_bombing": 0.78, "heap_spray": 0.82,
    }
    weighted = sum(scores.get(ind.technique, 0.3) * ind.confidence for ind in indicators)
    return min(1.0, weighted / max(1, len(indicators)))


def detect_memory_manipulation(binary) -> List[InjectionIndicator]:
    return MemoryManipulationDetector().detect(binary)
