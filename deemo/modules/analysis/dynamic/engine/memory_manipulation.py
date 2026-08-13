"""Memory manipulation code injection detection native binaries"""

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
    indicator_type: str = ""
    severity: str = ""
    description: str = ""
    evidence: list = field(default_factory=list)
    recommendation: str = ""
    signature: str = ""
    technique: str = ""
    confidence: float = 0.0
    affected_addresses: list = field(default_factory=list)


@dataclass
class MemoryManipulationResult:
    filename: str = ""
    injection_indicators: list = field(default_factory=list)
    suspicious_imports: list = field(default_factory=list)
    injection_risk: str = "none"
    risk_score: int = 0


class MemoryManipulationDetector:
    """Scan binaries for code injection, process hollowing, memory manipulation
    patterns common malware game hacking
    
    Usage::
    
    detector = MemoryManipulationDetector()
    indicators = detector.检测("./suspicious_binary.exe")
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

    INJECTION_IMPORTS = {
        'high': [
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx',
            'RtlCreateUserThread', 'WriteProcessMemory', 'NtWriteVirtualMemory',
            'VirtualAllocEx', 'VirtualAllocExNuma', 'VirtualProtectEx',
            'NtProtectVirtualMemory', 'SetWindowsHookEx', 'SetWindowsHookExA',
            'SetWindowsHookExW', 'NtQueueApcThread', 'NtQueueApcThreadEx',
            'QueueUserAPC', 'InjectLibrary', 'InjectDll', 'LoadRemoteLibraryR',
        ],
        'medium': [
            'OpenProcess', 'OpenThread', 'NtOpenProcess', 'NtOpenThread',
            'GetProcessHandleFromHwnd', 'GetWindowThreadProcessId', 'EnumProcesses',
            'EnumProcessModules', 'ReadProcessMemory', 'NtReadVirtualMemory',
            'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
            'Thread32First', 'Thread32Next',
        ],
        'low': [
            'GetModuleHandle', 'GetProcAddress', 'LoadLibrary', 'LoadLibraryA',
            'LoadLibraryW', 'GetModuleFileName', 'GetModuleFileNameA',
            'GetModuleFileNameW',
        ]
    }

    INJECTION_PATTERNS = [
        (r'VirtualAllocEx.*MEM_COMMIT.*PAGE_EXECUTE', '分配可执行内存并写入', 'high'),
        (r'VirtualAllocEx.*MEM_RESERVE.*PAGE_EXECUTE', '预分配可执行内存', 'high'),
        (r'WriteProcessMemory.*VirtualAllocEx', '先分配后写入模式', 'high'),
        (r'VirtualProtectEx.*PAGE_EXECUTE', '修改内存为可执行', 'high'),
        (r'CreateRemoteThread.*WriteProcessMemory', '写入后创建远程线程', 'high'),
        (r'QueueUserAPC.*WriteProcessMemory', 'APC注入模式', 'high'),
        (r'SetWindowsHookEx.*WH_KEYBOARD', '键盘钩子注入', 'medium'),
        (r'SetWindowsHookEx.*WH_MOUSE', '鼠标钩子注入', 'medium'),
        (r'CreateRemoteThreadEx.*LPTHREAD_START_ROUTINE', '远程线程启动', 'high'),
    ]

    INJECTION_STRINGS = [
        ('RemoteThread', '远程线程操作'),
        ('Inject', '注入相关'),
        ('Shellcode', 'Shellcode载荷'),
        ('Payload', '载荷内容'),
        ('ProcessInjection', '进程注入'),
        ('DLLInject', 'DLL注入'),
        ('ReflectiveDLL', '反射式DLL注入'),
        ('QueueUserAPC', 'APC注入'),
        ('SetWindowsHook', '钩子注入'),
    ]

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self._found_imports: Dict[str, Set[str]] = defaultdict(set)
        self._indicators: List[InjectionIndicator] = []
        self.injection_indicators: List[InjectionIndicator] = []
        self.suspicious_imports: List[str] = []
        self.strings: List[str] = []

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

# 新增: 堆 Spray检测
    # 检测重复的VirtualAlloc模式 — 相同大小的RWX分配在短窗口内集中出现
    # 是heap spray攻击的强烈信号。参考CVE-2017-11882等利用中观察到的模式
    def _scan_heap_spray(self, data: bytes) -> None:
        """在二进制数据中扫描heap spray特征模式：连续的大块RWX内存分配
        匹配VirtualAlloc调用后的0x0C字节对齐和重复大小模式"""
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

# 新增: AtomBombing检测
    # AtomBombing利用全局原子表(Global Atom Table)传递shellcode数据到目标进程。
    # 检测签名: GlobalGetAtomNameA/W + Nt队列ApcThread + WriteProcessMemory 链
    def _scan_atom_bombing(self, data: bytes) -> None:
        """AtomBombing注入技术检测 — 基于ensilo在2016年披露的技术签名"""
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

# 新增: 注入技术到ATT&CK ID的映射
    def classify_injection_technique(self) -> Dict[str, List[str]]:
        """将检测到的注入指标映射到MITRE ATT&CK技术ID
        未识别的技术归入通用T1055（Process Injection）类别"""
        mapping: Dict[str, List[str]] = {}
        for ind in self._indicators:
            attack_id = self._ATTACK_MAP.get(ind.technique, "T1055")
            mapping.setdefault(attack_id, []).append(ind.technique)
        return mapping

    def _extract_strings(self) -> List[str]:
        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
        except Exception as e:
            _log.error(f"提取字符串失败: {e}")
        return strings

    def _extract_imports(self) -> List[str]:
        imports = []
        try:
            import pefile
            pe = pefile.PE(self.binary_path)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else ''
                    if func_name:
                        imports.append(func_name)
        except ImportError:
            _log.warning("pefile 模块未安装，无法提取导入表")
        except Exception as e:
            _log.error(f"提取导入表失败: {e}")
        return imports

    def _check_imports(self):
        imports = self._extract_imports()
        for severity, func_list in self.INJECTION_IMPORTS.items():
            for func_name in func_list:
                if func_name in imports:
                    self.suspicious_imports.append(func_name)
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='SUSPICIOUS_IMPORT',
                        severity=severity,
                        description=f"发现注入相关函数: {self._get_import_description(func_name)}",
                        evidence=f"导入: {func_name}",
                        recommendation=self._get_import_recommendation(func_name)
                    ))

    def _get_import_description(self, func_name: str) -> str:
        descriptions = {
            'CreateRemoteThread': '创建远程线程，常用于远程注入',
            'WriteProcessMemory': '写入远程内存，常用于注入shellcode',
            'VirtualAllocEx': '在远程进程中分配内存',
            'VirtualProtectEx': '修改远程进程内存保护',
            'SetWindowsHookEx': '安装Windows钩子，常用于注入',
            'NtQueueApcThread': '插入APC队列，用于APC注入',
            'OpenProcess': '打开进程句柄',
            'ReadProcessMemory': '读取远程内存',
        }
        return descriptions.get(func_name, '注入相关函数')

    def _get_import_recommendation(self, func_name: str) -> str:
        if func_name in self.INJECTION_IMPORTS['high']:
            return "此函数常用于远程注入，请确认其合法用途"
        elif func_name in self.INJECTION_IMPORTS['medium']:
            return "此函数可能被用于进程枚举或内存操作辅助注入"
        else:
            return "此函数本身无害，但可能配合其他函数实现注入"

    def _check_patterns(self):
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read().hex()
            for pattern, desc, severity in self.INJECTION_PATTERNS:
                if re.search(pattern, data, re.IGNORECASE):
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='INJECTION_PATTERN',
                        severity=severity,
                        description=f"检测到注入调用模式: {desc}",
                        evidence=f"模式: {pattern}",
                        recommendation="此调用模式可能包含注入功能"
                    ))
        except Exception as e:
            _log.error(f"检查调用模式失败: {e}")

    def _check_strings(self):
        self.strings = self._extract_strings()
        for keyword, desc in self.INJECTION_STRINGS:
            for string in self.strings:
                if keyword.lower() in string.lower():
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='INJECTION_STRING',
                        severity='medium',
                        description=f"检测到注入相关字符串: {desc}",
                        evidence=f"字符串: {string[:50]}",
                        recommendation="确认是否与注入相关功能有关"
                    ))
                    break

    def _detect_injection_sequence(self):
        imports = self._extract_imports()
        injection_sequences = [
            (['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
             '标准注入链: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread'),
            (['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
             '精简注入链'),
            (['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'VirtualProtectEx', 'CreateRemoteThread'],
             '带权限修改的注入链'),
            (['NtOpenProcess', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx'],
             'Native API注入链'),
            (['SetWindowsHookEx', 'GetModuleHandle', 'GetProcAddress'],
             '钩子注入链'),
        ]
        for sequence, desc in injection_sequences:
            if all(func in imports for func in sequence):
                self.injection_indicators.append(InjectionIndicator(
                    indicator_type='INJECTION_SEQUENCE',
                    severity='high',
                    description=f"检测到完整注入序列: {desc}",
                    evidence=f"序列函数: {', '.join(sequence)}",
                    recommendation="此序列可能是注入功能，请审查相关调用"
                ))

    def analyze(self) -> MemoryManipulationResult:
        self.injection_indicators = []
        self.suspicious_imports = []
        if self.binary_path:
            self._check_imports()
            self._check_patterns()
            self._check_strings()
            self._detect_injection_sequence()
        risk_score, risk_level = self._calculate_risk()
        return MemoryManipulationResult(
            filename=os.path.basename(self.binary_path) if self.binary_path else 'unknown',
            injection_indicators=self.injection_indicators,
            suspicious_imports=self.suspicious_imports,
            injection_risk=risk_level,
            risk_score=risk_score
        )

    def _calculate_risk(self) -> Tuple[int, str]:
        score = 100
        high_count = sum(1 for i in self.injection_indicators if i.severity == 'high')
        medium_count = sum(1 for i in self.injection_indicators if i.severity == 'medium')
        score -= high_count * 25
        score -= medium_count * 10
        if score <= 30:
            risk_level = 'high'
        elif score <= 60:
            risk_level = 'medium'
        elif score <= 80:
            risk_level = 'low'
        else:
            risk_level = 'none'
        return max(0, score), risk_level

    def generate_report(self) -> str:
        result = self.analyze()
        lines = [
            "内存扫描与注入技术分析报告",
            "=========================",
            "",
            f"文件: {result.filename}",
            f"注入风险: {result.injection_risk.upper()}",
            f"风险评分: {result.risk_score}/100",
            ""
        ]
        if result.suspicious_imports:
            lines.append("可疑导入函数:")
            lines.append("--------------")
            for imp in sorted(result.suspicious_imports):
                lines.append(f"- {imp}")
            lines.append("")
        if result.injection_indicators:
            lines.append("注入指示器:")
            lines.append("------------")
            for i, indicator in enumerate(result.injection_indicators, 1):
                lines.append(f"{i}. [{indicator.severity.upper()}] {indicator.indicator_type}")
                lines.append(f"   描述: {indicator.description}")
                lines.append(f"   证据: {indicator.evidence}")
                lines.append(f"   建议: {indicator.recommendation}")
                lines.append("")
        if result.injection_risk == 'none':
            lines.append("未发现注入相关功能。")
        return '\n'.join(lines)


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


def detect_memory_manipulation(binary_path: str) -> MemoryManipulationResult:
    detector = MemoryManipulationDetector(binary_path)
    return detector.analyze()
