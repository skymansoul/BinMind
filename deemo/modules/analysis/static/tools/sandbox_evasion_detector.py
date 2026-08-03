# 2026-07-26
import re
import struct
from typing import List, Dict, Tuple, Optional
from collections import Counter


class SandboxEvasionDetector:
    """5-pass detection: strings -> imports -> opcodes -> timing -> hardware fingerprint"""

    # ---- 初始化: 构建各维度的特征pattern库 ----

    def __init__(self):
        # Pass 1: string patterns
        self._vm_strings = [
            # VM detection strings
            'vbox', 'vmware', 'virtualbox', 'vmx', 'qemu', 'xen',
            'virtio', 'hyper-v', 'hyperv', 'kvm',
            'VBOX', 'VMWARE', 'VIRTUAL', 'QEMU',
            # 沙箱 indicators
            'sandbox', 'sandboxie', 'sbiedll', 'cuckoo',
            'malwr', 'any.run', 'joe sandbox', 'vxstream',
            'analysis', 'sample', 'mallab',
            # Debugger detection
            'ida', 'idaq', 'x64_dbg', 'x32_dbg', 'x64dbg', 'ollydbg',
            'immunity', 'windbg', 'debugger', 'debug',
            'dbghelp', 'ntsd', 'cdb',
            # Common 沙箱 artifacts
            'c:\\cuckoo', 'c:\\analysis', 'c:\\agent',
            'sandboxpipe', 'sandboxagent',
        ]

        self._dbg_strings = [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString',
            'DbgBreakPoint', 'DbgUiRemoteBreakin',
            'DebugActiveProcess', 'NtSetInformationThread',
        ]

        # Pass 2: import patterns
        self._evasion_imports = {
            'vm_detect': [
                ('kernel32', 'GetSystemFirmwareTable'),
                ('kernel32', 'IsProcessorFeaturePresent'),
                ('ntdll', 'NtQuerySystemInformation'),
                ('setupapi', 'SetupDiGetClassDevs'),
                ('kernel32', 'GetSystemInfo'),
            ],
            'debug_detect': [
                ('kernel32', 'IsDebuggerPresent'),
                ('kernel32', 'CheckRemoteDebuggerPresent'),
                ('ntdll', 'NtQueryInformationProcess'),
                ('kernel32', 'OutputDebugStringA'),
                ('ntdll', 'NtSetInformationThread'),
            ],
            'sandbox_detect': [
                ('kernel32', 'GetTickCount'),
                ('kernel32', 'GetTickCount64'),
                ('kernel32', 'QueryPerformanceCounter'),
                ('kernel32', 'Sleep'),
                ('ntdll', 'NtDelayExecution'),
            ],
            'anti_analysis': [
                ('kernel32', 'GetModuleHandleA'),
                ('kernel32', 'GetProcAddress'),
                ('kernel32', 'VirtualProtect'),
                ('ntdll', 'NtQueryVirtualMemory'),
                ('ntdll', 'NtUnmapViewOfSection'),
            ],
        }

        # Pass 3: opcode sequences (byte patterns)
        self._evasion_opcodes = [
            # SIDT (Red Pill) - 0F 01 0?
            (b'\x0f\x01', 'SIDT red pill (VM detection)'),
            # SGDT - 0F 01 0? (存储 Global/中断 Descriptor Table)
            (b'\x0f\x01\x08', 'SGDT (IDT base check)'),
            # SLDT - 0F 00 0?
            (b'\x0f\x00', 'SLDT/SMSW (VM check)'),
            # CPUID leaf 0x40000000 (虚拟机监控器)
            (b'\xb8\x00\x00\x00\x40', 'CPUID hypervisor leaf'),
            # VMware port (0x5658)
            (b'\xed', 'IN instruction (port I/O, possible VMware backdoor 0x5658)'),
            # RDTSC timing
            (b'\x0f\x31', 'RDTSC (timing check)'),
            # INT 2D (kernel debugger)
            (b'\xcd\x2d', 'INT 2D (kernel debugger check)'),
            # INT 3 (breakpoint)
            (b'\xcc', 'INT 3 (breakpoint)'),
            # ICEBP
            (b'\xf1', 'ICEBP (debug trap)'),
            # RDTSCP
            (b'\x0f\x01\xf9', 'RDTSCP (timing check)'),
        ]

        # Pass 4: timing heuristics
        self._timing_patterns = {
            'rdtsc_pair': re.compile(
                rb'(\x0f\x31.{0,20}){2}', re.DOTALL
            ),
            'sleep_loop': re.compile(
                rb'\xe8.{4}\x85\xc0\x74', re.DOTALL
            ),
            'query_perf_pair': re.compile(
                rb'QueryPerformanceCounter.{0,50}QueryPerformanceCounter',
                re.DOTALL,
            ),
        }

        # Pass 5: hardware fingerprint strings
        self._hw_fingerprint_patterns = [
            r'GetSystemFirmwareTable',
            r'EnumDisplayDevices',
            r'GetAdaptersInfo',
            r'GetComputerName',
            r'GetVolumeInformation',
            r'GetDiskFreeSpace',
            r'GetLogicalDrives',
            r'SetupDiGetClassDevs',
            r'NetShareEnum',
            r'WNetEnumResource',
            r'LookupPrivilegeValue',
            r'OpenProcessToken',
            r'GetTokenInformation',
        ]

    # ---- Pass 1: 字符串分析 ----

    def _pass_strings(self, strings: List[str]) -> Dict:
        _hits = []
        _vm_score = 0.0
        _dbg_score = 0.0

        _vm_max = len(self._vm_strings)
        _dbg_max = len(self._dbg_strings)

        _strs_lower = [s.lower() for s in strings]

        for _pat in self._vm_strings:
            for _s in _strs_lower:
                if _pat.lower() in _s:
                    _hits.append(('vm_sandbox', _pat, _s[:60]))
                    break

        for _pat in self._dbg_strings:
            for _s in _strs_lower:
                if _pat.lower() in _s:
                    _hits.append(('debugger', _pat, _s[:60]))
                    break

        _vm_hits = sum(1 for h in _hits if h[0] == 'vm_sandbox')
        _dbg_hits = sum(1 for h in _hits if h[0] == 'debugger')
        _vm_score = min(_vm_hits / max(_vm_max * 0.15, 1), 1.0)
        _dbg_score = min(_dbg_hits / max(_dbg_max * 0.1, 1), 1.0)

        return {
            'hits': _hits,
            'vm_score': _vm_score,
            'debugger_score': _dbg_score,
        }

    # //// Pass 2: 导入表分析 ////

    def _pass_imports(self, imports: Dict[str, List[str]]) -> Dict:
        _hits = []
        _scores = {'vm_detect': 0.0, 'debug_detect': 0.0,
                    'sandbox_detect': 0.0, 'anti_analysis': 0.0}

        for _cat, _patterns in self._evasion_imports.items():
            _match = 0
            for _mod, _func in _patterns:
                _ml = _mod.lower()
                _fl = _func.lower()
                for _im, _ifs in imports.items():
                    if _ml in _im.lower():
                        for _if in _ifs:
                            if _fl in _if.lower():
                                _hits.append((_cat, f"{_im}.{_if}"))
                                _match += 1
                                break
            _scores[_cat] = min(_match / max(len(_patterns), 1), 1.0)

        return {'hits': _hits, 'scores': _scores}

    # ===== Pass 3: 操作码序列扫描 =====

    def _pass_opcodes(self, data: bytes) -> Dict:
        _hits = []
        _code_score = 0.0

        for _pat_bytes, _desc in self._evasion_opcodes:
            _count = 0
            _pos = 0
            while True:
                _pos = data.find(_pat_bytes, _pos)
                if _pos == -1:
                    break
                _pos += max(len(_pat_bytes), 1)
                _count += 1
            if _count > 0:
                _hits.append((_desc, _count))

        # 基于hit种类计算分
        _code_score = min(len(_hits) / max(len(self._evasion_opcodes) * 0.3, 1), 1.0)

        return {'hits': _hits, 'code_score': _code_score}

    # ---- Pass 4: 时序检测模式 ----

    def _pass_timing(self, data: bytes, strings: List[str]) -> Dict:
        _hits = []

        for _name, _pat in self._timing_patterns.items():
            if _pat.search(data):
                _hits.append(_name)

        # 检查Sleep后调用恶意函数的模式（sandbox跳过快进）
        _sleep_pat = re.compile(rb'Sleep.{0,30}(CreateProcess|WinExec|URLDownload|HttpSend)',
                                re.DOTALL)
        if _sleep_pat.search(data):
            _hits.append('sleep_evasion')

        _timing_score = min(len(_hits) / 3.0, 1.0) if _hits else 0.0

        return {'hits': _hits, 'timing_score': _timing_score}

    # //// Pass 5: 硬件指纹收集 ////

    def _pass_hardware_fingerprint(self, strings: List[str], imports: dict) -> Dict:
        _hits = []
        _strs_all = ' '.join(strings)
        _imp_all = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_all.add(_f.lower())

        for _pat in self._hw_fingerprint_patterns:
            _pl = _pat.lower()
            if _pl in _strs_all.lower():
                _hits.append(('string', _pat))
            for _imp in _imp_all:
                if _pl in _imp:
                    _hits.append(('import', _pat))
                    break

        _hw_score = min(len(_hits) / 5.0, 1.0) if _hits else 0.0

        return {'hits': _hits, 'hw_score': _hw_score}

    # ===== 综合评分: 加权5-pass结果 -> 0-100 evasiveness score =====

    def analyze(self, data: bytes, strings: List[str] = None,
                imports: Dict[str, List[str]] = None) -> Dict:
        """
        5-pass composite evasiveness analysis
        返回 score 0-100 per-pass details
        """
        if strings is None:
            strings = self._extract_strings(data)
        if imports is None:
            imports = {}

        _p1 = self._pass_strings(strings)
        _p2 = self._pass_imports(imports)
        _p3 = self._pass_opcodes(data)
        _p4 = self._pass_timing(data, strings)
        _p5 = self._pass_hardware_fingerprint(strings, imports)

        # 加权: strings权重低（易误报）, 硬件指纹权重高
        _weights = {
            'strings': 0.15,
            'imports': 0.25,
            'opcodes': 0.20,
            'timing': 0.15,
            'hardware': 0.25,
        }

        _scores = {
            'strings': _p1['vm_score'] * 0.6 + _p1['debugger_score'] * 0.4,
            'imports': sum(_p2['scores'].values()) / max(len(_p2['scores']), 1),
            'opcodes': _p3['code_score'],
            'timing': _p4['timing_score'],
            'hardware': _p5['hw_score'],
        }

        _total = sum(_scores[k] * _weights[k] for k in _weights) * 100
        _total = min(round(_total), 100)

        _categories = []
        if _p1['vm_score'] > 0.3 or _p1['debugger_score'] > 0.3:
            _categories.append('vm_sandbox_detection')
        if _p2['scores']['debug_detect'] > 0.4:
            _categories.append('anti_debug')
        if _p2['scores']['sandbox_detect'] > 0.3:
            _categories.append('anti_sandbox')
        if _p3['code_score'] > 0.3:
            _categories.append('anti_vm_opcodes')
        if _p4['timing_score'] > 0.3:
            _categories.append('timing_evasion')
        if _p5['hw_score'] > 0.4:
            _categories.append('hardware_fingerprinting')

        return {
            'evasiveness_score': _total,
            'categories': _categories,
            'per_pass': {
                'strings': {'hits': _p1['hits'], 'score': _scores['strings']},
                'imports': {'hits': _p2['hits'], 'score': _scores['imports']},
                'opcodes': {'hits': _p3['hits'], 'score': _scores['opcodes']},
                'timing': {'hits': _p4['hits'], 'score': _scores['timing']},
                'hardware': {'hits': _p5['hits'], 'score': _scores['hardware']},
            },
            'risk_level': 'HIGH' if _total >= 70 else ('MEDIUM' if _total >= 30 else 'LOW'),
        }

    # ---- 辅助: 字符串提取 ----

    def _extract_strings(self, data: bytes, min_len=4) -> List[str]:
        _strings = []
        _pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        for _m in _pat.finditer(data):
            _strings.append(_m.group().decode('ascii', errors='ignore'))

        # UTF-16LE strings
        _i = 0
        while _i < len(data) - 1:
            if 0x20 <= data[_i] <= 0x7e and data[_i + 1] == 0:
                _buf = bytearray()
                _j = _i
                while _j < len(data) - 1 and 0x20 <= data[_j] <= 0x7e and data[_j + 1] == 0:
                    _buf.append(data[_j])
                    _j += 2
                if len(_buf) >= min_len:
                    _strings.append(_buf.decode('ascii', errors='ignore'))
                _i = _j
            else:
                _i += 1

        return _strings
