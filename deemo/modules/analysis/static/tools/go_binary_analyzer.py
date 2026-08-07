# 2026-07-29
import re
import struct
from typing import List, Dict, Optional, Tuple


class GoBinaryAnalyzer:
    """binary detection, version extraction, pclntab recovery, -specific vuln patterns"""

# 初始化: Go特征签名

    def __init__(self):
        # Go版本字符串模式
        self._go_version_patterns = [
            re.compile(rb'go1\.(\d+)\.(\d+)'),
            re.compile(rb'go1\.(\d+)\.(\d+)(?:\.(\d+))?'),
        ]

        # build信息pattern
        self._build_info_patterns = [
            rb'Go build ID:',
            rb'build\tvcs\.time=',
            rb'build\tvcs\.revision=',
            rb'path\tcommand-line-arguments',
            rb'path\tgithub\.com',
            rb'runtime\.(.*?)\.go',
        ]

        # pclntab magic
        self._pclntab_magics = [
            b'\xFB\xFF\xFF\xFF\x00\x00',  # 1.2-1.15
            b'\xFA\xFF\xFF\xFF\x00\x00',  # 1.16
            b'\xF0\xFF\xFF\xFF\x00\x00',  # 1.18+
            b'\xF1\xFF\xFF\xFF\x00\x00',  # 1.18+ variant
        ]

        # runtime函数特征
        self._go_runtime_funcs = [
            'runtime.mallocgc', 'runtime.newobject', 'runtime.growslice',
            'runtime.panic', 'runtime.deferproc', 'runtime.deferreturn',
            'runtime.newstack', 'runtime.morestack', 'runtime.schedule',
            'runtime.gcStart', 'runtime.gcBgMarkWorker',
            'runtime.mapassign', 'runtime.mapaccess1',
            'runtime.chanrecv', 'runtime.chansend',
            'runtime.selectgo', 'runtime.closechan',
            'runtime.goexit', 'runtime.gopark',
            'runtime.goready', 'runtime.systemstack',
            'runtime.wakep', 'runtime.stopm',
            'internal/abi.(*RegArgs)', 'internal/reflectlite',
        ]

        # Go不安全模式pattern
        self._vuln_patterns = {
            'unsafe_pointer': {
                'patterns': [
                    r'unsafe\.Pointer', r'unsafe\.Slice',
                    r'uintptr.*unsafe\.Pointer', r'unsafe\.Pointer.*uintptr',
                ],
                'severity': 'MEDIUM',
                'description': 'Unsafe pointer usage - risk of type confusion, GC issues',
            },
            'unchecked_type_assert': {
                'patterns': [
                    r'\.\(\s*\*?\w+\s*\)',  # type assertion
                ],
                'severity': 'LOW',
                'description': 'Type assertion without ok check - potential panic',
            },
            'reflect_abuse': {
                'patterns': [
                    r'reflect\.ValueOf', r'reflect\.TypeOf',
                    r'reflect\.Value\.Elem', r'reflect\.Value\.Field',
                    r'reflect\.Value\.Set',
                    r'reflect\.DeepEqual',
                ],
                'severity': 'LOW',
                'description': 'Heavy reflect usage - bypasses type safety',
            },
            'cgo_border': {
                'patterns': [
                    r'C\.\w+', r'_Cfunc_', r'_cgo_',
                    r'import\s+"C"', r'cgo\.Handle',
                ],
                'severity': 'MEDIUM',
                'description': 'CGo border crossing - potential memory safety boundary violation',
            },
            'math_rand_crypto': {
                'patterns': [
                    r'math/rand\.(?:Int|Intn|Float|Read|Perm|Shuffle)',
                    r'math/rand\.New',
                ],
                'severity': 'HIGH',
                'description': 'Use math/rand for crypto purposes (should be crypto/rand)',
            },
            'sync_atomic_misuse': {
                'patterns': [
                    r'sync/atomic\.',
                ],
                'severity': 'LOW',
                'description': 'Atomic operations - check for 64-bit alignment on 32-bit arches',
            },
            'os_exec_input': {
                'patterns': [
                    r'os\.Exec', r'exec\.Command', r'exec\.CommandContext',
                ],
                'severity': 'HIGH',
                'description': 'External command execution - check for command injection',
            },
            'template_injection': {
                'patterns': [
                    r'template\.Must', r'template\.New', r'template\.Execute',
                    r'html/template\.',
                ],
                'severity': 'MEDIUM',
                'description': 'Template usage - verify user input is properly escaped',
            },
        }

# Go二进制检测

    def is_go_binary(self, data: bytes, strings: List[str] = None) -> Dict:
        if strings is None:
            strings = []
        _indicators = []
        _score = 0.0

        # Indicator 1: 构建 ID
        for _pat in self._build_info_patterns:
            if isinstance(_pat, bytes) and _pat in data:
                _indicators.append(('build_info', _pat.decode('ascii', errors='replace')))
                _score += 0.25
                break

        # Indicator 2: version string
        for _pat in self._go_version_patterns:
            _m = _pat.search(data)
            if _m:
                _ver = f"go1.{_m.group(1).decode()}.{_m.group(2).decode()}"
                _indicators.append(('version_string', _ver))
                _score += 0.25
                break

        # Indicator 3: pclntab magic
        for _magic in self._pclntab_magics:
            _pos = data.find(_magic)
            if _pos != -1:
                _indicators.append(('pclntab', f"offset={hex(_pos)}"))
                _score += 0.25
                break

        # Indicator 4: runtime strings
        _strs_text = ' '.join(strings)
        _func_matches = 0
        for _func in self._go_runtime_funcs:
            _fn = _func.split('.')[-1] if '.' in _func else _func
            if _fn in _strs_text:
                _func_matches += 1
        if _func_matches >= 3:
            _indicators.append(('runtime_funcs', f"{_func_matches} matches"))
            _score += 0.25

        # Indicator 5: ELF.gopclntab section
        if b'.gopclntab' in data or b'gopclntab' in data:
            _indicators.append(('gopclntab_section', True))
            _score += 0.2

        # Indicator 6: -specific ELF note section
        if b'Go\x00\x00' in data:
            _indicators.append(('go_note_section', True))
            _score += 0.15

        _is_go = _score >= 0.4

        return {
            'is_go_binary': _is_go,
            'confidence': min(round(_score, 2), 1.0),
            'indicators': _indicators,
        }

    # //// Go版本提取 ////

    def extract_version(self, data: bytes) -> Optional[str]:
        for _pat in self._go_version_patterns:
            _m = _pat.search(data)
            if _m:
                _groups = _m.groups()
                _major = _groups[0].decode() if isinstance(_groups[0], bytes) else str(_groups[0])
                _minor = _groups[1].decode() if isinstance(_groups[1], bytes) else str(_groups[1])
                if len(_groups) > 2 and _groups[2]:
                    _patch = _groups[2].decode() if isinstance(_groups[2], bytes) else str(_groups[2])
                    return f"go1.{_major}.{_minor}.{_patch}"
                return f"go1.{_major}.{_minor}"

        # 回退: 查找 "go1." literal
        _m = re.search(rb'go1\.(\d+)(?:\.(\d+))?', data)
        if _m:
            return _m.group(0).decode('ascii', errors='replace')

        return None

# pclntab函数恢复 (模拟r2 pcln)

    def recover_functions_from_pclntab(self, data: bytes) -> List[Dict]:
        _funcs = []

        # 查找 pclntab magic
        _pcln_off = -1
        _quantum = 1
        _pointer_size = 8
        for _magic in self._pclntab_magics:
            _pos = data.find(_magic)
            if _pos != -1:
                _pcln_off = _pos
                # Determine version magic
                if _magic == b'\xFB\xFF\xFF\xFF\x00\x00':
                    _quantum = 1
                    _pointer_size = 4 if len(data) < 0x100000000 else 8
                elif _magic == b'\xFA\xFF\xFF\xFF\x00\x00':
                    _quantum = 1
                else:
                    _quantum = 1
                break

        if _pcln_off == -1:
            return _funcs

        # 解析 pclntab header (simplified)
        try:
            # header: magic(6) + 填充(2) + quantum(1) + 指针_size(1) + num_funcs(4/8)
            _hdr = data[_pcln_off:_pcln_off + 8]
            _num_funcs = struct.unpack('<I', data[_pcln_off + 8:_pcln_off + 12])[0]

            # Function entries 启动 header
            _func_off = _pcln_off + 16  # approximate

            for _i in range(min(_num_funcs, 50000)):
                _entry_off = _func_off + _i * 16  # entry: entry_pc(8) + func_offset(8)
                if _entry_off + 16 > len(data):
                    break

                _pc = struct.unpack('<Q', data[_entry_off:_entry_off + 8])[0]
                _off = struct.unpack('<Q', data[_entry_off + 8:_entry_off + 16])[0]

                # 读取 function name func_offset location
                _name_off = _pcln_off + _off
                if _name_off < len(data):
                    _name = self._read_cstr(data, _name_off, 128)
                    if _name and len(_name) > 1:
                        _funcs.append({
                            'offset': _pc,
                            'name': _name,
                            'func_offset': _off,
                        })

        except (struct.error, IndexError):
            pass

        return _funcs

# Go特异性漏洞检测

    def detect_go_vulns(self, strings: List[str], imports: dict = None) -> List[Dict]:
        _findings = []
        _strs_text = ' '.join(strings)

        for _vuln_id, _info in self._vuln_patterns.items():
            _matched = []
            for _pat in _info['patterns']:
                if re.search(_pat, _strs_text, re.I):
                    _matched.append(_pat)

            if _matched:
                _conf = min(len(_matched) / max(len(_info['patterns']) * 0.3, 1), 0.9)
                _findings.append({
                    'vuln_id': _vuln_id,
                    'description': _info['description'],
                    'severity': _info['severity'],
                    'confidence': round(_conf, 2),
                    'matched_patterns': _matched,
                })

        return _findings

    # //// Go依赖检测 ////

    def extract_dependencies(self, data: bytes, strings: List[str]) -> List[Dict]:
        _deps = []
        # module paths pattern: github.com/org/repo, golang.org/x/, etc
        _dep_re = re.compile(
            r'(?:github\.com|gitlab\.com|bitbucket\.org|golang\.org|'
            r'go\.googlesource\.com|gopkg\.in|k8s\.io|cloud\.google\.com)/'
            r'[\w\-./]+',
        )
        _found = set()
        for _m in _dep_re.finditer(' '.join(strings)):
            _dep = _m.group(0)
            if _dep not in _found:
                _found.add(_dep)
                _deps.append({'package': _dep, 'type': 'import'})

        # Additional binary
        _dep_re_b = re.compile(rb'path\t(github\.com/[\w\-./]+)')
        for _m in _dep_re_b.finditer(data):
            _dep = _m.group(1).decode('ascii', errors='replace')
            if _dep not in _found:
                _found.add(_dep)
                _deps.append({'package': _dep, 'type': 'build_info'})

        return _deps

# 综合分析入口

    def analyze(self, data: bytes = None, filepath: str = None,
                strings: List[str] = None, imports: dict = None) -> Dict:
        if data is None and filepath:
            with open(filepath, 'rb') as _f:
                data = _f.read()

        if data is None:
            return {'error': 'no data or filepath provided'}

        if strings is None:
            strings = self._extract_strings(data)
        if imports is None:
            imports = {}

        _is_go = self.is_go_binary(data, strings)
        _ver = self.extract_version(data) if _is_go['is_go_binary'] else None
        _funcs = self.recover_functions_from_pclntab(data) if _is_go['is_go_binary'] else []
        _vulns = self.detect_go_vulns(strings, imports) if _is_go['is_go_binary'] else []
        _deps = self.extract_dependencies(data, strings) if _is_go['is_go_binary'] else []

        return {
            'go_binary_analysis': _is_go,
            'go_version': _ver,
            'recovered_functions': len(_funcs),
            'function_samples': _funcs[:20],  # first 20 for preview
            'dependencies': _deps[:50],
            'vulnerabilities': _vulns,
            'summary': {
                'is_go': _is_go['is_go_binary'],
                'confidence': _is_go['confidence'],
                'version': _ver,
                'function_count': len(_funcs),
                'vulnerability_count': len(_vulns),
                'dependency_count': len(_deps),
            },
        }

# 辅助

    def _read_cstr(self, data: bytes, offset: int, max_len=256) -> str:
        _end = offset
        while _end < min(offset + max_len, len(data)) and data[_end] != 0:
            _end += 1
        _raw = data[offset:_end]
        return _raw.decode('utf-8', errors='replace')

    def _extract_strings(self, data: bytes, min_len=4) -> List[str]:
        _strings = []
        _pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        for _m in _pat.finditer(data):
            _strings.append(_m.group().decode('ascii', errors='ignore'))
        return _strings
