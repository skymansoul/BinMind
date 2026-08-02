# 2026-07-28
import re
from typing import List, Dict, Tuple, Optional
from collections import Counter


class VulnSignatureScanner:
    """15+ built-in vulnerability signatures with CVE/CWE references, multi-method detection"""

    # ---- 初始化: 15+ CVE级漏洞签名库 ----

    def __init__(self):
        self._signatures = [
            # Buffer overflow patterns
            {
                'id': 'VULN-001',
                'title': 'Stack Buffer Overflow (strcpy/gets/sprintf)',
                'cwe': 'CWE-121',
                'cvss_base': 7.8,
                'apis': ['strcpy', 'gets', 'sprintf', 'strcat', 'wcscpy', '_tcscpy',
                         'StrCpyA', 'StrCpyW', 'lstrcpyA', 'lstrcpyW'],
                'safe_alternatives': ['strncpy', 'strcpy_s', 'snprintf', 'StringCchCopy'],
                'method': 'api_sequence',
            },
            {
                'id': 'VULN-002',
                'title': 'Format String Vulnerability',
                'cwe': 'CWE-134',
                'cvss_base': 7.5,
                'apis': ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf',
                         'vfprintf', 'vsprintf', 'syslog', 'LogMessage'],
                'patterns': [
                    r'printf\s*\(\s*[^,\s)]+\s*\)',  # printf(user_input) without format
                    r'fprintf\s*\(\s*\w+\s*,\s*[^,\s)]+\s*\)',
                ],
                'method': 'api_sequence',
            },
            # Command injection
            {
                'id': 'VULN-003',
                'title': 'Command Injection (system/popen/exec)',
                'cwe': 'CWE-78',
                'cvss_base': 8.8,
                'apis': ['system', 'popen', 'execve', 'execvp', 'execl', 'CreateProcessA',
                         'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW', 'WinExec',
                         '_wsystem', '_popen'],
                'method': 'api_sequence',
            },
            # Insecure deserialization
            {
                'id': 'VULN-004',
                'title': 'Insecure Deserialization',
                'cwe': 'CWE-502',
                'cvss_base': 8.1,
                'apis': ['readObject', 'Deserialize', 'Unmarshal', 'json.Unmarshal',
                         'json.loads', 'pickle.loads', 'pickle.load', 'yaml.load',
                         'Marshal.load', 'BinaryFormatter', 'ObjectInputStream',
                         'JavaDeserialize', 'SoapFormatter'],
                'method': 'api_sequence',
            },
            # TOCTOU / race condition
            {
                'id': 'VULN-005',
                'title': 'TOCTOU Race Condition (access/open)',
                'cwe': 'CWE-367',
                'cvss_base': 6.3,
                'apis': ['access', '_access', 'stat', 'lstat'],
                'api_pairs': [('access', 'open'), ('_access', 'fopen'),
                              ('stat', 'open'), ('GetFileAttributes', 'CreateFile')],
                'method': 'api_pairs',
            },
            # Integer overflow
            {
                'id': 'VULN-006',
                'title': 'Integer Overflow (malloc with unchecked multiplication)',
                'cwe': 'CWE-190',
                'cvss_base': 7.8,
                'apis': ['malloc', 'calloc', 'realloc', 'new[]', 'HeapAlloc',
                         'LocalAlloc', 'GlobalAlloc', 'operator new'],
                'patterns': [
                    r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',  # malloc(a * b) - potential overflow
                    r'calloc\s*\(\s*\w+\s*,\s*\w+\s*\)',
                ],
                'method': 'api_sequence',
            },
            # NULL pointer dereference
            {
                'id': 'VULN-007',
                'title': 'Potential NULL Pointer Dereference',
                'cwe': 'CWE-476',
                'cvss_base': 5.9,
                'apis': ['malloc', 'calloc', 'fopen', 'CreateFile', 'new', 'GlobalAlloc'],
                'patterns': [
                    r'(\w+)\s*=\s*malloc\s*\(.*\)\s*;[^;]*\1->',  # malloc then deref without check
                ],
                'method': 'pattern',
            },
            # Path traversal
            {
                'id': 'VULN-008',
                'title': 'Path Traversal',
                'cwe': 'CWE-22',
                'cvss_base': 7.5,
                'apis': ['fopen', 'open', 'CreateFile', 'ifstream', 'File.Open',
                         'readFile', 'writeFile'],
                'strings': ['../', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f',
                            'Directory.GetFiles', 'Directory.GetDirectories'],
                'method': 'import_string_combo',
            },
            # Use of unsafe functions
            {
                'id': 'VULN-009',
                'title': 'Use of Banned/Deprecated API',
                'cwe': 'CWE-676',
                'cvss_base': 6.2,
                'apis': ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
                         'scanf', 'sscanf', 'getwd', 'tmpnam', 'tempnam',
                         'mktemp', 'cuserid'],
                'method': 'api_sequence',
            },
            # Hardcoded credentials
            {
                'id': 'VULN-010',
                'title': 'Hardcoded Credentials',
                'cwe': 'CWE-798',
                'cvss_base': 7.4,
                'strings': ['password', 'passwd', 'secret', 'apikey', 'api_key',
                            'private_key', 'access_key', 'secret_key',
                            'admin', 'root', 'sa', 'postgres'],
                'method': 'string_pattern',
            },
            # SQL injection
            {
                'id': 'VULN-011',
                'title': 'Potential SQL Injection',
                'cwe': 'CWE-89',
                'cvss_base': 8.8,
                'apis': ['mysql_query', 'mysqli_query', 'pg_query', 'sqlite3_exec',
                         'SQLExecDirect', 'Execute', 'exec sp_executesql'],
                'patterns': [
                    r"(?:sprintf|snprintf|asprintf).*SELECT",
                    r"(?:strcat|strcpy).*INSERT\s+INTO",
                    r"Query\s*\(\s*\".*\%s",
                ],
                'method': 'api_sequence',
            },
            # Weak cryptography
            {
                'id': 'VULN-012',
                'title': 'Weak Cryptographic Algorithm',
                'cwe': 'CWE-327',
                'cvss_base': 6.8,
                'apis': ['DES_', 'RC4_', 'MD4_', 'MD5_', 'SHA1_', 'AES_ECB',
                         'CryptDeriveKey', 'CALG_DES', 'CALG_RC4'],
                'strings': ['MD5', 'SHA1', 'DES-', 'RC4', 'AES-ECB', 'Cipher.getInstance("DES"'],
                'method': 'import_string_combo',
            },
            # Missing authentication
            {
                'id': 'VULN-013',
                'title': 'Missing Function-level Access Control',
                'cwe': 'CWE-862',
                'cvss_base': 7.5,
                'apis': ['system', 'exec', 'eval', 'popen', 'subprocess.call',
                         'subprocess.Popen', 'os.system', 'os.exec'],
                'strings': ['shell_exec', 'exec(', 'eval(', 'no_auth', 'bypass_auth'],
                'method': 'import_string_combo',
            },
            # Insecure permission
            {
                'id': 'VULN-014',
                'title': 'Insecure File Permissions',
                'cwe': 'CWE-732',
                'cvss_base': 6.5,
                'apis': ['chmod', 'fchmod', '_chmod', 'SetFileSecurity',
                         'CreateFile', 'open'],
                'patterns': [
                    r'chmod\s*\(\s*\w+\s*,\s*0?777',
                    r'CreateFile.*GENERIC_ALL',
                ],
                'method': 'api_sequence',
            },
            # Unsafe reflection
            {
                'id': 'VULN-015',
                'title': 'Unsafe Reflection / Dynamic Code Execution',
                'cwe': 'CWE-470',
                'cvss_base': 8.1,
                'apis': ['Class.forName', 'Method.invoke', 'ClassLoader.loadClass',
                         'getattr', 'eval', 'exec', '__import__', 'importlib.import_module',
                         'Reflection.Assembly', 'Activator.CreateInstance'],
                'method': 'api_sequence',
            },
            # Memory leak
            {
                'id': 'VULN-016',
                'title': 'Potential Memory Leak',
                'cwe': 'CWE-401',
                'cvss_base': 5.5,
                'apis': ['malloc', 'calloc', 'new', 'HeapAlloc', 'VirtualAlloc'],
                'free_apis': ['free', 'delete', 'HeapFree', 'VirtualFree'],
                'method': 'api_pairs',
            },
        ]

    # ---- 检测方法1: API序列匹配 ----

    def _scan_api_sequence(self, imports: Dict[str, List[str]], signatures: List[Dict]) -> List[Dict]:
        _found = []
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            _ml = _mod.lower()
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        for _sig in signatures:
            if _sig.get('method') != 'api_sequence':
                continue
            _apis = _sig.get('apis', [])
            _matched = []
            for _api in _apis:
                _al = _api.lower()
                for _imp in _imp_flat:
                    if _al in _imp:
                        _matched.append(_api)
                        break

            if _matched:
                _conf = min(len(_matched) / max(len(_apis) * 0.3, 1), 1.0)
                if _sig.get('safe_alternatives'):
                    _safe_used = any(s.lower() in _ for _imp in _imp_flat for s in _sig['safe_alternatives'])
                    if _safe_used:
                        _conf *= 0.3  # safe alternatives present -> reduce confidence

                _found.append({
                    'signature_id': _sig['id'],
                    'title': _sig['title'],
                    'cwe': _sig['cwe'],
                    'cvss_base': _sig['cvss_base'],
                    'confidence': round(_conf, 2),
                    'matched_apis': _matched,
                    'detection_method': 'api_sequence',
                })

        return _found

    # //// 检测方法2: API对匹配 (pair analysis) ////

    def _scan_api_pairs(self, imports: Dict[str, List[str]], signatures: List[Dict]) -> List[Dict]:
        _found = []
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            _ml = _mod.lower()
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        for _sig in signatures:
            if _sig.get('method') not in ('api_pairs',):
                continue
            _pairs = _sig.get('api_pairs', [])
            for _a, _b in _pairs:
                _a_found = any(_a.lower() in _imp for _imp in _imp_flat)
                _b_found = any(_b.lower() in _imp for _imp in _imp_flat)
                if _a_found and _b_found:
                    _found.append({
                        'signature_id': _sig['id'],
                        'title': _sig['title'],
                        'cwe': _sig['cwe'],
                        'cvss_base': _sig['cvss_base'],
                        'confidence': 0.7,
                        'matched_pair': f"{_a} -> {_b}",
                        'detection_method': 'api_pairs',
                    })

            # check api_pairs from re patterns
            if _sig.get('patterns'):
                _imp_str = ' '.join(_imp_flat)
                for _pat in _sig['patterns']:
                    if re.search(_pat, _imp_str, re.I):
                        _found.append({
                            'signature_id': _sig['id'],
                            'title': _sig['title'],
                            'cwe': _sig['cwe'],
                            'cvss_base': _sig['cvss_base'],
                            'confidence': 0.65,
                            'matched_pattern': _pat,
                            'detection_method': 'pattern',
                        })

        return _found

    # ===== 检测方法3: 字符串模式匹配 =====

    def _scan_string_patterns(self, strings: List[str], signatures: List[Dict]) -> List[Dict]:
        _found = []
        _strs_text = ' '.join(strings)

        for _sig in signatures:
            if _sig.get('method') not in ('string_pattern', 'pattern'):
                continue
            _sig_strs = _sig.get('strings', [])
            _matched = []
            for _s in _sig_strs:
                if _s.lower() in _strs_text.lower():
                    _matched.append(_s)

            if _matched:
                _conf = min(len(_matched) / max(len(_sig_strs) * 0.3, 1), 0.85)
                _found.append({
                    'signature_id': _sig['id'],
                    'title': _sig['title'],
                    'cwe': _sig['cwe'],
                    'cvss_base': _sig['cvss_base'],
                    'confidence': round(_conf, 2),
                    'matched_strings': _matched,
                    'detection_method': 'string_pattern',
                })

            # Regex patterns in strings
            if _sig.get('patterns'):
                for _pat in _sig['patterns']:
                    if re.search(_pat, _strs_text, re.I):
                        _found.append({
                            'signature_id': _sig['id'],
                            'title': _sig['title'],
                            'cwe': _sig['cwe'],
                            'cvss_base': _sig['cvss_base'],
                            'confidence': 0.55,
                            'matched_pattern': _pat,
                            'detection_method': 'regex_string',
                        })

        return _found

    # ---- 检测方法4: import+string组合 ----

    def _scan_import_string_combo(self, imports: dict, strings: List[str],
                                   signatures: List[Dict]) -> List[Dict]:
        _found = []
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_flat.add(_f.lower())
        _strs_text = ' '.join(strings).lower()

        for _sig in signatures:
            if _sig.get('method') != 'import_string_combo':
                continue
            _apis = _sig.get('apis', [])
            _strs = _sig.get('strings', [])
            _api_match = any(_a.lower() in _imp for _a in _apis for _imp in _imp_flat)
            _str_match = any(_s.lower() in _strs_text for _s in _strs)

            _conf = 0.0
            if _api_match and _str_match:
                _conf = 0.7
            elif _api_match:
                _conf = 0.4
            elif _str_match:
                _conf = 0.3

            if _conf > 0:
                _found.append({
                    'signature_id': _sig['id'],
                    'title': _sig['title'],
                    'cwe': _sig['cwe'],
                    'cvss_base': _sig['cvss_base'],
                    'confidence': round(_conf, 2),
                    'matched_apis': [_a for _a in _apis if any(_a.lower() in _imp for _imp in _imp_flat)],
                    'matched_strings': [_s for _s in _strs if _s.lower() in _strs_text],
                    'detection_method': 'import_string_combo',
                })

        return _found

    # //// 综合扫描入口 ////

    def scan(self, imports: Dict[str, List[str]] = None,
             strings: List[str] = None,
             opcode_flags: List[str] = None) -> Dict:
        if imports is None:
            imports = {}
        if strings is None:
            strings = []
        if opcode_flags is None:
            opcode_flags = []

        _all_findings = []
        _sigs = self._signatures

        # 四种检测方法并行
        _f1 = self._scan_api_sequence(imports, _sigs)
        _f2 = self._scan_api_pairs(imports, _sigs)
        _f3 = self._scan_string_patterns(strings, _sigs)
        _f4 = self._scan_import_string_combo(imports, strings, _sigs)

        _all_findings = _f1 + _f2 + _f3 + _f4

        # 去重：同一signature_id取最高confidence
        _dedup = {}
        for _f in _all_findings:
            _sid = _f['signature_id']
            if _sid not in _dedup or _f['confidence'] > _dedup[_sid]['confidence']:
                _dedup[_sid] = _f

        _results = sorted(_dedup.values(), key=lambda x: x['confidence'], reverse=True)

        # Opcode pattern check
        _opcode_flags_list = list(opcode_flags)  # reserved for future opcode scanning

        # 综合风险评分
        _cvss_total = 0.0
        for _r in _results:
            _cvss_total += _r.get('cvss_base', 5.0) * _r['confidence']

        _max_score = sum(s.get('cvss_base', 5.0) for s in self._signatures)
        _risk = min((_cvss_total / max(_max_score * 0.3, 1)) * 100, 100)

        _critical = sum(1 for r in _results if r.get('cvss_base', 0) >= 9.0 and r['confidence'] > 0.5)
        _high = sum(1 for r in _results if 7.0 <= r.get('cvss_base', 0) < 9.0 and r['confidence'] > 0.4)
        _medium = sum(1 for r in _results if 4.0 <= r.get('cvss_base', 0) < 7.0 and r['confidence'] > 0.3)
        _low = len(_results) - _critical - _high - _medium

        return {
            'findings': _results,
            'total_findings': len(_results),
            'risk_score': round(_risk),
            'severity_breakdown': {
                'critical': _critical,
                'high': _high,
                'medium': _medium,
                'low': _low,
            },
            'detection_methods_used': ['api_sequence', 'api_pairs', 'string_pattern', 'import_string_combo'],
        }
