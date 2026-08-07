# 2026-07-31
import re
import struct
import hashlib
from typing import List, Dict, Optional, Tuple
import math


class FirmwareAnalyzer:
    """U-Boot/DTB/UEFI/ATF detection, FS extraction, IoT vuln scanning"""

# 初始化: 固件特征库

    def __init__(self):
        # Boot加载器 magics
        self._bootloader_magics = {
            b'\x27\x05\x19\x56': 'U-Boot (legacy uImage)',
            b'\xd0\x0d\xfe\xed': 'DTB (Device Tree Blob)',
            b'\x44\x54\x42\x00': 'DTB (DTB magic string)',
            b'\xAA\x64\x00\x00': 'UEFI PI Firmware Volume',
            b'_FVH': 'UEFI Firmware Volume Header',
            b'\x5f\x46\x56\x48': 'UEFI FVH (raw)',
            b'FV\x00\x00': 'UEFI Firmware Volume',
            b'ARM Trusted Firmware': 'ARM Trusted Firmware (ATF)',
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                'Possible padding/empty region',
        }

        # 文件系统 magic bytes
        self._fs_magics = {
            b'hsqs': 'SquashFS (little-endian)',
            b'sqsh': 'SquashFS (big-endian)',
            b'\x68\x73\x71\x73': 'SquashFS (alt)',
            b'\x53\x45\x46\x48': 'SquashFS (SEFH)',
            b'\x28\xcd\x3d\x45': 'JFFS2 (little-endian, cleanmarker)',
            b'\x45\x3d\xcd\x28': 'JFFS2 (big-endian, cleanmarker)',
            b'\x19\x85': 'JFFS2 node magic',
            b'\x45\x3d\xcd\x28': 'CramFS (little-endian)',  # LE 0x28cd3d45
            b'\x28\xcd\x3d\x45': 'CramFS (big-endian)',
            b'070707': 'CPIO (ASCII)',
            b'\xc7\x71': 'CPIO (binary, little-endian)',
            b'\x71\xc7': 'CPIO (binary, big-endian)',
            b'UBI#': 'UBIFS Superblock',
            b'\x31\x18\x10\x06': 'UBIFS node',
            b'UBI!': 'UBI volume',
            b'\x53\xef': 'EXT2/3/4 Superblock',
            b'\xe2\xe1\xf5\xe0': 'YAFFS (bytes 0-3 = 0xFFFF0000?)',
            b'ROMFS': 'romfs',
            b'-rom1fs-': 'romfs (header string)',
            b'\x00\x00\x00\x01': 'ISO9660 (CD001 signature offset)',
        }

        # IoT 漏洞 patterns
        self._iot_vuln_patterns = {
            'hardcoded_password': {
                'patterns': [
                    r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\'\s]{3,})["\']',
                    r'root:.*:0:0:',
                    r'admin:\$1\$',
                ],
                'severity': 'CRITICAL',
            },
            'private_key': {
                'patterns': [
                    r'BEGIN\s+RSA\s+PRIVATE\s+KEY',
                    r'BEGIN\s+DSA\s+PRIVATE\s+KEY',
                    r'BEGIN\s+EC\s+PRIVATE\s+KEY',
                    r'BEGIN\s+OPENSSH\s+PRIVATE\s+KEY',
                ],
                'severity': 'CRITICAL',
            },
            'telnet_enabled': {
                'patterns': [
                    r'telnetd\s', r'/usr/sbin/telnetd',
                    r'telnet\s+enable', r'telnetd.*-l\s+/bin/sh',
                    r'start-stop-daemon.*telnet',
                ],
                'severity': 'HIGH',
            },
            'wifi_credentials': {
                'patterns': [
                    r'wpa_passphrase\s*[=:]\s*["\']([^"\']+)["\']',
                    r'ssid\s*[=:]\s*["\']([^"\']+)["\']',
                    r'wifi.*password\s*[=:]',
                    r'wlan.*key\s*[=:]',
                ],
                'severity': 'HIGH',
            },
            'busybox_version': {
                'patterns': [
                    r'BusyBox\s+v?(\d+\.\d+\.\d+)',
                    r'busybox\s+v?(\d+\.\d+)',
                ],
                'severity': 'MEDIUM',
            },
            'dropbear_version': {
                'patterns': [
                    r'Dropbear\s+v?(\d+\.\d+)',
                    r'Dropbear\s+ssh',
                ],
                'severity': 'MEDIUM',
            },
            'debug_interfaces': {
                'patterns': [
                    r'/dev/ttyS\d+', r'serial\s*console',
                    r'UART', r'JTAG', r'SWD\s',
                    r'debug\s*shell', r'root\s*shell',
                ],
                'severity': 'MEDIUM',
            },
            'default_credentials': {
                'patterns': [
                    r'admin:admin', r'root:root', r'guest:guest',
                    r'user:user', r'support:support',
                    r'user\s*name\s*:\s*admin', r'default\s*password',
                ],
                'severity': 'HIGH',
            },
            'backdoor_account': {
                'patterns': [
                    r'backdoor', r'hidden\s*user', r'secret\s*account',
                    r'maintenance\s*user', r'factory\s*account',
                ],
                'severity': 'HIGH',
            },
            'insecure_startup': {
                'patterns': [
                    r'chmod\s+777', r'chmod\s+-R\s+777',
                    r'mount\s+-o\s+rw,remount\s+/',
                    r'iptables\s+-F', r'iptables\s+--flush',
                ],
                'severity': 'MEDIUM',
            },
        }

# Boot加载器检测: U-Boot/DTB/UEFI/ATF

    def detect_bootloader(self, data: bytes) -> List[Dict]:
        _findings = []

        # U-Boot uImage: magic + header fields
        if len(data) >= 64 and data[:4] == b'\x27\x05\x19\x56':
            _hcrc = struct.unpack('>I', data[4:8])[0]
            _created = struct.unpack('>I', data[8:12])[0]
            _size = struct.unpack('>I', data[12:16])[0]
            _load_addr = struct.unpack('>I', data[20:24])[0]
            _ep = struct.unpack('>I', data[24:28])[0]

            _findings.append({
                'type': 'U-Boot uImage',
                'offset': 0,
                'load_address': hex(_load_addr),
                'entry_point': hex(_ep),
                'data_size': _size,
                'created_timestamp': _created,
                'confidence': 0.95,
            })

        # DTB magic
        for _magic, _desc in self._bootloader_magics.items():
            if _magic == b'\x27\x05\x19\x56':
                continue  # handled above
            _pos = data.find(_magic)
            if _pos != -1:
                _dtb_info = {'type': _desc, 'offset': _pos, 'confidence': 0.9}
                if 'DTB' in _desc:
                    # 解析 DTB header
                    if _pos + 40 <= len(data):
                        try:
                            _total_size = struct.unpack('>I', data[_pos + 4:_pos + 8])[0]
                            _dtb_info['total_size'] = _total_size
                        except struct.error:
                            pass
                _findings.append(_dtb_info)

        # UEFI specific
        if re.search(rb'FV\x00\x00.{28}\x78\xe5\x8c\x8c', data):
            _findings.append({'type': 'UEFI PI Firmware Volume (FV)', 'confidence': 0.85})

        # ARM Trusted Firmware headers
        if b'ARM Trusted Firmware' in data[:1024] or b'BL31' in data[:512]:
            _findings.append({
                'type': 'ARM Trusted Firmware (ATF/BL31)',
                'offset': data.find(b'ARM Trusted Firmware'),
                'confidence': 0.9,
            })

        # Barebox
        if b'barebox' in data[:1024] or b'BAREBOX' in data[:4096]:
            _findings.append({'type': 'Barebox bootloader', 'confidence': 0.85})

        return _findings

    # //// 文件系统检测 ////

    def detect_filesystems(self, data: bytes) -> List[Dict]:
        _findings = []

        for _magic, _desc in self._fs_magics.items():
            _pos = 0
            _found_count = 0
            while _pos < len(data) - len(_magic):
                _pos = data.find(_magic, _pos)
                if _pos == -1:
                    break
                _found_count += 1

                _info = {
                    'type': _desc,
                    'offset': _pos,
                    'confidence': 0.85 if _found_count == 1 else 0.7,
                }

                # SquashFS: try 读取 superblock
                if 'SquashFS' in _desc and _pos + 100 <= len(data):
                    try:
                        _s = data[_pos:_pos + 96]
                        _magic32 = struct.unpack('<I', _s[0:4])[0]
                        _block_size = struct.unpack('<I', _s[12:16])[0]
                        if _block_size > 0 and _block_size <= 1048576:
                            _info['block_size'] = _block_size
                    except struct.error:
                        pass

                # JFFS2
                if 'JFFS2' in _desc and _pos + 12 <= len(data):
                    try:
                        _magic16 = struct.unpack('<H', data[_pos:_pos + 2])[0]
                        if _magic16 == 0x1985:
                            _node_type = struct.unpack('<H', data[_pos + 2:_pos + 4])[0]
                            _info['node_type'] = _node_type
                    except struct.error:
                        pass

                _findings.append(_info)
                _pos += 1  # continue scan (embedded FS may repeat)

        # Dedup type + offset proximity
        _dedup = []
        for _f in _findings:
            _dup = False
            for _existing in _dedup:
                if (_existing['type'] == _f['type'] and
                        abs(_existing['offset'] - _f['offset']) < 256):
                    _dup = True
                    break
            if not _dup:
                _dedup.append(_f)

        return _dedup

# IoT漏洞扫描

    def scan_iot_vulns(self, strings: List[str]) -> List[Dict]:
        _findings = []
        _strs_text = '\n'.join(strings)

        for _vuln_id, _info in self._iot_vuln_patterns.items():
            _matched = []
            _extracted_values = []
            for _pat in _info['patterns']:
                for _m in re.finditer(_pat, _strs_text, re.I | re.MULTILINE):
                    _matched.append(_m.group(0)[:120])
                    if _m.groups():
                        _extracted_values.append(_m.group(1)[:60])

            if _matched:
                # 降重
                _unique = list(set(_matched))[:5]
                _findings.append({
                    'vuln_id': _vuln_id,
                    'severity': _info['severity'],
                    'matched_patterns': _unique,
                    'extracted_values': _extracted_values[:3],
                    'count': len(_matched),
                    'confidence': min(len(_unique) / 3.0, 0.95),
                })

        return _findings

# BusyBox/Dropbear版本检测

    def extract_software_versions(self, strings: List[str]) -> List[Dict]:
        _versions = []
        _strs_text = '\n'.join(strings)

        _software_patterns = [
            (r'BusyBox\s+v?(\d+\.\d+\.\d+)', 'BusyBox'),
            (r'busybox\s+v?(\d+\.\d+\.\d+)', 'BusyBox'),
            (r'Dropbear\s+v?(\d+\.\d+)', 'Dropbear SSH'),
            (r'OpenSSH[_ ](\d+\.\d+\w?)', 'OpenSSH'),
            (r'OpenSSL\s+(\d+\.\d+\.\d+\w?)', 'OpenSSL'),
            (r'uClibc\s+(\d+\.\d+\.\d+)', 'uClibc'),
            (r'Linux\s+version\s+(\d+\.\d+\.\d+)', 'Linux Kernel'),
            (r'Linux-(\d+\.\d+\.\d+)', 'Linux Kernel (build)'),
            (r'dnsmasq-(\d+\.\d+\.\d+)', 'dnsmasq'),
            (r'lighttpd/(\d+\.\d+\.\d+)', 'lighttpd'),
            (r'nginx/(\d+\.\d+\.\d+)', 'nginx'),
            (r'apache/(\d+\.\d+\.\d+)', 'Apache'),
        ]

        _found_names = set()
        for _pat, _name in _software_patterns:
            if _name in _found_names:
                continue
            _m = re.search(_pat, _strs_text, re.I)
            if _m:
                _found_names.add(_name)
                _versions.append({
                    'software': _name,
                    'version': _m.group(1),
                    'potential_cves': self._check_known_vulns(_name, _m.group(1)),
                })

        return _versions

    def _check_known_vulns(self, name: str, version: str) -> List[str]:
        # 简化版: 检查已知IoT高危版本
        _known = {
            'Dropbear SSH': [('2020.80', 'CVE-2021-36369')],
            'BusyBox': [('1.30.1', 'CVE-2022-28391')],
            'dnsmasq': [('2.78', 'CVE-2017-14491'), ('2.85', 'CVE-2021-3448')],
        }
        _vulns = []
        for _sv, _cve in _known.get(name, []):
            try:
                if self._version_compare(version, _sv) <= 0:
                    _vulns.append(_cve)
            except (ValueError, IndexError):
                pass
        return _vulns

    def _version_compare(self, v1: str, v2: str) -> int:
        _parts1 = [int(p) for p in v1.replace('p', '.').split('.') if p.isdigit()]
        _parts2 = [int(p) for p in v2.replace('p', '.').split('.') if p.isdigit()]
        for _i in range(max(len(_parts1), len(_parts2))):
            _a = _parts1[_i] if _i < len(_parts1) else 0
            _b = _parts2[_i] if _i < len(_parts2) else 0
            if _a < _b:
                return -1
            if _a > _b:
                return 1
        return 0

    # //// 综合分析入口 ////

    def analyze(self, data: bytes = None, filepath: str = None,
                strings: List[str] = None) -> Dict:
        if data is None and filepath:
            with open(filepath, 'rb') as _f:
                data = _f.read()

        if data is None:
            return {'error': 'no data or filepath provided'}

        if strings is None:
            strings = self._extract_strings(data)

        _bl = self.detect_bootloader(data)
        _fs = self.detect_filesystems(data)
        _vulns = self.scan_iot_vulns(strings)
        _versions = self.extract_software_versions(strings)

        # 风险汇总
        _critical = sum(1 for v in _vulns if v['severity'] == 'CRITICAL')
        _high = sum(1 for v in _vulns if v['severity'] == 'HIGH')
        _score = _critical * 30 + _high * 15

        # 文件系统种类（多文件系统可能表示复杂固件）
        _fs_types = set(f['type'] for f in _fs)

        return {
            'bootloader': _bl,
            'filesystems': _fs,
            'iot_vulnerabilities': _vulns,
            'software_versions': _versions,
            'summary': {
                'bootloader_type': _bl[0]['type'] if _bl else 'unknown',
                'filesystem_types': list(_fs_types),
                'critical_vulnerabilities': _critical,
                'high_vulnerabilities': _high,
                'total_vulnerabilities': len(_vulns),
                'identified_software': len(_versions),
                'risk_score': min(_score, 100),
                'has_private_keys': any(v['vuln_id'] == 'private_key' for v in _vulns),
                'has_hardcoded_passwords': any(v['vuln_id'] == 'hardcoded_password' for v in _vulns),
            },
        }

# 辅助: 字符串提取

    def _extract_strings(self, data: bytes, min_len=4) -> List[str]:
        _strings = []
        _pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        for _m in _pat.finditer(data):
            _strings.append(_m.group().decode('ascii', errors='ignore'))
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
