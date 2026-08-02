# 2026-07-28
import struct
import re
import hashlib
from typing import List, Dict, Tuple, Optional
from collections import Counter
import math


class BinaryUnpacker:
    """17 packer signatures, PE section entropy profiling, unpacking strategy builder"""

    # ---- 初始化: 17个加壳工具签名库 ----

    def __init__(self):
        # 已知加壳工具: section名称 + 特征字符串 + 入口点特征
        self._packer_sigs = {
            'UPX': {
                'sections': ['UPX0', 'UPX1', 'UPX2', 'upx0', 'upx1', 'upx2'],
                'strings': ['UPX!', 'UPX0', 'UPX1', 'UPX2', '$Info: This file is packed with the UPX'],
                'ep_bytes': [b'\x60\xbe', b'\x60\xe8', b'\xe8\x00\x00\x00\x00'],
                'unpack_tool': 'upx -d',
            },
            'ASPack': {
                'sections': ['.aspack', '.adata'],
                'strings': ['ASPack', '.aspack', 'ASProtect'],
                'ep_bytes': [b'\x60\xe8\x03\x00\x00', b'\xe8\x03\x00\x00\x00\xe8'],
                'unpack_tool': 'asPack_die / pe_unmapper',
            },
            'MPRESS': {
                'sections': ['.MPRESS1', '.MPRESS2', '.mpr1', '.mpr2', '.mpr3'],
                'strings': ['MPRESS', 'MPRESS1', 'MPRESS2', '.mpr'],
                'ep_bytes': [b'\x68', b'\xe8', b'\xe9'],
                'unpack_tool': 'process dump (Scylla/x64dbg)',
            },
            'VMProtect': {
                'sections': ['.vmp0', '.vmp1', '.vmp2', '.vmp3', '.vmp', 'vmp0'],
                'strings': ['VMProtect', '.vmp', 'VMPROTECT', 'VMProtectSDK'],
                'ep_bytes': [b'\xe8', b'\xe9', b'\x50', b'\x68'],
                'unpack_tool': 'VMProtect unpacker / TitanHide + x64dbg',
            },
            'Themida': {
                'sections': ['.themida', '.them', 'themida'],
                'strings': ['Themida', 'Winlicense', 'Oreans', '.themida'],
                'ep_bytes': [b'\xb8', b'\xbb', b'\xe9'],
                'unpack_tool': 'Themida_unpacker / Oreans Unvirtualizer',
            },
            'Enigma': {
                'sections': ['.enigma', '.enigma1', '.enigma2', 'enigma'],
                'strings': ['Enigma Protector', 'Enigma', '.enigma'],
                'ep_bytes': [b'\xe9', b'\xeb'],
                'unpack_tool': 'EnigmaUnpacker / Scylla',
            },
            'Petite': {
                'sections': ['.petite', 'petite'],
                'strings': ['Petite', 'petite'],
                'ep_bytes': [b'\xb8', b'\xe8'],
                'unpack_tool': 'petite_unpacker / OllyDbg',
            },
            'y0da': {
                'sections': ['.y0da', '.yoda', 'y0da', 'yC'],
                'strings': ['y0da', 'yoda', 'yoda\'s'],
                'ep_bytes': [b'\xe8', b'\xe9', b'\x60'],
                'unpack_tool': 'ollydbg + ImportREC',
            },
            'PECompact': {
                'sections': ['.pec', '.pec1', '.pec2', 'pec1', 'pec2'],
                'strings': ['PECompact', 'pec2', 'PEC2'],
                'ep_bytes': [b'\xe8', b'\x50', b'\x60'],
                'unpack_tool': 'pecompact_unpacker / OllyDbg script',
            },
            'NsPack': {
                'sections': ['.nsp0', '.nsp1', '.nsp2', 'nsp0', 'nsp1'],
                'strings': ['NsPack', 'nspack'],
                'ep_bytes': [b'\xe8', b'\x56'],
                'unpack_tool': 'nspack_unpacker / QuickUnpack',
            },
            'WwPack32': {
                'sections': ['.wwpack', '.wwp32'],
                'strings': ['WWPack32', 'wwpack'],
                'ep_bytes': [b'\x53', b'\x57'],
                'unpack_tool': 'QuickUnpack / OllyDbg',
            },
            'Armadillo': {
                'sections': ['.text1', '.text2', '.adata', '.pdata'],
                'strings': ['Armadillo', 'SoftwarePassport', 'ArmAccess'],
                'ep_bytes': [b'\x55\x8b\xec', b'\xe8'],
                'unpack_tool': 'Armadillo_unpacker / dillodie',
            },
            'Obsidium': {
                'sections': ['.obsidium', '.obsi'],
                'strings': ['Obsidium', '.obsidium'],
                'ep_bytes': [b'\xe8', b'\xe9'],
                'unpack_tool': 'Obsidium_unpack / OllyDbg',
            },
            'MoleBox': {
                'sections': ['.molebox', '.mbox', '.molb'],
                'strings': ['MoleBox', '.molebox', 'molebox'],
                'ep_bytes': [b'\xe8', b'\x55\x8b\xec'],
                'unpack_tool': 'demolebox / OllyDbg',
            },
            'RLPack': {
                'sections': ['.rlpack', '.rlp', 'rlpack'],
                'strings': ['RLPack', 'rlpack'],
                'ep_bytes': [b'\xe8', b'\x53'],
                'unpack_tool': 'rlpack_unpacker / OllyDbg',
            },
            'EXEStealth': {
                'sections': ['.exest', '.estealth'],
                'strings': ['EXEStealth', 'exestealth'],
                'ep_bytes': [b'\xe8', b'\xe9'],
                'unpack_tool': 'OllyDbg + ImportREC',
            },
            'PESpin': {
                'sections': ['.pespin', '.spin'],
                'strings': ['PESpin', 'pespin'],
                'ep_bytes': [b'\xe8', b'\xeb'],
                'unpack_tool': 'pespin_unpacker / OllyDbg script',
            },
        }

        # 通用加壳检测特征
        self._generic_packer_indicators = [
            'VirtualProtect', 'VirtualAlloc', 'VirtualFree',
            'LoadLibrary', 'GetProcAddress', 'GetModuleHandle',
            'WriteProcessMemory', 'ZwUnmapViewOfSection',
            'NtUnmapViewOfSection',
        ]

    # ---- 基于section名称+熵检测加壳 ----

    def detect_packer(self, sections: List[str],
                      section_entropy: Dict[str, float] = None,
                      imports: Dict[str, List[str]] = None,
                      ep_bytes: bytes = None) -> Dict:
        _findings = []
        _sec_lower = [s.lower() for s in sections]
        _ent = section_entropy or {}
        _imp = imports or {}

        # 精确段名匹配
        for _pname, _info in self._packer_sigs.items():
            _segs = _info.get('sections', [])
            _matched = []
            for _seg in _segs:
                if _seg.lower() in _sec_lower:
                    _matched.append(_seg)

            if _matched:
                _confidence = 0.9 if len(_matched) >= 2 else 0.7

                # EP bytes验证
                if ep_bytes and _info.get('ep_bytes'):
                    _ep_match = False
                    for _epb in _info['ep_bytes']:
                        if ep_bytes[:len(_epb)] == _epb:
                            _ep_match = True
                            break
                    if _ep_match:
                        _confidence = min(_confidence + 0.1, 1.0)

                _findings.append({
                    'packer': _pname,
                    'confidence': round(_confidence, 2),
                    'method': 'section_name',
                    'matched_sections': _matched,
                    'unpack_tool': _info.get('unpack_tool', 'generic dump'),
                    'known': True,
                })

        # 字符串匹配（对不匹配段名的packer）
        _all_strs = ' '.join(sections).lower()
        for _pname, _info in self._packer_sigs.items():
            _strs = _info.get('strings', [])
            if any(_s.lower() in _all_strs for _s in _strs):
                # 确认未通过段名找到
                if not any(f['packer'] == _pname for f in _findings):
                    _findings.append({
                        'packer': _pname,
                        'confidence': 0.5,
                        'method': 'string_match',
                        'matched_strings': [_s for _s in _strs if _s.lower() in _all_strs],
                        'unpack_tool': _info.get('unpack_tool', 'generic dump'),
                        'known': True,
                    })

        # 通用加壳启发式
        _hi_ent_count = sum(1 for v in _ent.values() if v > 7.0)
        _imp_count = sum(len(v) for v in _imp.values()) if _imp else 0

        # 特征imports检查
        _generic_imports_found = []
        for _mod, _funcs in _imp.items():
            for _f in _funcs:
                if _f in self._generic_packer_indicators:
                    _generic_imports_found.append(f"{_mod}.{_f}")

        _generic_score = 0.0
        _generic_reasons = []

        # 高熵指示
        if _hi_ent_count >= 2:
            _generic_score += 0.3
            _generic_reasons.append(f"{_hi_ent_count} sections with entropy > 7.0")

        # 少导入
        if _imp_count < 5 and _imp_count > 0:
            _generic_score += 0.2
            _generic_reasons.append(f"very few imports ({_imp_count})")

        # 入口特征（pushad/pushfd）
        if ep_bytes and len(ep_bytes) >= 1 and ep_bytes[0] in (0x60, 0x9C):
            _generic_score += 0.1
            _generic_reasons.append("pushad/pushfd at entry point")

        # 假入口点（不在第一个section）
        _generic_score += 0.1 if _hi_ent_count > 0 and _imp_count < 3 else 0

        if _generic_score >= 0.3 and not _findings:
            _findings.append({
                'packer': 'generic_packer',
                'confidence': min(_generic_score, 0.7),
                'method': 'heuristic',
                'reasons': _generic_reasons,
                'unpack_tool': 'process dump (Scylla/x64dbg/DIE)',
                'known': False,
            })

        _best = max(_findings, key=lambda x: x['confidence']) if _findings else None

        return {
            'packer_detected': _best is not None,
            'best_match': _best,
            'all_matches': _findings,
            'is_packed': len(_findings) > 0,
        }

    # //// 解包策略构建 ////

    def build_unpacking_strategy(self, packer_result: Dict,
                                  arch: str = 'x64',
                                  has_debugger_detect: bool = False) -> Dict:
        _best = packer_result.get('best_match')
        if not _best:
            return {'strategy': 'none', 'steps': ['No packer detected']}

        _steps = []
        _tools = []
        _difficulty = 'medium'

        _pname = _best.get('packer', 'unknown')

        # 已知packer -> 专用工具
        if _best.get('known') and _best.get('unpack_tool'):
            _tools.append(_best['unpack_tool'])
            _steps.append(f"1. Use {_best['unpack_tool']} for {_pname}")

        # 通用解包流程
        _steps.append(f"2. Load binary in x64dbg/OllyDbg ({arch} mode)")

        if has_debugger_detect:
            _steps.append("3. Bypass anti-debug: hide PEB.BeingDebugged (TitanHide/ScyllaHide)")
            _steps.append("4. Patch NtQueryInformationProcess (ProcessDebugFlags/ProcessDebugPort)")
            _difficulty = 'hard'

        _steps.append(f"{len(_steps)+1}. Set breakpoint on VirtualProtect/VirtualAlloc")
        _steps.append(f"{len(_steps)+1}. Trace to OEP (Original Entry Point)")
        _steps.append(f"{len(_steps)+1}. Dump process memory at OEP (Scylla plugin)")
        _steps.append(f"{len(_steps)+1}. Rebuild IAT (Scylla/ImportREC)")
        _steps.append(f"{len(_steps)+1}. Fix PE header (optional: PE-bear)")

        if _pname in ('UPX', 'ASPack', 'MPRESS'):
            _difficulty = 'easy'
        elif _pname in ('VMProtect', 'Themida', 'Enigma', 'Obsidium'):
            _difficulty = 'very_hard'
            _steps.append(f"{len(_steps)+1}. Consider virtualization detection + deobfuscation")

        if _pname == 'generic_packer':
            _difficulty = 'medium'
            _steps.insert(1, "2. Identify packer type with DIE/detect-it-easy")

        return {
            'packer': _pname,
            'difficulty': _difficulty,
            'tools': _tools,
            'steps': _steps,
            'estimated_time': '5-15 min' if _difficulty == 'easy' else (
                '30-60 min' if _difficulty == 'medium' else '2-8 hours'
            ),
        }

    # ===== PE section熵分析 =====

    def analyze_section_entropy(self, sections_data: Dict[str, bytes]) -> Dict:
        _result = {}
        for _name, _data in sections_data.items():
            _ent = self._shannon_entropy(_data)
            _size = len(_data)
            _interpretation = 'normal'
            if _ent > 7.5:
                _interpretation = 'likely_packed_or_encrypted'
            elif _ent > 6.5:
                _interpretation = 'compressed_or_obfuscated'
            elif _ent < 1.0:
                _interpretation = 'likely_null_padding'

            _result[_name] = {
                'entropy': round(_ent, 3),
                'size': _size,
                'interpretation': _interpretation,
            }

        return _result

    # ---- 综合打包体分析 ----

    def analyze(self, pe_data: bytes = None,
                sections: List[str] = None,
                section_data: Dict[str, bytes] = None,
                imports: Dict[str, List[str]] = None,
                strings: List[str] = None,
                entry_point: int = 0) -> Dict:

        _sections = sections or []
        _ent = {}
        if section_data:
            _ent_analysis = self.analyze_section_entropy(section_data)
            _ent = {k: v['entropy'] for k, v in _ent_analysis.items()}
        else:
            _ent_analysis = {}

        _ep_bytes = None
        if pe_data and entry_point:
            # extract EP bytes (first 4 bytes at entry point)
            _ep_off = entry_point
            if _ep_off + 4 <= len(pe_data):
                _ep_bytes = pe_data[_ep_off:_ep_off + 4]

        _packer = self.detect_packer(_sections, _ent, imports, _ep_bytes)
        _strategy = self.build_unpacking_strategy(_packer)

        return {
            'packer_analysis': _packer,
            'unpacking_strategy': _strategy,
            'entropy_analysis': _ent_analysis,
            'summary': {
                'is_packed': _packer['is_packed'],
                'identified_packer': _packer['best_match']['packer'] if _packer['best_match'] else None,
                'confidence': _packer['best_match']['confidence'] if _packer['best_match'] else 0.0,
                'unpack_difficulty': _strategy['difficulty'],
            },
        }

    # //// 香农熵计算 ////

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        _cnt = [0] * 256
        for _b in data:
            _cnt[_b] += 1
        _ent = 0.0
        _total = len(data)
        for _c in _cnt:
            if _c > 0:
                _p = _c / _total
                _ent -= _p * math.log2(_p)
        return _ent

    # ===== PE基础解析 =====

    def parse_pe_basic(self, data: bytes) -> Optional[Dict]:
        if len(data) < 64 or data[:2] != b'MZ':
            return None

        _pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
        if _pe_off + 4 > len(data) or data[_pe_off:_pe_off + 4] != b'PE\x00\x00':
            return None

        _oh_off = _pe_off + 4 + 20
        _num_sec = struct.unpack('<H', data[_pe_off + 6:_pe_off + 8])[0]
        _oh_size = struct.unpack('<H', data[_pe_off + 20:_pe_off + 22])[0]
        _ep = struct.unpack('<I', data[_oh_off + 16:_oh_off + 20])[0]

        _sections = []
        _sec_data = {}
        _sec_off = _pe_off + 24 + _oh_size
        for _i in range(min(_num_sec, 50)):
            _so = _sec_off + _i * 40
            if _so + 40 > len(data):
                break
            _name = data[_so:_so + 8].rstrip(b'\x00').decode('ascii', errors='replace').strip('\x00')
            _raw_off = struct.unpack('<I', data[_so + 20:_so + 24])[0]
            _raw_size = struct.unpack('<I', data[_so + 16:_so + 20])[0]
            _sections.append(_name)
            if _raw_size > 0 and _raw_off + _raw_size <= len(data):
                _sec_data[_name] = data[_raw_off:_raw_off + _raw_size]

        return {
            'sections': _sections,
            'section_data': _sec_data,
            'entry_point': _ep,
            'data': data,
        }
