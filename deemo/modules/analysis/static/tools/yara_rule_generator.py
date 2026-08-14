# 2026-07-30
import re
import hashlib
import struct
from typing import List, Dict, Tuple, Optional


class YaraRuleGenerator:
    """Auto-构造 YARA 4.x rules 二进制分析 results"""

    def __init__(self, author="BinMind Auto-Generator"):
        self._author = author
        self._rule_counter = 0

# 基于字符串生成规则

    def generate_string_rule(self, strings: List[str],
                              rule_name: str = None,
                              description: str = "Auto-generated string-based detection",
                              min_weight: int = 3) -> str:
        if rule_name is None:
            rule_name = self._next_rule_name()
        if not strings:
            return ""

        # 过滤和加权: 长字符串 > 短字符串, UNIQUE > COMMON
        _str_freq = {}
        for _s in strings:
            _sl = _s.strip()
            if len(_sl) < 4:
                continue
            _str_freq[_sl] = _str_freq.get(_sl, 0) + 1

        # 选择有价值字符串: 长的、独立的
        _candidates = []
        for _s, _freq in _str_freq.items():
            _len = len(_s)
            _weight = _len * (1.0 / max(_freq, 1))
            if _weight >= min_weight and _len >= 6:
                _candidates.append((_s, _weight))

        _candidates.sort(key=lambda x: x[1], reverse=True)
        _selected = _candidates[:30]  # 最多30条字符串

        _parts = []
        _parts.append(f'rule {rule_name}')
        _parts.append('{')
        _parts.append('    meta:')
        _parts.append(f'        author = "{self._author}"')
        _parts.append(f'        description = "{description}"')
        _parts.append(f'        date = "2024-12-27"')
        _parts.append(f'        generated_strings = {len(_selected)}')
        _parts.append('')

        if _selected:
            _parts.append('    strings:')
            for _i, (_s, _w) in enumerate(_selected):
                # Escape string for YARA
                _escaped = self._escape_yara_string(_s)
                # wide modifier for strings look like UTF-16
                _modifier = ''
                if any(ord(c) > 127 for c in _s):
                    _modifier = ' wide'
                elif len(_s) >= 12:  # longer ASCII strings 使用 ascii + wide
                    _modifier = ' wide ascii'

                # nocase for shorter strings
                _nc = ' nocase' if len(_s) < 12 and _s.isalpha() else ''

                _parts.append(f'        $s{_i} = "{_escaped}"{_modifier}{_nc}')

        _parts.append('')
        _parts.append('    condition:')
        # 条件逻辑: 短规则用all/, 包含过于通用库函数时用更严格条件
        if len(_selected) == 0:
            _parts.append('        false')
        elif len(_selected) <= 3:
            _parts.append(f'        all of them')
        elif len(_selected) <= 8:
            _parts.append(f'        {min(3, len(_selected))} of them')
        elif len(_selected) <= 15:
            _parts.append(f'        4 of them')
        else:
            _parts.append(f'        6 of them')

        _parts.append('}')

        return '\n'.join(_parts)

    # //// 基于导入表生成规则 ////

    def generate_import_rule(self, imports: Dict[str, List[str]],
                              rule_name: str = None,
                              description: str = "Auto-generated import-based detection") -> str:
        if rule_name is None:
            rule_name = self._next_rule_name()

        _parts = []
        _parts.append(f'import "pe"')
        _parts.append('')
        _parts.append(f'rule {rule_name}')
        _parts.append('{')
        _parts.append('    meta:')
        _parts.append(f'        author = "{self._author}"')
        _parts.append(f'        description = "{description}"')
        _parts.append(f'        date = "2023-07-04"')

        _import_count = 0
        for _mod, _funcs in imports.items():
            _import_count += len(_funcs)
        _parts.append(f'        detected_imports = {_import_count}')
        _parts.append('')

        _parts.append('    condition:')
        _conditions = []

        # 为每个模块生成pe.imports条件
        for _mod, _funcs in imports.items():
            _mod_name = _mod.replace('.dll', '').replace('.DLL', '')
            for _func in _funcs[:5]:  # 每个模块最多5个函数
                _esc_mod = _mod_name.lower()
                _esc_func = _func.lower()
                _cond = f'        pe.imports("{_esc_mod}", "{_esc_func}")'
                _conditions.append(_cond)

        if _conditions:
            # 根据导入数量决定条件
            if len(_conditions) <= 3:
                _parts.append('        ' + ' and\n        '.join(_conditions))
            elif len(_conditions) <= 8:
                _parts.append(f'        /* At least 3 of the following import conditions */')
                _parts.append(f'        3 of (')
                for _c in _conditions:
                    _parts.append(f'            {_c[8:]},')  # strip ' '
                _parts.append(f'        )')
            else:
                _parts.append(f'        /* At least 5 of the following import conditions */')
                _parts.append(f'        5 of (')
                for _c in _conditions[:15]:
                    _parts.append(f'            {_c[8:]},')
                _parts.append(f'        )')
        else:
            _parts.append('        false')

        _parts.append('}')

        return '\n'.join(_parts)

# 基于节区哈希生成规则

    def generate_section_rule(self, sections_data: Dict[str, bytes],
                               rule_name: str = None,
                               description: str = "Auto-generated section hash detection") -> str:
        if rule_name is None:
            rule_name = self._next_rule_name()

        _parts = []
        _parts.append(f'import "pe"')
        _parts.append(f'import "hash"')
        _parts.append('')
        _parts.append(f'rule {rule_name}')
        _parts.append('{')
        _parts.append('    meta:')
        _parts.append(f'        author = "{self._author}"')
        _parts.append(f'        description = "{description}"')
        _parts.append(f'        date = "2023-08-10"')
        _parts.append('')
        _parts.append('    condition:')

        _conditions = []
        for _name, _data in sections_data.items():
            if len(_data) < 16:
                continue
            _sec_name = _name.replace('.', '_').strip('_') or 'noname'
            # 使用 first 64 bytes hash weak 签名
            _h = hashlib.sha256(_data[:64]).hexdigest()
            _var = f'$hash_{_sec_name}'
            _parts.append(f'        /* Section .{_name} hash: {_h[:16]}... */')

        _parts.append(f'        /* Match on section characteristics */')
        _parts.append(f'        for any section in pe.sections : (')
        _parts.append(f'            section.name contains ".text" or')

        _data_sections = []
        for _name in sections_data.keys():
            _sec_n = _name.replace('.', '_').strip('_') or 'noname'
            _data_sections.append(f'.{_name}')

        if _data_sections:
            _parts.append(f'            section.name contains "{_data_sections[0]}"')
        else:
            _parts.append(f'            false')

        _parts.append(f'        )')
        _parts.append('}')

        return '\n'.join(_parts)

# 组合规则生成

    def generate_composite_rule(self, strings: List[str] = None,
                                 imports: Dict[str, List[str]] = None,
                                 sections_data: Dict[str, bytes] = None,
                                 rule_name: str = None,
                                 family_name: str = "Unknown",
                                 tags: List[str] = None) -> str:
        if rule_name is None:
            rule_name = self._next_rule_name()
        if strings is None:
            strings = []
        if imports is None:
            imports = {}
        if tags is None:
            tags = []

        _parts = []
        _parts.append(f'import "pe"')
        _parts.append('')
        _parts.append(f'rule {rule_name}')
        _parts.append('{')
        _parts.append('    meta:')
        _parts.append(f'        author = "{self._author}"')
        _parts.append(f'        description = "Detection rule for {family_name}"')
        _parts.append(f'        family = "{family_name}"')
        _parts.append(f'        date = "2023-09-16"')
        _parts.append(f'        hash = "{hashlib.md5(str(strings+list(imports)).encode()).hexdigest()}"')
        if tags:
            _parts.append(f'        tags = "{", ".join(tags)}"')
        _parts.append('')

        # 字符串部分
        _str_freq = {}
        for _s in strings:
            _sl = _s.strip()
            if len(_sl) >= 6:
                _str_freq[_sl] = _str_freq.get(_sl, 0) + 1

        _str_candidates = [(s, f) for s, f in _str_freq.items()
                           if len(s) >= 8 or (len(s) >= 6 and f == 1)]

        if _str_candidates:
            _parts.append('    strings:')
            for _i, (_s, _freq) in enumerate(_str_candidates[:20]):
                _esc = self._escape_yara_string(_s)
                _mod = ' wide ascii' if len(_s) > 12 else ''
                _nc = ' nocase' if _s.isalpha() else ''
                _parts.append(f'        $str{_i} = "{_esc}"{_mod}{_nc}')

        _parts.append('')
        _parts.append('    condition:')
        _conds = []

        # String condition
        if _str_candidates:
            _n = min(max(2, len(_str_candidates) // 3), 8)
            _conds.append(f'        {_n} of them')

        # PE specific: MZ magic
        _conds.append(f'        uint16(0) == 0x5A4D')

        # Import conditions
        _imp_count = 0
        for _mod, _funcs in imports.items():
            _ml = _mod.lower().replace('.dll', '')
            for _func in _funcs[:1]:
                _conds.append(f'        pe.imports("{_ml}", "{_func.lower()}")')
                _imp_count += 1
            if _imp_count >= 3:
                break

        if len(_conds) == 1:
            _parts.append(_conds[0])
        else:
            _parts.append('        ' + ' and\n'.join(_conds) if len(_conds) <= 3 else
                          '        ' + ' and\n'.join(_conds[:3]))

        _parts.append('}')

        return '\n'.join(_parts)

    # //// YARA字符串转义 ////

    def _escape_yara_string(self, s: str) -> str:
        _escaped = s.replace('\\', '\\\\')
        _escaped = _escaped.replace('"', '\\"')
        _escaped = _escaped.replace('\n', '\\n')
        _escaped = _escaped.replace('\r', '\\r')
        _escaped = _escaped.replace('\t', '\\t')
        # 截断过长字符串
        if len(_escaped) > 128:
            _escaped = _escaped[:128]
        return _escaped

    def _next_rule_name(self) -> str:
        _c = self._rule_counter
        self._rule_counter += 1
        return f"BinMind_AutoGen_{_c:03d}"

# 批量生成: 从分析结果一键生成所有类型规则

    def batch_generate(self, strings: List[str] = None,
                       imports: Dict[str, List[str]] = None,
                       sections_data: Dict[str, bytes] = None,
                       family_name: str = "Unknown",
                       tags: List[str] = None) -> Dict[str, str]:
        _rules = {}

        if strings and len(strings) > 5:
            _rules['string_rule'] = self.generate_string_rule(
                strings,
                rule_name=f"{family_name}_strings",
                description=f"String-based detection for {family_name}",
            )

        if imports and len(imports) > 0:
            _rules['import_rule'] = self.generate_import_rule(
                imports,
                rule_name=f"{family_name}_imports",
                description=f"Import-based detection for {family_name}",
            )

        if sections_data:
            _rules['section_rule'] = self.generate_section_rule(
                sections_data,
                rule_name=f"{family_name}_sections",
                description=f"Section hash detection for {family_name}",
            )

        _rules['composite_rule'] = self.generate_composite_rule(
            strings=strings,
            imports=imports,
            sections_data=sections_data,
            rule_name=f"{family_name}_composite",
            family_name=family_name,
            tags=tags,
        )

        return _rules
