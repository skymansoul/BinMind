
import json
import logging
import math
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RulePattern:
    type: str; value: str; offset_hint: str = 'any'

@dataclass
class Rule:
    name: str; description: str = ""
    patterns: List[RulePattern] = field(default_factory=list)
    condition: Dict = field(default_factory=dict)

@dataclass
class RuleMatch:
    rule_name: str; pattern_name: str; offset: int; evidence: str = ""


_ELF_MAGIC = b"\x7fELF"


def _builtin_rules() -> List[Rule]:
    return [
        Rule(name='ollvm_patterns', description='OLLVM obfuscation patterns',
            patterns=[
                RulePattern('bytes', r'\x55\x89\xe5.*?\xe9', 'any'),
                RulePattern('bytes', r'\xe8\x00\x00\x00\x00', 'any'),
                RulePattern('regex', r'mov\s+e(cx|dx|ax),\s*\[', 'any')],
            condition={'type': 'or', 'value': 0}),
        Rule(name='vmprotect_signatures', description='VMProtect virtualized code',
            patterns=[
                RulePattern('bytes', b'VMProtect'.hex(), 'any'),
                RulePattern('bytes', b'.vmp0'.hex(), 'start'),
                RulePattern('bytes', b'.vmp1'.hex(), 'any'),
                RulePattern('bytes', b'.vmp2'.hex(), 'any'),
                RulePattern('bytes', r'\x9c\x60', 'entry'),
                RulePattern('regex', r'call\s+\$[\+\-]0x[0-9a-f]+.*?push\s+[a-z0-9]+', 'any')],
            condition={'type': 'min_matches', 'value': 1}),
        Rule(name='themida_signatures', description='Themida / WinLicense',
            patterns=[
                RulePattern('bytes', b'Themida'.hex(), 'any'),
                RulePattern('bytes', b'WinLicense'.hex(), 'any'),
                RulePattern('bytes', r'\xe8\x00\x00\x00\x00\x58', 'any'),
                RulePattern('bytes', r'\x0f\x31.*?\x0f\x31', 'any')],
            condition={'type': 'min_matches', 'value': 1}),
        Rule(name='high_entropy_sections', description='Sections with entropy > 7.2',
            patterns=[RulePattern('entropy', '7.2', 'any')],
            condition={'type': 'and', 'value': 0}),
        Rule(name='anti_debug_patterns', description='Anti-debugging API calls',
            patterns=[
                RulePattern('import', 'kernel32.dll:IsDebuggerPresent', 'any'),
                RulePattern('import', 'kernel32.dll:CheckRemoteDebuggerPresent', 'any'),
                RulePattern('import', 'ntdll.dll:NtQueryInformationProcess', 'any'),
                RulePattern('import', 'kernel32.dll:OutputDebugStringA', 'any'),
                RulePattern('bytes', r'\x64\xa1\x30\x00\x00\x00', 'any'),
                RulePattern('bytes', r'\x65\x48\x8b\x04\x25\x60\x00\x00\x00', 'any'),
                RulePattern('regex', r'mov\s+[a-z]+,\s*(dword )?fs:\[0x30\]', 'any')],
            condition={'type': 'min_matches', 'value': 1}),
        Rule(name='packing_stubs', description='Common packer signatures',
            patterns=[
                RulePattern('bytes', b'UPX0'.hex(), 'start'),
                RulePattern('bytes', b'UPX1'.hex(), 'start'),
                RulePattern('bytes', b'UPX!'.hex(), 'start'),
                RulePattern('bytes', b'.aspack'.hex(), 'start'),
                RulePattern('bytes', b'.adata'.hex(), 'start'),
                RulePattern('bytes', b'MPRESS1'.hex(), 'start'),
                RulePattern('bytes', b'MPRESS2'.hex(), 'start'),
                RulePattern('bytes', r'\x60\xe8\x00\x00\x00\x00', 'entry')],
            condition={'type': 'min_matches', 'value': 1}),
        Rule(name='code_virtualization', description='Multi-vendor VM code protection',
            patterns=[
                RulePattern('bytes', r'\xe8\x00\x00\x00\x00', 'any'),
                RulePattern('bytes', r'\xff\x24\x9', 'any'),
                RulePattern('regex', r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*[\+\-]', 'any'),
                RulePattern('regex', r'mov\s+r\w+,\s*\[r\w+\s*\*\s*[0-9]', 'any')],
            condition={'type': 'proximity', 'value': 256, 'min_hits': 2}),
        Rule(name='elf_anomalies', description='ELF structure anomalies: stripped, corrupted, modified',
            patterns=[
                RulePattern('elf_section', '.gnu_debuglink', 'any'),
                RulePattern('elf_section', '.gnu_debugdata', 'any'),
                RulePattern('elf_phdr', 'GNU_STACK', 'any'),
                RulePattern('elf_phdr', 'GNU_RELRO', 'any')],
            condition={'type': 'min_matches', 'value': 1}),
        Rule(name='elf_infection', description='ELF infection: PT_NOTE->PT_LOAD, segment padding code',
            patterns=[
                RulePattern('elf_phdr', 'PT_NOTE', 'any'),
                RulePattern('elf_segment_gap', '4096', 'any')],
            condition={'type': 'proximity', 'value': 4096, 'min_hits': 2}),
    ]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def _parse_pe_imports(data: bytes) -> List[str]:
    results: List[str] = []
    try:
        import pefile
        pe = pefile.PE(data=data)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                for imp in entry.imports:
                    if imp.name:
                        results.append(f'{dll_name}:{imp.name.decode("utf-8", errors="replace")}')
    except ImportError:
        pass
    except Exception as e:
        logger.debug("PE import parse error: %s", e)
    return results


# ELF 结构解析 - 用于 elf_section / elf_phdr / elf_segment_gap 规则模式
# ELF ABI: e_shoff / e_shnum / e_phoff / e_phnum

def _parse_elf_sections(data: bytes) -> List[str]:
    names: List[str] = []
    if data[:4] != _ELF_MAGIC:
        return names
    try:
        if data[4] == 1:
            bitness = 32
        elif data[4] == 2:
            bitness = 64
        else:
            return names
        endian = '<' if data[5] == 1 else '>'
        fmt = endian + ('HHIIIIIHHII' if bitness == 32 else 'HHIQQQIHHII')
        e_shoff_off = 32 if bitness == 32 else 40
        e_shentsize_off = 46 if bitness == 32 else 58
        e_shnum_off = 48 if bitness == 32 else 60
        e_shstrndx_off = 50 if bitness == 32 else 62
        e_shoff = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, e_shoff_off)[0]
        e_shentsize = struct.unpack_from('<H', data, e_shentsize_off)[0]
        e_shnum = struct.unpack_from('<H', data, e_shnum_off)[0]
        e_shstrndx = struct.unpack_from('<H', data, e_shstrndx_off)[0]
        if e_shnum == 0 or e_shoff == 0:
            return names
        shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
        shstrtab_off = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, shstrtab_hdr + 16)[0]
        for i in range(min(e_shnum, 256)):
            shdr = e_shoff + i * e_shentsize
            sh_name_idx = struct.unpack_from('<I', data, shdr)[0]
            name_end = data.find(b'\x00', shstrtab_off + sh_name_idx)
            name = data[shstrtab_off + sh_name_idx:name_end].decode('ascii', errors='replace')
            names.append(name)
    except (struct.error, IndexError):
        pass
    return names


def _parse_elf_phdrs(data: bytes) -> List[str]:
    types: List[str] = []
    if data[:4] != _ELF_MAGIC:
        return types
    try:
        bitness = 64 if data[4] == 2 else 32
        endian = '<' if data[5] == 1 else '>'
        e_phoff_off = 28 if bitness == 32 else 32
        e_phentsize_off = 42 if bitness == 32 else 54
        e_phnum_off = 44 if bitness == 32 else 56
        e_phoff = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, e_phoff_off)[0]
        e_phentsize = struct.unpack_from('<H', data, e_phentsize_off)[0]
        e_phnum = struct.unpack_from('<H', data, e_phnum_off)[0]
        ptype_names = {0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP',
                       4: 'PT_NOTE', 6: 'PT_PHDR', 0x6474E550: 'PT_GNU_EH_FRAME',
                       0x6474E551: 'PT_GNU_STACK', 0x6474E552: 'PT_GNU_RELRO',
                       0x65041580: 'PT_SUNW_EH_FRAME', 0x6CCF0F1B: 'PT_LOPROC'}
        for i in range(min(e_phnum, 32)):
            phdr = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, phdr)[0]
            types.append(ptype_names.get(p_type, f'PT_UNKNOWN({p_type})'))
    except (struct.error, IndexError):
        pass
    return types


def _find_elf_segment_gaps(data: bytes) -> List[Tuple[int, int]]:
    gaps: List[Tuple[int, int]] = []
    if data[:4] != _ELF_MAGIC or data[4] not in (1, 2):
        return gaps
    try:
        bitness = 64 if data[4] == 2 else 32
        endian = '<' if data[5] == 1 else '>'
        e_phoff_off = 28 if bitness == 32 else 32
        e_phentsize_off = 42 if bitness == 32 else 54
        e_phnum_off = 44 if bitness == 32 else 56
        e_phoff = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, e_phoff_off)[0]
        e_phentsize = struct.unpack_from('<H', data, e_phentsize_off)[0]
        e_phnum = struct.unpack_from('<H', data, e_phnum_off)[0]
        load_segments = []
        for i in range(min(e_phnum, 32)):
            phdr = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, phdr)[0]
            if p_type == 1:
                p_offset = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, phdr + 4)[0]
                p_filesz = struct.unpack_from(endian + ('I' if bitness == 32 else 'Q'), data, phdr + 16)[0]
                load_segments.append((p_offset, p_offset + p_filesz))
        load_segments.sort()
        for i in range(len(load_segments) - 1):
            gap = load_segments[i + 1][0] - load_segments[i][1]
            if gap > 512:
                gaps.append((load_segments[i][1], gap))
    except (struct.error, IndexError):
        pass
    return gaps


def _extract_strings(data: bytes, min_len: int = 4) -> Dict[int, str]:
    strings: Dict[int, str] = {}
    current: List[int] = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(b)
        else:
            if len(current) >= min_len:
                strings[start] = bytes(current).decode('ascii')
            current = []
    if len(current) >= min_len:
        strings[start] = bytes(current).decode('ascii')
    if len(data) >= 2:
        current_wide: List[int] = []
        w_start = 0
        pairs = [(data[i], data[i + 1]) for i in range(0, len(data) - 1, 2)]
        for idx, (lo, hi) in enumerate(pairs):
            cp = lo | (hi << 8)
            if 0x20 <= cp < 0x7f and hi == 0:
                if not current_wide:
                    w_start = idx * 2
                current_wide.append(cp)
            else:
                if len(current_wide) >= min_len:
                    strings[w_start] = ''.join(chr(c) for c in current_wide)
                current_wide = []
        if len(current_wide) >= min_len:
            strings[w_start] = ''.join(chr(c) for c in current_wide)
    return strings


# 匹配调度

def _match_pattern(data: bytes, pattern: RulePattern, imports: List[str],
                   strings: Dict[int, str]) -> List[Tuple[int, str]]:
    matches: List[Tuple[int, str]] = []
    ptype, pval = pattern.type, pattern.value

# ELF section 名称匹配
    if ptype == 'elf_section':
        sections = _parse_elf_sections(data)
        for sec_name in sections:
            if pval.lower() in sec_name.lower():
                matches.append((0, f'elf_section: {sec_name}'))
                break
        return matches

# ELF program header 类型匹配
    if ptype == 'elf_phdr':
        phdrs = _parse_elf_phdrs(data)
        for phdr_name in phdrs:
            if pval.upper() in phdr_name.upper():
                matches.append((0, f'elf_phdr: {phdr_name}'))
                break
        return matches

# ELF 段空隙检测
    if ptype == 'elf_segment_gap':
        gaps = _find_elf_segment_gaps(data)
        for gap_start, gap_size in gaps:
            matches.append((gap_start, f'elf_segment_gap: {gap_size} bytes @ {gap_start:#x}'))
        return matches

# 标准模式类型
    if ptype == 'bytes':
        try:
            if isinstance(pval, bytes):
                search_val = pval
            elif isinstance(pval, str) and all(c in '0123456789abcdefABCDEF \t' for c in pval.replace(' ', '')):
                search_val = bytes.fromhex(pval.replace(' ', ''))
            else:
                compiled = re.compile(pval if isinstance(pval, bytes) else pval.encode('latin-1'), re.DOTALL)
                for m in re.finditer(compiled, data):
                    matches.append((m.start(), f'bytes regex hit @ {m.start():#x}'))
                return matches
            offset = 0
            while True:
                pos = data.find(search_val, offset)
                if pos == -1:
                    break
                matches.append((pos, f'bytes {search_val[:8].hex()}... @ {pos:#x}'))
                offset = pos + 1
                if pattern.offset_hint == 'start' and pos > 4096:
                    break
        except Exception as e:
            logger.debug("bytes match error: %s", e)
    elif ptype == 'hex':
        try:
            search_val = bytes.fromhex(pval.replace(' ', ''))
            offset = 0
            while True:
                pos = data.find(search_val, offset)
                if pos == -1:
                    break
                matches.append((pos, f'hex {pval[:16]}... @ {pos:#x}'))
                offset = pos + 1
        except Exception as e:
            logger.debug("hex match error: %s", e)
    elif ptype == 'string':
        search_s = pval
        for addr, s in strings.items():
            if search_s.lower() in s.lower():
                matches.append((addr, f'string "{search_s}" in "{s}"'))
        try:
            encoded = search_s.encode('ascii')
            offset = 0
            while True:
                pos = data.find(encoded, offset)
                if pos == -1:
                    break
                matches.append((pos, f'string "{search_s}" @ {pos:#x}'))
                offset = pos + 1
        except Exception:
            pass
    elif ptype == 'regex':
        try:
            compiled = re.compile(pval, re.DOTALL | re.IGNORECASE)
            for m in re.finditer(compiled, data):
                snippet = data[max(0, m.start() - 4):min(len(data), m.end() + 4)]
                matches.append((m.start(), f'regex match: {snippet.hex()[:32]}'))
        except re.error as e:
            logger.debug("regex compile error: %s", e)
    elif ptype == 'import':
        search_val = pval.lower()
        for imp in imports:
            if search_val in imp.lower():
                matches.append((0, f'import {imp}'))
    elif ptype == 'entropy':
        try:
            threshold = float(pval)
        except ValueError:
            threshold = 7.0
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            ent = _shannon_entropy(chunk)
            if ent >= threshold:
                matches.append((i, f'entropy {ent:.2f} >= {threshold}'))

    return matches


# 规则引擎

class RuleEngine:

    def __init__(self):
        self.rules: List[Rule] = []
        for r in _builtin_rules():
            self.rules.append(r)

    def load_rules(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("rules file must contain a JSON array")
            for entry in data:
                if 'name' not in entry:
                    raise ValueError(f"rule missing 'name': {entry}")
                name, desc = entry['name'], entry.get('description', '')
                patterns = []
                for p in entry.get('patterns', []):
                    if 'type' not in p or 'value' not in p:
                        raise ValueError(f"pattern missing type/value in rule '{name}'")
                    patterns.append(RulePattern(
                        type=p['type'], value=p['value'],
                        offset_hint=p.get('offset_hint', 'any')))
                condition = entry.get('condition', {'type': 'or', 'value': 0})
                if 'type' not in condition:
                    raise ValueError(f"condition missing 'type' in rule '{name}'")
                self.rules.append(Rule(name=name, description=desc,
                                       patterns=patterns, condition=condition))
            logger.info("loaded %d rules from %s", len(data), path)
        except Exception as e:
            logger.error("load_rules error: %s", e)

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def get_matches(self, rule_name: str) -> List[RuleMatch]:
        return [m for m in self._last_matches if m.rule_name == rule_name]

    def scan_binary(self, filepath: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            logger.error("read binary error: %s", e)
            return matches
        imports = _parse_pe_imports(data)
        strings = _extract_strings(data)
        logger.debug("imports=%d, strings=%d", len(imports), len(strings))

        for rule in self.rules:
            rule_matches: List[RuleMatch] = []
            for i, pattern in enumerate(rule.patterns):
                pattern_matches = _match_pattern(data, pattern, imports, strings)
                for offset, evidence in pattern_matches:
                    rule_matches.append(RuleMatch(
                        rule_name=rule.name,
                        pattern_name=f'{pattern.type}:{i}',
                        offset=offset, evidence=evidence))
            cond_type = rule.condition.get('type', 'or')
            cond_val = rule.condition.get('value', 0)
            kept = []
            if cond_type == 'and':
                pattern_indices = {int(m.pattern_name.split(':')[1]) for m in rule_matches}
                if len(pattern_indices) == len(rule.patterns):
                    kept = rule_matches
            elif cond_type == 'min_matches':
                if len(rule_matches) >= cond_val:
                    kept = rule_matches
            elif cond_type == 'proximity':
                min_hits = rule.condition.get('min_hits', 2)
                window = cond_val if cond_val > 0 else 256
                if len(rule_matches) >= min_hits:
                    sorted_offsets = sorted(m.offset for m in rule_matches)
                    proximity_found = False
                    j = 0
                    for i_off in range(len(sorted_offsets)):
                        while j < len(sorted_offsets) and sorted_offsets[j] - sorted_offsets[i_off] <= window:
                            j += 1
                        if j - i_off >= min_hits:
                            proximity_found = True
                            break
                    if proximity_found:
                        kept = rule_matches
            elif cond_type == 'exclude':
                if not rule_matches:
                    kept = []
            else:
                if rule_matches:
                    kept = rule_matches
            matches.extend(kept)

        self._last_matches = matches
        logger.info("scan done: %d matches across %d rules", len(matches), len(self.rules))
        return matches

    _last_matches: List[RuleMatch] = []


def scan_for_obfuscation(binary_path: str) -> Dict[str, List[RuleMatch]]:
    engine = RuleEngine()
    matches = engine.scan_binary(binary_path)
    grouped: Dict[str, List[RuleMatch]] = {}
    for m in matches:
        grouped.setdefault(m.rule_name, []).append(m)
    return grouped
