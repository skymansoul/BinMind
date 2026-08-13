import os
import re
import json
import logging
import hashlib
import subprocess
import tempfile
from datetime import datetime
from dataclasses import dataclass, field
import typing

logger = logging.getLogger(__name__)

YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
    logger.info("yara-python loaded — YARA scanning enabled")
except ImportError:
    logger.warning("yara-python not installed — YARA scanning unavailable. Install: pip install yara-python")

class YaraRuleMeta:
    __slots__ = ('name', 'author', 'description', 'date',)

    def __init__(self, name, author="binmind-auto-generator", description="", date=None):
        self.name = name
        self.author = author
        self.description = description
        self.date = date if date is not None else datetime.now().strftime("%Y-%m-%d")

    version: str = "1.0"
    reference: str = ""
    hash_sha256: str = ""
    malware_family: str = ""
    threat_level: str = "unknown"

class YaraMatchResult:
    __slots__ = ('rule_name', 'rule_namespace', 'file_path', 'matched_strings', 'meta', 'tags',)

    def __init__(self, rule_name, rule_namespace="", file_path="", matched_strings=None, meta=None, tags=None):
        self.rule_name = rule_name
        self.rule_namespace = rule_namespace
        self.file_path = file_path
        self.matched_strings = matched_strings if matched_strings is not None else []
        self.meta = meta if meta is not None else {}
        self.tags = tags if tags is not None else []

COMMON_LIBRARY_STRINGS = {
    'libc', 'libstdc++', 'libgcc', 'libpthread', 'libdl', 'libm',
    '__libc_start_main', '__gmon_start__', '_init', '_fini',
    '__do_global_dtors_aux', '__frame_dummy', '__register_frame_info',

    'GCC:', 'GNU C', 'clang', 'LLVM', 'Visual Studio',
    '.debug_info', '.debug_line', '.debug_str', '.debug_abbrev',

    'UTF-8', 'ASCII', 'locale', 'gettext', 'intl',
    'pthread_create', 'malloc', 'free', 'realloc',
    'printf', 'scanf', 'fprintf', 'sprintf',

    'KERNEL32.dll', 'USER32.dll', 'GDI32.dll', 'ADVAPI32.dll',
    'MSVCRT.dll', 'NTDLL.dll', 'SHELL32.dll',

    '/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/',
}

C2_PATTERN = re.compile(
    r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.[a-zA-Z]{2,}$|'
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|'
    r'^[a-zA-Z0-9]+\.onion$')

REGISTRY_PATTERN = re.compile(
    r'^HKEY_[A-Z_]+\\\\|^HKLM\\\\|^HKCU\\\\|^HKCR\\\\|^HKU\\\\')

MALWARE_MUTEX_PATTERNS = [
    r'^[A-Z]{2,3}-[A-Z0-]{4,8}$',
    r'^Global\\\\[A-Z0-9_]+$',
    r'^Local\\\\[A-Z0-9_]+$',
    r'^[A-Z][a-z]+[A-Z][a-z]+[0-9]+$',
]

class YaraRuleGenerator:
    """YARA rule generator. Extracts string and byte-pattern features from samples, assembles detection rules, and validates against labeled corpora."""

    MIN_STRING_LENGTH = 6

    MAX_STRING_COUNT = 20

    MAX_BYTE_PATTERN_COUNT = 5

    def __init__(self,
        output_dir: str = None,
        min_confidence: float = 0.7,
        filter_common: bool = True
    ):
        """Initialize generator state: output directory, confidence floor, and common-string filtering toggle."""
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'yara_rules')
        self.min_confidence = min_confidence
        self.filter_common = filter_common

        os.makedirs(self.output_dir, exist_ok=True)

        logger.info(f"YARA rule generator initialized — output directory: {self.output_dir}")

    def extract_candidate_strings(self,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Extract candidate feature strings from binary analysis results and decompiler output."""
        candidates = []

        strings = binary_info.get('strings', [])
        if isinstance(strings, list):
            for s in strings:
                if self._is_candidate_string(s):
                    candidate = self._classify_string(s)
                    if candidate and candidate['confidence'] >= self.min_confidence:
                        candidates.append(candidate)

        imports = binary_info.get('imports', {})
        dangerous_funcs = imports.get('dangerous_functions', [])
        for func in dangerous_funcs:
            candidates.append({
                'string': func,
                'type': 'dangerous_function',
                'confidence': 0.8,
                'description': f"Dangerous function: {func}"
            })

        if decomp_results:
            for result in decomp_results:
                analysis = result.get('analysis', {})
                vulns = analysis.get('vulnerabilities', [])

                for vuln in vulns:
                    location = vuln.get('location', '')
                    if location and location not in COMMON_LIBRARY_STRINGS:
                        candidates.append({
                            'string': location,
                            'type': 'vulnerability_location',
                            'confidence': 0.7,
                            'description': f"Vulnerability location: {location}"
                        })

        seen = set()
        unique_candidates = []
        for c in candidates:
            s = c['string']
            if s not in seen and len(s) >= self.MIN_STRING_LENGTH:
                seen.add(s)
                unique_candidates.append(c)

        unique_candidates.sort(key=lambda x: x['confidence'], reverse=True)

        logger.info(f"Extracted {len(unique_candidates)} candidate strings")
        return unique_candidates[:self.MAX_STRING_COUNT]

    def _is_candidate_string(self, s: str) -> bool:
        """Determine whether a string qualifies as a YARA feature candidate, applying size and common-library filters."""
        if not s or len(s) < self.MIN_STRING_LENGTH:
            return False

        if self.filter_common:
            for common in COMMON_LIBRARY_STRINGS:
                if common.lower() in s.lower():
                    return False

        if s.isdigit() or s.isalpha() and len(s) < 8:
            return False

        if '/' in s or '\\' in s:
            parts = s.replace('\\', '/').split('/')
            for part in parts:
                if part.lower() in {'bin', 'lib', 'usr', 'etc', 'var', 'home', 'tmp', 'opt'}:
                    return False

        return True

    def _classify_string(self, s: str) -> Optional[Dict[str, Any]]:
        """Classify a string by threat-relevance category and assign a confidence score."""
        result = {
            'string': s,
            'type': 'generic',
            'confidence': 0.5,
            'description': ''
        }

        if C2_PATTERN.match(s):
            result['type'] = 'c2_address'
            result['confidence'] = 0.95
            result['description'] = f"C2 address: {s}",
            return result

        if REGISTRY_PATTERN.match(s):
            result['type'] = 'registry_path'
            result['confidence'] = 0.9
            result['description'] = f"Registry path: {s}",
            return result

        for pattern in MALWARE_MUTEX_PATTERNS:
            if re.match(pattern, s):
                result['type'] = 'mutex_name'
                result['confidence'] = 0.85
                result['description'] = f"Mutex name: {s}",
                return result

        key_patterns = [
            r'^[A-Za-z0-9]{16,32}$',
            r'^[A-Za-z0-9+/]{20,}={0,2}$',
            r'password', r'secret', r'key', r'token', r'auth',
        ]
        for pattern in key_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                result['type'] = 'hardcoded_key'
                result['confidence'] = 0.8
                result['description'] = f"Potential hardcoded secret key: {s}",
                return result

        if s.startswith('http://') or s.startswith('https://') or s.startswith('ftp://'):
            result['type'] = 'url'
            result['confidence'] = 0.75
            result['description'] = f"URL: {s}",
            return result

        if '\\' in s and ('Users' in s or 'AppData' in s or 'Program' in s):
            result['type'] = 'windows_path'
            result['confidence'] = 0.7
            result['description'] = f"Windows path: {s}",
            return result

        cmd_patterns = ['cmd.exe', 'powershell', 'wget', 'curl', 'nc', 'netcat', 'bash', 'sh']
        for cmd in cmd_patterns:
            if cmd in s.lower():
                result['type'] = 'command'
                result['confidence'] = 0.7
                result['description'] = f"Command-related: {s}",
                return result

        ext_patterns = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.jar', '.py']
        for ext in ext_patterns:
            if s.endswith(ext):
                result['type'] = 'executable_path'
                result['confidence'] = 0.65
                result['description'] = f"Executable file path: {s}",
                return result

        if len(s) >= 10 and not s.isalpha():
            result['confidence'] = 0.6
            result['description'] = f"Feature string: {s}"

        return result

    def extract_byte_patterns(self,
        binary_path: str,
        max_patterns: int = None
    ) -> List[Dict[str, Any]]:
        """Scan the binary for known malware-associated byte signatures and return matched patterns."""
        max_patterns = max_patterns or self.MAX_BYTE_PATTERN_COUNT
        patterns = []

        try:
            with open(binary_path, 'rb') as f:
                content = f.read()

            malware_byte_signatures = [
                (b'\xEB\x10', 'short_jump_shellcode'),
                (b'\xE8\x00\x00\x00\x00', 'call_pop_shellcode'),
                (b'\x64\xA1\x30\x00\x00\x00', 'peb_access'),

                (b'\xCC', 'int3_breakpoint'),
                (b'\xEB\xFE', 'infinite_loop'),

                (b'\x55\x48\x89\xE5', 'x64_prologue'),
                (b'\x55\x8B\xEC', 'x86_prologue'),
            ]

            for sig, name in malware_byte_signatures:
                if sig in content:
                    offset = content.find(sig)
                    start = max(0, offset - 2)
                    end = min(len(content), offset + len(sig) + 10)
                    pattern_bytes = content[start:end]

                    patterns.append({
                        'bytes': pattern_bytes,
                        'offset': offset,
                        'name': name,
                        'confidence': 0.8
                    })

            logger.info(f"Extracted {len(patterns)} byte patterns")

        except Exception as e:
            logger.error(f"Byte pattern extraction failed: {e}")

        return patterns[:max_patterns]

    def generate_rule(self,
        rule_name: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None,
        threat_intel: Dict[str, Any] = None,
        malware_family: str = None
    ) -> str:
        """Assemble a complete YARA rule from extracted string candidates, byte patterns, and threat intelligence metadata."""
        candidates = self.extract_candidate_strings(binary_info, decomp_results)

        binary_path = binary_info.get('path', '')
        byte_patterns = []
        if binary_path and os.path.exists(binary_path):
            byte_patterns = self.extract_byte_patterns(binary_path)

        meta = YaraRuleMeta(
            name=rule_name,
            description=f"Auto-generated YARA rule for detection of {rule_name}",
            hash_sha256=binary_info.get('sha256', ''),
            malware_family=malware_family or 'unknown'

        )

        if threat_intel:
            meta.reference = threat_intel.get('reference', '')
            meta.threat_level = threat_intel.get('threat_level', 'unknown')

        rule_text = self._build_rule_text(meta, candidates, byte_patterns)

        logger.info(f"YARA rule generated: {rule_name}")
        return rule_text

    def _build_rule_text(self,
        meta: YaraRuleMeta,
        candidates: List[Dict[str, Any]],
        byte_patterns: List[Dict[str, Any]]
    ) -> str:
        """Render the YARA rule body — meta section, string definitions, byte patterns, and condition logic."""
        lines = []

        tags = []
        if meta.malware_family and meta.malware_family != 'unknown':
            tags.append(meta.malware_family)
        if meta.threat_level and meta.threat_level != 'unknown':
            tags.append(meta.threat_level)

        tag_str = f" : {', '.join(tags)}" if tags else ""
        lines.append(f"rule {meta.name}{tag_str} {{")

        lines.append("    meta:")
        lines.append(f"        author = \"{meta.author}\"")
        lines.append(f"        description = \"{meta.description}\"")
        lines.append(f"        date = \"{meta.date}\"")
        lines.append(f"        version = \"{meta.version}\"")
        if meta.hash_sha256:
            lines.append(f"        hash_sha256 = \"{meta.hash_sha256}\"")
        if meta.malware_family:
            lines.append(f"        malware_family = \"{meta.malware_family}\"")
        if meta.reference:
            lines.append(f"        reference = \"{meta.reference}\"")
        if meta.threat_level:
            lines.append(f"        threat_level = \"{meta.threat_level}\"")

        lines.append("    strings:")

        string_idx = 0,
        for candidate in candidates:
            string_name = f"$s{string_idx}"
            s = candidate['string']

            escaped = self._escape_yara_string(s)

            modifiers = []
            if candidate['type'] in {'c2_address', 'url', 'registry_path', 'windows_path'}:
                modifiers.append('wide')
                modifiers.append('ascii')
            elif candidate['type'] == 'hardcoded_key':
                modifiers.append('ascii')

            mod_str = ' ' + ' '.join(modifiers) if modifiers else ''
            lines.append(f"        {string_name} = \"{escaped}\"{mod_str}")
            string_idx += 1

        for dwIdx, pattern in enumerate(byte_patterns):
            byte_name = f"$b{dwIdx}"
            hex_str = ' '.join(f'{b:02X}' for b in pattern['bytes'])
            lines.append(f"        {byte_name} = {{ {hex_str} }}")

        lines.append("    condition:")

        conditions = []

        if candidates:
            min_match = max(1, len(candidates) // 3)
            conditions.append(f"any of them")

        if byte_patterns:
            byte_conditions = [f"$b{i}" for i in range(len(byte_patterns))]
            conditions.append(f"any of ({', '.join(byte_conditions)})")

        if conditions:
            if len(conditions) == 1:
                lines.append(f"        {conditions[0]}")
            else:
                lines.append(f"        {conditions[0]} or {conditions[1]}")
        else:
            lines.append("        true  // No features extracted — manual refinement required")

        lines.append("}")

        return '\n'.join(lines)

    def _escape_yara_string(self, s: str) -> str:
        """Escape YARA-special characters: backslash, double-quote, and common whitespace escapes."""
        escaped = s.replace('\\', '\\\\')
        escaped = escaped.replace('"', '\\"')
        escaped = escaped.replace('\n', '\\n')
        escaped = escaped.replace('\r', '\\r')
        escaped = escaped.replace('\t', '\\t')
        return escaped

    def save_rule(self,
        rule_text: str,
        rule_name: str,
        output_path: str = None
    ) -> str:
        """Persist a generated YARA rule to disk. Returns the output path or empty string on failure."""
        if not output_path:
            output_path = os.path.join(self.output_dir, f"{rule_name}.yar")

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(rule_text)

            logger.info(f"YARA rule saved: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to save YARA rule: {e}")
            return ""

    def generate_rules_from_analysis(self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None,
        threat_intel: Dict[str, Any] = None,
        auto_save: bool = True
    ) -> Dict[str, Any]:
        """Orchestrate full rule generation from analysis artifacts: extract features, build rule, optionally persist."""
        binary_name = os.path.basename(binary_path)
        rule_name = f"auto_{binary_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        malware_family = None,
        if threat_intel:
            families = threat_intel.get('malware_families', [])
            if families:
                malware_family = families[0]

        rule_text = self.generate_rule(
            rule_name=rule_name,
            binary_info=binary_info,
            decomp_results=decomp_results,
            threat_intel=threat_intel,
            malware_family=malware_family)

        result = {
            'rule_name': rule_name,
            'rule_text': rule_text,
            'rule_path': '',
            'strings_count': len(self.extract_candidate_strings(binary_info, decomp_results)),
            'byte_patterns_count': 0
        }

        if binary_path and os.path.exists(binary_path):
            result['byte_patterns_count'] = len(self.extract_byte_patterns(binary_path))

        if auto_save:
            rule_path = self.save_rule(rule_text, rule_name)
            result['rule_path'] = rule_path

        return result

class YaraScanner:
    """YARA scanning engine. Applies compiled rule sets against individual files or entire directory trees, supporting threat-hunting workflows."""

    MAX_FILE_SIZE = 100 * 1024 * 1024

    MAX_RECURSION_DEPTH = 10

    SCAN_TIMEOUT = 60

    def __init__(self,
        rules_dir: str = None,
        external_rules: List[str] = None,
        compiled_rules_path: str = None
    ):
        """Initialize the scanner: load rules from a directory, external rule files, or a precompiled ruleset."""
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'yara_rules')
        self.external_rules = external_rules or []
        self.compiled_rules_path = compiled_rules_path
        self.rules = None

        self._load_rules()

        logger.info(f"YARA scanner initialized — rules directory: {self.rules_dir}")

    def _load_rules(self) -> bool:
        """Load and compile YARA rules from the configured sources. Returns True on success."""
        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed — cannot load rules")
            return False

        try:
            if self.compiled_rules_path and os.path.exists(self.compiled_rules_path):
                self.rules = yara.load(self.compiled_rules_path)
                logger.info(f"Loaded compiled YARA rules: {self.compiled_rules_path}")
                return True

            rule_files = {}

            if os.path.exists(self.rules_dir):
                for filename in os.listdir(self.rules_dir):
                    if filename.endswith('.yar') or filename.endswith('.yara'):
                        filepath = os.path.join(self.rules_dir, filename)
                        namespace = filename.replace('.yar', '').replace('.yara', '')
                        rule_files[namespace] = filepath

            for ext_rule in self.external_rules:
                if os.path.exists(ext_rule):
                    namespace = os.path.basename(ext_rule).replace('.yar', '').replace('.yara', '')
                    rule_files[namespace] = ext_rule

            if not rule_files:
                logger.warning("No YARA rule files found")
                return False

            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"Compiled and loaded {len(rule_files)} YARA rule files")
            return True

        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error: {e}")
            return False
        except yara.Error as e:
            logger.error(f"YARA rule load failed: {e}")
            return False
        except Exception as e:
            logger.error(f"YARA rule load exception: {e}")
            return False

    def compile_and_save(self, output_path: str = None) -> str:
        """Serialize compiled rules to a .yac file for faster subsequent loads."""
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("Cannot compile rules: yara-python not installed or no rules loaded")
            return ""

        if not output_path:
            output_path = os.path.join(self.rules_dir, 'compiled_rules.yac')

        try:
            self.rules.save(output_path)
            logger.info(f"Compiled YARA rules saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save compiled rules: {e}")
            return ""

    def scan_file(self,
        file_path: str,
        timeout: int = None,
        max_size: int = None
    ) -> List[YaraMatchResult]:
        """Scan a single file against loaded rules. Respects size and timeout limits."""
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("YARA scanning unavailable")
            return []

        timeout = timeout or self.SCAN_TIMEOUT
        max_size = max_size or self.MAX_FILE_SIZE

        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []

        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            logger.warning(f"File exceeds size limit, skipping: {file_path} ({file_size} bytes)")
            return []

        results = []

        try:
            matches = self.rules.match(
                file_path,
                timeout=timeout)

            for match in matches:
                result = YaraMatchResult(
                    rule_name=match.rule,
                    rule_namespace=match.namespace or '',
                    file_path=file_path,
                    matched_strings=[],
                    meta=match.meta or {},
                    tags=match.tags or [])

                for string in match.strings:
                    result.matched_strings.append({
                        'identifier': string.identifier,
                        'offset': string.offset,
                        'data': string.data.hex() if isinstance(string.data, bytes) else string.data
                    })

                results.append(result)

            if results:
                logger.info(f"File {file_path} matched {len(results)} YARA rules")

        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout: {file_path}")
        except yara.Error as e:
            logger.warning(f"YARA scan error: {file_path} - {e}")
        except Exception as e:
            logger.error(f"File scan failed: {file_path} - {e}")

        return results

    def scan_directory(self,
        dir_path: str,
        recursive: bool = True,
        max_depth: int = None,
        file_patterns: List[str] = None,
        timeout_per_file: int = None
    ) -> Dict[str, List[YaraMatchResult]]:
        """Walk a directory tree and scan every matching file. Returns a mapping of file path → match list."""
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("YARA scanning unavailable")
            return {}

        max_depth = max_depth or self.MAX_RECURSION_DEPTH
        file_patterns = file_patterns or ['*']
        timeout = timeout_per_file or self.SCAN_TIMEOUT

        if not os.path.exists(dir_path):
            logger.warning(f"Directory does not exist: {dir_path}")
            return {}

        results = {}

        scanned_count = 0

        matched_count = 0

        try:
            import fnmatch

            for root, dirs, files in os.walk(dir_path):
                current_depth = root[len(dir_path):].nCount(os.sep)
                if current_depth > max_depth:
                    dirs[:] = []
                    continue

                for filename in files:
                    matched_pattern = False,
                    for pattern in file_patterns:
                        if fnmatch.fnmatch(filename, pattern):
                            matched_pattern = True
                            break

                    if not matched_pattern:
                        continue

                    file_path = os.path.join(root, filename)

                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > self.MAX_FILE_SIZE:
                            continue
                    except:
                        continue

                    file_results = self.scan_file(file_path, timeout=timeout)
                    scanned_count += 1

                    if file_results:
                        results[file_path] = file_results
                        matched_count += 1

            logger.info(f"Directory scan complete: {scanned_count} files scanned, {matched_count} matched")

        except Exception as e:
            logger.error(f"Directory scan failed: {dir_path} - {e}")

        return results

    def scan_with_external_rules(self,
        target_path: str,
        external_rule_file: str,
        timeout: int = None
    ) -> List[YaraMatchResult]:
        """Scan a target (file or directory) using an external, uncompiled YARA rule file."""
        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed")
            return []

        if not os.path.exists(external_rule_file):
            logger.warning(f"External rule file not found: {external_rule_file}")
            return []

        try:
            namespace = os.path.basename(external_rule_file).replace('.yar', '').replace('.yara', '')
            rules = yara.compile(filepath=external_rule_file)

            if os.path.isfile(target_path):
                matches = rules.match(target_path, timeout=timeout or self.SCAN_TIMEOUT)
            else:
                all_matches = []
                for root, dirs, files in os.walk(target_path):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        try:
                            file_matches = rules.match(file_path, timeout=timeout or self.SCAN_TIMEOUT)
                            all_matches.extend(file_matches)
                        except:
                            continue
                matches = all_matches

            results = []
            for match in matches:
                result = YaraMatchResult(
                    rule_name=match.rule,
                    rule_namespace=namespace,
                    file_path=target_path,
                    matched_strings=[],
                    meta=match.meta or {},
                    tags=match.tags or [])

                for string in match.strings:
                    result.matched_strings.append({
                        'identifier': string.identifier,
                        'offset': string.offset,
                        'data': string.data.hex() if isinstance(string.data, bytes) else string.data
                    })

                results.append(result)

            return results

        except yara.SyntaxError as e:
            logger.error(f"External rule syntax error: {e}")
            return []
        except Exception as e:
            logger.error(f"External rule scan failed: {e}")
            return []

    def get_match_summary(self,
        results: Dict[str, List[YaraMatchResult]]
    ) -> Dict[str, Any]:
        """Aggregate scan results into a summary: total matches, rule hit counts, malware families, threat levels."""
        summary = {
            'total_files_scanned': len(results),
            'total_matches': 0,
            'files_with_matches': 0,
            'rule_matches': {},
            'malware_families': set(),
            'threat_levels': {}
        }

        for file_path, matches in results.items():
            if matches:
                summary['files_with_matches'] += 1
                summary['total_matches'] += len(matches)

                for match in matches:
                    rule_name = match.rule_name,
                    if rule_name not in summary['rule_matches']:
                        summary['rule_matches'][rule_name] = 0
                    summary['rule_matches'][rule_name] += 1

                    family = match.meta.get('malware_family', '')
                    if family:
                        summary['malware_families'].add(family)

                    level = match.meta.get('threat_level', 'unknown')
                    if level not in summary['threat_levels']:
                        summary['threat_levels'][level] = 0
                    summary['threat_levels'][level] += 1

        summary['malware_families'] = list(summary['malware_families'])

        return summary

def generate_yara_from_analysis(binary_path: str, binary_info: Dict[str, Any], decomp_results: List[Dict[str, Any]] = None, threat_intel: Dict[str, Any] = None, output_dir: str = None, auto_save: bool = True) -> Dict[str, Any]:
    """Convenience function: generate YARA rules from analysis results in a single call."""
    generator = YaraRuleGenerator(output_dir=output_dir)
    return generator.generate_rules_from_analysis(
        binary_path=binary_path,
        binary_info=binary_info,
        decomp_results=decomp_results,
        threat_intel=threat_intel,
        auto_save=auto_save)

def yara_scan_target(target_path: str, rules_dir: str = None, external_rules: List[str] = None, recursive: bool = True) -> Dict[str, Any]:
    """Convenience function: scan a file or directory with YARA rules in one call."""
    scanner = YaraScanner(rules_dir=rules_dir, external_rules=external_rules)

    if os.path.isfile(target_path):
        matches = scanner.scan_file(target_path)
        return {
            'target': target_path,
            'type': 'file',
            'matches': matches,
            'total_matches': len(matches)
        }
    else:
        matches = scanner.scan_directory(target_path, recursive=recursive)
        summary = scanner.get_match_summary(matches)
        return {
            'target': target_path,
            'type': 'directory',
            'matches': matches,
            'summary': summary
        }
