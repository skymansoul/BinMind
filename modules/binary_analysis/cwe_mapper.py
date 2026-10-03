import os
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CWEMapping:
    cwe_id: str
    cwe_name: str
    description: str
    severity: str
    keywords: List[str]
    suggestions: List[str]
    references: List[str]


@dataclass
class CWEClassification:
    cwe_id: str
    cwe_name: str
    confidence: float
    description: str
    suggestions: List[str]


class CWEMapper:
    def __init__(self, mapping_file: str = None):
        self.mappings: Dict[str, List[CWEMapping]] = {}
        self.cwe_details: Dict[str, CWEMapping] = {}
        self._default_mapping_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'data',
            'cwe_mapping.json'
        )
        self.mapping_file = mapping_file or self._default_mapping_file
        self._load_mappings()

    def _load_mappings(self):
        files_to_try = [
            self.mapping_file,
            self._default_mapping_file,
            os.path.join('./data', 'cwe_mapping.json')
        ]

        loaded = False
        for file_path in files_to_try:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    self._parse_mappings(data)
                    logger.info(f"CWE mapping data loaded: {file_path}")
                    loaded = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load CWE mapping file {file_path}: {e}")

        if not loaded:
            logger.warning("CWE mapping file not found, using built-in defaults")
            self._load_default_mappings()

    def _parse_mappings(self, data: Dict[str, Any]):
        for vuln_type, cwe_list in data.get('mappings', {}).items():
            self.mappings[vuln_type] = []
            for cwe_data in cwe_list:
                mapping = CWEMapping(
                    cwe_id=cwe_data.get('cwe_id', ''),
                    cwe_name=cwe_data.get('cwe_name', ''),
                    description=cwe_data.get('description', ''),
                    severity=cwe_data.get('severity', 'Medium'),
                    keywords=cwe_data.get('keywords', []),
                    suggestions=cwe_data.get('suggestions', []),
                    references=cwe_data.get('references', [])
                )
                self.mappings[vuln_type].append(mapping)
                self.cwe_details[cwe_data.get('cwe_id', '')] = mapping

    def _load_default_mappings(self):
        default_mappings = {
            'stack_overflow': [
                {
                    'cwe_id': 'CWE-121',
                    'cwe_name': 'Stack-based Buffer Overflow',
                    'description': 'Program writes data to a fixed-size buffer without validating input length, causing overflow into adjacent memory.',
                    'severity': 'Critical',
                    'keywords': ['stack', 'overflow', 'buffer', 'strcpy', 'gets', 'sprintf'],
                    'suggestions': ['Use safe string functions (strncpy, snprintf)', 'Validate input length before writing', 'Enable stack canary protection'],
                    'references': ['https://cwe.mitre.org/data/definitions/121.html']
                }
            ],
            'heap_overflow': [
                {
                    'cwe_id': 'CWE-122',
                    'cwe_name': 'Heap-based Buffer Overflow',
                    'description': 'Program writes data to a heap buffer without validating input length.',
                    'severity': 'Critical',
                    'keywords': ['heap', 'overflow', 'buffer', 'malloc', 'memcpy', 'realloc'],
                    'suggestions': ['Validate buffer sizes', 'Use bounded copy functions', 'Enable AddressSanitizer'],
                    'references': ['https://cwe.mitre.org/data/definitions/122.html']
                }
            ],
            'format_string': [
                {
                    'cwe_id': 'CWE-134',
                    'cwe_name': 'Uncontrolled Format String',
                    'description': 'Program uses user-controlled string as format parameter to printf-like functions.',
                    'severity': 'High',
                    'keywords': ['format', 'printf', 'sprintf', 'fprintf', 'format string'],
                    'suggestions': ['Use fixed format strings', 'Separate data from format specifiers', 'Use safe formatting functions'],
                    'references': ['https://cwe.mitre.org/data/definitions/134.html']
                }
            ],
            'uaf': [
                {
                    'cwe_id': 'CWE-416',
                    'cwe_name': 'Use After Free',
                    'description': 'Program references memory after it has been freed.',
                    'severity': 'Critical',
                    'keywords': ['use after free', 'double free', 'free', 'dangling pointer'],
                    'suggestions': ['Null pointers after free', 'Use memory-safe languages', 'Enable AddressSanitizer'],
                    'references': ['https://cwe.mitre.org/data/definitions/416.html']
                }
            ],
            'double_free': [
                {
                    'cwe_id': 'CWE-415',
                    'cwe_name': 'Double Free',
                    'description': 'Program frees the same memory region multiple times.',
                    'severity': 'Critical',
                    'keywords': ['double free', 'free', 'memory corruption'],
                    'suggestions': ['Null pointers after free', 'Use smart pointers', 'Enable memory detection tools'],
                    'references': ['https://cwe.mitre.org/data/definitions/415.html']
                }
            ],
            'integer_overflow': [
                {
                    'cwe_id': 'CWE-190',
                    'cwe_name': 'Integer Overflow or Wraparound',
                    'description': 'Integer operation result exceeds the representable range of its type.',
                    'severity': 'High',
                    'keywords': ['integer overflow', 'overflow', 'unsigned', 'signed'],
                    'suggestions': ['Check boundaries before operations', 'Use safe integer types', 'Enable compiler warnings'],
                    'references': ['https://cwe.mitre.org/data/definitions/190.html']
                }
            ],
            'taint_sink': [
                {
                    'cwe_id': 'CWE-20',
                    'cwe_name': 'Improper Input Validation',
                    'description': 'Program does not properly validate user input, allowing malicious data into sensitive operations.',
                    'severity': 'High',
                    'keywords': ['input validation', 'sanitization', 'taint', 'sink'],
                    'suggestions': ['Validate and sanitize all user input', 'Use whitelist validation', 'Limit input length'],
                    'references': ['https://cwe.mitre.org/data/definitions/20.html']
                }
            ],
            'command_injection': [
                {
                    'cwe_id': 'CWE-78',
                    'cwe_name': 'Improper Neutralization of Special Elements used in an OS Command',
                    'description': 'Program passes user input directly to system command execution functions.',
                    'severity': 'Critical',
                    'keywords': ['command injection', 'system', 'exec', 'popen', 'shell'],
                    'suggestions': ['Use parameterized APIs', 'Avoid shell=True', 'Strictly validate input'],
                    'references': ['https://cwe.mitre.org/data/definitions/78.html']
                }
            ],
            'sql_injection': [
                {
                    'cwe_id': 'CWE-89',
                    'cwe_name': 'SQL Injection',
                    'description': 'Program concatenates user input directly into SQL queries.',
                    'severity': 'Critical',
                    'keywords': ['sql injection', 'database', 'query', 'select', 'insert'],
                    'suggestions': ['Use parameterized queries (Prepared Statements)', 'Use ORM frameworks', 'Validate input'],
                    'references': ['https://cwe.mitre.org/data/definitions/89.html']
                }
            ],
            'xss': [
                {
                    'cwe_id': 'CWE-79',
                    'cwe_name': 'Cross-Site Scripting',
                    'description': 'Web application does not properly escape user input, allowing malicious scripts to execute.',
                    'severity': 'High',
                    'keywords': ['xss', 'cross-site scripting', 'javascript', 'html', 'script'],
                    'suggestions': ['HTML-escape output', 'Use safe template engines', 'Set correct Content-Type'],
                    'references': ['https://cwe.mitre.org/data/definitions/79.html']
                }
            ],
            'path_traversal': [
                {
                    'cwe_id': 'CWE-22',
                    'cwe_name': 'Improper Limitation of a Pathname to a Restricted Directory',
                    'description': 'Program does not properly validate file path input, allowing access outside restricted directories.',
                    'severity': 'High',
                    'keywords': ['path traversal', 'directory traversal', '..', '../'],
                    'suggestions': ['Normalize paths before validation', 'Use directory whitelists', 'Block .. in paths'],
                    'references': ['https://cwe.mitre.org/data/definitions/22.html']
                }
            ],
            'null_pointer': [
                {
                    'cwe_id': 'CWE-476',
                    'cwe_name': 'NULL Pointer Dereference',
                    'description': 'Program attempts to access memory via a null pointer.',
                    'severity': 'High',
                    'keywords': ['null pointer', 'dereference', 'crash', 'segmentation fault'],
                    'suggestions': ['Check pointers for null before use', 'Initialize with defaults', 'Enable compiler warnings'],
                    'references': ['https://cwe.mitre.org/data/definitions/476.html']
                }
            ],
            'race_condition': [
                {
                    'cwe_id': 'CWE-362',
                    'cwe_name': 'Concurrent Execution using Shared Resource with Improper Synchronization',
                    'description': 'Multiple threads or processes access shared resources without proper synchronization.',
                    'severity': 'High',
                    'keywords': ['race condition', 'concurrency', 'thread', 'mutex', 'lock'],
                    'suggestions': ['Use mutex locks for shared resources', 'Use atomic operations', 'Avoid shared mutable state'],
                    'references': ['https://cwe.mitre.org/data/definitions/362.html']
                }
            ],
            'uninitialized_variable': [
                {
                    'cwe_id': 'CWE-457',
                    'cwe_name': 'Use of Uninitialized Variable',
                    'description': 'Program uses an uninitialized variable.',
                    'severity': 'Medium',
                    'keywords': ['uninitialized', 'variable', 'garbage value'],
                    'suggestions': ['Initialize all variables', 'Enable compiler warnings', 'Use static analysis tools'],
                    'references': ['https://cwe.mitre.org/data/definitions/457.html']
                }
            ],
            'buffer_underflow': [
                {
                    'cwe_id': 'CWE-124',
                    'cwe_name': 'Buffer Underwrite',
                    'description': 'Program writes data to a buffer at a position below the buffer start address.',
                    'severity': 'High',
                    'keywords': ['buffer underflow', 'underwrite', 'negative index'],
                    'suggestions': ['Validate indices are non-negative', 'Check boundary conditions', 'Use unsigned types'],
                    'references': ['https://cwe.mitre.org/data/definitions/124.html']
                }
            ],
            'insecure_crypto': [
                {
                    'cwe_id': 'CWE-327',
                    'cwe_name': 'Use of a Broken or Risky Cryptographic Algorithm',
                    'description': 'Program uses insecure encryption algorithms or weak keys.',
                    'severity': 'High',
                    'keywords': ['crypto', 'encryption', 'md5', 'sha1', 'weak key'],
                    'suggestions': ['Use strong algorithms (AES-256, SHA-256)', 'Use sufficient key lengths', 'Follow crypto best practices'],
                    'references': ['https://cwe.mitre.org/data/definitions/327.html']
                }
            ],
            'hardcoded_secret': [
                {
                    'cwe_id': 'CWE-798',
                    'cwe_name': 'Use of Hard-coded Credentials',
                    'description': 'Program contains hardcoded sensitive information (passwords, keys).',
                    'severity': 'High',
                    'keywords': ['hardcoded', 'secret', 'password', 'key', 'credentials'],
                    'suggestions': ['Use environment variables for secrets', 'Use key management services', 'Read from config files'],
                    'references': ['https://cwe.mitre.org/data/definitions/798.html']
                }
            ],
            'unrestricted_upload': [
                {
                    'cwe_id': 'CWE-434',
                    'cwe_name': 'Unrestricted Upload of File with Dangerous Type',
                    'description': 'Program allows uploading arbitrary file types, potentially leading to malicious file execution.',
                    'severity': 'High',
                    'keywords': ['file upload', 'upload', 'malicious file', 'webshell'],
                    'suggestions': ['Validate file types', 'Limit file sizes', 'Store outside web-accessible directories'],
                    'references': ['https://cwe.mitre.org/data/definitions/434.html']
                }
            ],
            'missing_authentication': [
                {
                    'cwe_id': 'CWE-287',
                    'cwe_name': 'Improper Authentication',
                    'description': 'Program does not properly verify user identity.',
                    'severity': 'Critical',
                    'keywords': ['authentication', 'login', 'session', 'token'],
                    'suggestions': ['Implement strong authentication', 'Use secure session management', 'Verify all sensitive operations'],
                    'references': ['https://cwe.mitre.org/data/definitions/287.html']
                }
            ],
            'access_control': [
                {
                    'cwe_id': 'CWE-284',
                    'cwe_name': 'Improper Access Control',
                    'description': 'Program does not properly restrict resource access.',
                    'severity': 'High',
                    'keywords': ['access control', 'authorization', 'permission', 'privilege'],
                    'suggestions': ['Implement least privilege principle', 'Verify user permissions', 'Use role-based access control'],
                    'references': ['https://cwe.mitre.org/data/definitions/284.html']
                }
            ]
        }

        self._parse_mappings({'mappings': default_mappings})

    def get_cwe_for_vulnerability(self, vuln_type: str) -> List[CWEClassification]:
        vuln_type_lower = vuln_type.lower().strip()

        if vuln_type_lower in self.mappings:
            results = []
            for mapping in self.mappings[vuln_type_lower]:
                results.append(CWEClassification(
                    cwe_id=mapping.cwe_id,
                    cwe_name=mapping.cwe_name,
                    confidence=1.0,
                    description=mapping.description,
                    suggestions=mapping.suggestions
                ))
            return results

        return self._fuzzy_match(vuln_type_lower)

    def _fuzzy_match(self, vuln_type: str) -> List[CWEClassification]:
        results = []
        matched_types = set()

        vuln_words = set(vuln_type.split())

        for known_type, cwe_list in self.mappings.items():
            known_words = set(known_type.split('_'))

            intersection = vuln_words & known_words
            union = vuln_words | known_words

            if union:
                jaccard = len(intersection) / len(union)
            else:
                jaccard = 0.0

            if jaccard >= 0.5:
                confidence = 0.8 + jaccard * 0.2
                for mapping in cwe_list:
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=min(confidence, 1.0),
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    ))
                matched_types.add(known_type)
                continue

            if known_type in vuln_type:
                for mapping in cwe_list:
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=0.7,
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    ))
                matched_types.add(known_type)
                continue

            for mapping in cwe_list:
                keyword_matches = 0
                total_keywords = len(mapping.keywords)
                for keyword in mapping.keywords:
                    if keyword.lower() in vuln_type:
                        keyword_matches += 1

                if keyword_matches > 0:
                    confidence = 0.3 + (keyword_matches / total_keywords) * 0.4
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=confidence,
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    ))
                    matched_types.add(known_type)

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:5]

    def get_top_cwe(self, vuln_type: str) -> Optional[CWEClassification]:
        results = self.get_cwe_for_vulnerability(vuln_type)
        return results[0] if results else None

    def get_cwe_details(self, cwe_id: str) -> Optional[CWEMapping]:
        return self.cwe_details.get(cwe_id)

    def classify_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        classified = []

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            cwe_results = self.get_cwe_for_vulnerability(vuln_type)

            if cwe_results:
                top_cwe = cwe_results[0]
                vuln['cwe'] = {
                    'id': top_cwe.cwe_id,
                    'name': top_cwe.cwe_name,
                    'confidence': top_cwe.confidence,
                    'description': top_cwe.description,
                    'suggestions': top_cwe.suggestions,
                    'all_candidates': [
                        {
                            'id': c.cwe_id,
                            'name': c.cwe_name,
                            'confidence': c.confidence
                        } for c in cwe_results
                    ]
                }
            else:
                vuln['cwe'] = None

            classified.append(vuln)

        return classified

    def get_all_vulnerability_types(self) -> List[str]:
        return list(self.mappings.keys())

    def get_all_cwe_ids(self) -> List[str]:
        return list(self.cwe_details.keys())

    def add_custom_mapping(self, vuln_type: str, cwe_id: str, cwe_name: str,
                            description: str = '', severity: str = 'Medium',
                            keywords: List[str] = None, suggestions: List[str] = None,
                            references: List[str] = None):
        if vuln_type not in self.mappings:
            self.mappings[vuln_type] = []

        mapping = CWEMapping(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            description=description,
            severity=severity,
            keywords=keywords or [],
            suggestions=suggestions or [],
            references=references or []
        )
        self.mappings[vuln_type].append(mapping)
        self.cwe_details[cwe_id] = mapping

        logger.info(f"Custom CWE mapping added: {vuln_type} -> {cwe_id}")

    def save_mappings(self, output_path: str = None):
        if not output_path:
            output_path = self.mapping_file

        data = {'mappings': {}}

        for vuln_type, cwe_list in self.mappings.items():
            data['mappings'][vuln_type] = []
            for mapping in cwe_list:
                data['mappings'][vuln_type].append({
                    'cwe_id': mapping.cwe_id,
                    'cwe_name': mapping.cwe_name,
                    'description': mapping.description,
                    'severity': mapping.severity,
                    'keywords': mapping.keywords,
                    'suggestions': mapping.suggestions,
                    'references': mapping.references
                })

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"CWE mappings saved: {output_path}")
        except Exception as e:
            logger.error(f"Failed to save CWE mappings: {e}")

    def get_cwe_url(self, cwe_id: str) -> str:
        return f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html"
