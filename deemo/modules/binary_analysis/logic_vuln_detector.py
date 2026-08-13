from enum import StrEnum
import logging
import os
import re
from collections import defaultdict
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)


class VulnerabilityType(StrEnum):
    TOCTOU = "toctou"
    PERMISSION_BYPASS = "permission_bypass"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    ACCESS_CONTROL = "access_control"
    RACE_CONDITION = "race_condition"
    SYMLINK_ATTACK = "symlink_attack"
    PATH_TRAVERSAL = "path_traversal"

class VulnerabilitySeverity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class VulnerabilityFinding:
    vuln_type: Any = None
    severity: Any = None
    function_name: Any = None
    address: int = 0
    description: str = ""
    evidence: Any = None
    affected_code: Any = None
    recommendation: Any = None
    confidence: float = 0.0


class TOCTOUMatch:
    __slots__ = ('check_address', 'use_address', 'check_function', 'use_function', 'vulnerable_path', 'confidence',)

    def __init__(self, check_address, use_address, check_function, use_function, vulnerable_path=None, confidence=0.0):
        self.check_address = check_address
        self.use_address = use_address
        self.check_function = check_function
        self.use_function = use_function
        self.vulnerable_path = vulnerable_path
        self.confidence = confidence


class PermissionCheck:
    __slots__ = ('function_name', 'address', 'check_type', 'path_argument', 'permission_flags', 'conditional_jump',)

    def __init__(self, function_name, address, check_type, path_argument, permission_flags, conditional_jump=None):
        self.function_name = function_name
        self.address = address
        self.check_type = check_type
        self.path_argument = path_argument
        self.permission_flags = permission_flags
        self.conditional_jump = conditional_jump


class LogicVulnDetector:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.findings: List[VulnerabilityFinding] = []

    def analyze(self) -> List[VulnerabilityFinding]:
        pass

    def detect_toctou(self) -> List[VulnerabilityFinding]:
        pass

    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        pass


class TOCTORuleEngine:
    TOCTOU_PATTERNS = [
        ('access', 'open', False, 'access()???open()???TOCTOU??'),
        ('access', 'openat', False, 'access()???openat()???TOCTOU??'),
        ('stat', 'open', False, 'stat()???open()???TOCTOU??'),
        ('stat', 'openat', False, 'stat()???openat()???TOCTOU??'),
        ('stat', 'chmod', False, 'stat()???chmod()???TOCTOU??'),
        ('stat', 'chown', False, 'stat()???chown()???TOCTOU??'),
        ('lstat', 'open', True, 'lstat()?open()???????????????'),
        ('lstat', 'openat', True, 'lstat()?openat()?????'),
        ('fstat', 'open', True, 'fstat()?open()???????????????'),
    ]

    DANGEROUS_SEQUENCES = [
        ['access', 'open'],
        ['access', 'chmod'],
        ['access', 'chown'],
        ['stat', 'open'],
        ['stat', 'chmod'],
        ['stat', 'chown'],
        ['stat', 'unlink'],
    ]

    def __init__(self):
        self.matches: List[TOCTOUMatch] = []

    def analyze_call_sequence(self, call_sequence: List[Tuple[str, int]]) -> List[TOCTOUMatch]:
        matches = []

        for i in range(len(call_sequence) - 1):
            check_func, check_addr = call_sequence[i]
            use_func, use_addr = call_sequence[i + 1]

            for pattern_check, pattern_use, is_safe, desc in self.TOCTOU_PATTERNS:
                if check_func == pattern_check and use_func == pattern_use:
                    confidence = 0.8 if not is_safe else 0.2
                    if not is_safe:
                        matches.append(TOCTOUMatch(
                            check_address=check_addr,
                            use_address=use_addr,
                            check_function=check_func,
                            use_function=use_func,
                            confidence=confidence
                        ))

        return matches

    def detect_dangerous_sequences(self, call_graph: Dict[str, List[str]]) -> List[str]:
        dangerous = []

        for func_name, called_funcs in call_graph.items():
            for sequence in self.DANGEROUS_SEQUENCES:
                if all(f in called_funcs for f in sequence):
                    dangerous.append(f"?? {func_name} ??????: {' -> '.join(sequence)}")

        return dangerous


class PermissionAnalysisEngine:
    DANGEROUS_OPS_REQUIRING_CHECK = [
        'open', 'openat', 'chmod', 'chown', 'unlink', 'rmdir',
        'rename', 'link', 'symlink', 'mount', 'umount'
    ]

    PERMISSION_CHECK_FUNCS = [
        'access', 'stat', 'lstat', 'fstat', 'getuid', 'getgid',
        'geteuid', 'getegid', 'setuid', 'setgid', 'cap_get_proc'
    ]

    PERMISSION_FLAGS = {
        'R_OK': 4,
        'W_OK': 2,
        'X_OK': 1,
        'F_OK': 0
    }

    def __init__(self):
        self.permission_checks: List[PermissionCheck] = []

    def find_permission_checks(self, functions: Dict[str, Any]) -> List[PermissionCheck]:
        checks = []

        for func_name, func_info in functions.items():
            calls = func_info.get('calls', [])
            for call in calls:
                if call['name'] in ['access', 'stat', 'lstat']:
                    checks.append(PermissionCheck(
                        function_name=func_name,
                        address=call['address'],
                        check_type=call['name'],
                        path_argument=0,
                        permission_flags=call.get('args', {}).get('mode', 0)
                    ))

        return checks

    def detect_missing_checks(self, call_graph: Dict[str, List[str]]) -> List[str]:
        missing_checks = []

        for func_name, called_funcs in call_graph.items():
            has_permission_check = any(f in self.PERMISSION_CHECK_FUNCS for f in called_funcs)

            for dangerous_op in self.DANGEROUS_OPS_REQUIRING_CHECK:
                if dangerous_op in called_funcs and not has_permission_check:
                    missing_checks.append({
                        'function': func_name,
                        'dangerous_op': dangerous_op,
                        'description': f"?? {func_name} ?? {dangerous_op} ????????"
                    })

        return missing_checks

    def detect_insecure_comparisons(self, instructions: List[Dict[str, Any]]) -> List[str]:
        insecure = []

        hardcoded_patterns = [
            (0, 'root'),
            (1000, '????'),
        ]

        for instr in instructions:
            for uid, desc in hardcoded_patterns:
                if str(uid) in instr.get('disassembly', ''):
                    insecure.append(f"??????UID {uid} ({desc}) ??")

        return insecure


class SimpleLogicVulnDetector(LogicVulnDetector):
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.toctou_engine = TOCTORuleEngine()
        self.permission_engine = PermissionAnalysisEngine()
        self._binary_content = b""
        self._disassembly = ""

    def _load_binary(self):
        if os.path.exists(self.binary_path):
            with open(self.binary_path, 'rb') as f:
                self._binary_content = f.read()

    def _get_disassembly(self) -> str:
        try:
            import subprocess
            result = subprocess.run(
                ['objdump', '-d', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_function_calls(self) -> Dict[str, List[str]]:
        call_graph = defaultdict(list)

        disasm = self._get_disassembly()
        current_func = None

        for line in disasm.split('\n'):
            func_match = re.match(r'^([0-9a-f]+)\s+<(\w+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue

            if current_func:
                call_match = re.search(r'call\s+q?word\s+ptr\s*\[[^]]*\]\s*<(\w+)>', line)
                if not call_match:
                    call_match = re.search(r'bl?\s+[0-9a-f]+\s*<(\w+)>', line)

                if call_match:
                    called_func = call_match.group(1)
                    if called_func not in call_graph[current_func]:
                        call_graph[current_func].append(called_func)

        return dict(call_graph)

    def _find_string_constants(self) -> List[str]:
        strings = []

        pattern = rb'[ -~]{4,}'
        for match in re.finditer(pattern, self._binary_content):
            try:
                strings.append(match.group().decode('utf-8'))
            except Exception:
                pass

        return strings

    def analyze(self) -> List[VulnerabilityFinding]:
        logger.info(f"[LogicVuln] ????????: {self.binary_path}")

        self._load_binary()

        toctou_findings = self.detect_toctou()
        self.findings.extend(toctou_findings)

        permission_findings = self.detect_permission_bypass()
        self.findings.extend(permission_findings)

        path_findings = self.detect_path_traversal()
        self.findings.extend(path_findings)

        logger.info(f"[LogicVuln] ??????? {len(self.findings)} ?????")
        return self.findings

    def detect_toctou(self) -> List[VulnerabilityFinding]:
        findings = []

        try:
            call_graph = self._parse_function_calls()
            dangerous_sequences = self.toctou_engine.detect_dangerous_sequences(call_graph)

            for seq_desc in dangerous_sequences:
                func_match = re.search(r'?? (\w+) ??????', seq_desc)
                func_name = func_match.group(1) if func_match else 'unknown'

                findings.append(VulnerabilityFinding(
                    vuln_type=VulnerabilityType.TOCTOU,
                    severity=VulnerabilitySeverity.HIGH,
                    function_name=func_name,
                    address=0,
                    description=seq_desc,
                    evidence=[seq_desc],
                    recommendation="????openat()??O_NOFOLLOW??????lstat()??stat()",
                    confidence=0.7
                ))

        except Exception as e:
            logger.debug(f"[LogicVuln] TOCTOU????: {e}")

        return findings

    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        findings = []

        try:
            call_graph = self._parse_function_calls()
            missing_checks = self.permission_engine.detect_missing_checks(call_graph)

            for check in missing_checks:
                findings.append(VulnerabilityFinding(
                    vuln_type=VulnerabilityType.PERMISSION_BYPASS,
                    severity=VulnerabilitySeverity.HIGH,
                    function_name=check['function'],
                    address=0,
                    description=check['description'],
                    evidence=[f"????: {check['dangerous_op']}"],
                    recommendation=f"??? {check['dangerous_op']} ??????????",
                    confidence=0.6
                ))

        except Exception as e:
            logger.debug(f"[LogicVuln] ????????: {e}")

        return findings

    def detect_path_traversal(self) -> List[VulnerabilityFinding]:
        findings = []

        try:
            strings = self._find_string_constants()

            path_traversal_patterns = [
                '../', '..\\', '/etc/passwd', '/etc/shadow',
                '~', '/root/', '/home/', '..%2f', '..%5c'
            ]

            for pattern in path_traversal_patterns:
                if pattern in ' '.join(strings):
                    findings.append(VulnerabilityFinding(
                        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                        severity=VulnerabilitySeverity.HIGH,
                        function_name='unknown',
                        address=0,
                        description=f"?????????: {pattern}",
                        evidence=[f"????????: {pattern}"],
                        recommendation="?????????????????realpath()?pathlib??????",
                        confidence=0.5
                    ))

        except Exception as e:
            logger.debug(f"[LogicVuln] ????????: {e}")

        return findings

    def generate_report(self) -> Dict[str, Any]:
        report = {
            'binary_path': self.binary_path,
            'analysis_type': 'logic_vulnerability',
            'findings': [],
            'summary': {
                'total_findings': len(self.findings),
                'critical': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.CRITICAL),
                'high': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.HIGH),
                'medium': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.MEDIUM),
                'low': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.LOW)
            }
        }

        for finding in self.findings:
            report['findings'].append({
                'type': finding.vuln_type.value,
                'severity': finding.severity.value,
                'function_name': finding.function_name,
                'address': hex(finding.address),
                'description': finding.description,
                'evidence': finding.evidence,
                'recommendation': finding.recommendation,
                'confidence': finding.confidence
            })

        return report


class AngrLogicVulnDetector(LogicVulnDetector):
    ANGR_AVAILABLE = False

    def __init__(self, binary_path: str):
        super().__init__(binary_path)

        try:
            import angr
            self.ANGR_AVAILABLE = True
            self.project = angr.Project(binary_path, auto_load_libs=False)
        except ImportError:
            logger.warning("angr ????????????")
            self.project = None

    def is_available(self) -> bool:
        return self.ANGR_AVAILABLE and self.project is not None

    def analyze(self) -> List[VulnerabilityFinding]:
        if not self.is_available():
            simple_detector = SimpleLogicVulnDetector(self.binary_path)
            return simple_detector.analyze()

        logger.info(f"[AngrLogicVuln] ??angr??????: {self.binary_path}")

        findings = []

        toctou_findings = self.detect_toctou()
        findings.extend(toctou_findings)

        permission_findings = self.detect_permission_bypass()
        findings.extend(permission_findings)

        self.findings = findings
        return findings

    def detect_toctou(self) -> List[VulnerabilityFinding]:
        findings = []

        if not self.is_available():
            return findings

        try:
            cfg = self.project.analyses.CFGEmulated()

            for func in cfg.kb.functions.values():
                if not func.is_simprocedure:
                    called_funcs = set()
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            if instr.insn_name() in ['call', 'bl', 'jal', 'jalr']:
                                try:
                                    op_str = instr.op_str
                                    called_funcs.add(op_str)
                                except Exception:
                                    pass

                    if 'access' in called_funcs and 'open' in called_funcs:
                        findings.append(VulnerabilityFinding(
                            vuln_type=VulnerabilityType.TOCTOU,
                            severity=VulnerabilitySeverity.HIGH,
                            function_name=func.name,
                            address=func.addr,
                            description=f"?? {func.name} ?? access() + open() ?????TOCTOU??????",
                            evidence=[f"????: {hex(func.addr)}"],
                            recommendation="????openat()??O_NOFOLLOW??",
                            confidence=0.8
                        ))

        except Exception as e:
            logger.debug(f"[AngrLogicVuln] TOCTOU????: {e}")

        return findings

    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        findings = []

        if not self.is_available():
            return findings

        try:
            cfg = self.project.analyses.CFGEmulated()

            for func in cfg.kb.functions.values():
                if not func.is_simprocedure:
                    called_funcs = set()
                    has_permission_check = False
                    has_dangerous_op = False

                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            op_str = instr.op_str.lower()
                            if any(check in op_str for check in ['access', 'stat', 'lstat', 'getuid', 'getgid']):
                                has_permission_check = True
                            if any(op in op_str for op in ['open', 'chmod', 'chown', 'unlink']):
                                has_dangerous_op = True

                    if has_dangerous_op and not has_permission_check:
                        findings.append(VulnerabilityFinding(
                            vuln_type=VulnerabilityType.PERMISSION_BYPASS,
                            severity=VulnerabilitySeverity.HIGH,
                            function_name=func.name,
                            address=func.addr,
                            description=f"?? {func.name} ?????????????",
                            evidence=[f"????: {hex(func.addr)}"],
                            recommendation="???????????",
                            confidence=0.7
                        ))

        except Exception as e:
            logger.debug(f"[AngrLogicVuln] ????????: {e}")

        return findings


def create_logic_vuln_detector(binary_path: str, use_angr: bool = True) -> LogicVulnDetector:
    if use_angr:
        detector = AngrLogicVulnDetector(binary_path)
        if detector.is_available():
            return detector

    return SimpleLogicVulnDetector(binary_path)


def analyze_logic_vulnerabilities(binary_path: str, use_angr: bool = True) -> Dict[str, Any]:
    detector = create_logic_vuln_detector(binary_path, use_angr)
    findings = detector.analyze()

    return {
        'success': True,
        'binary_path': binary_path,
        'detector_type': type(detector).__name__,
        'findings': [
            {
                'type': f.vuln_type.value,
                'severity': f.severity.value,
                'function_name': f.function_name,
                'address': hex(f.address),
                'description': f.description,
                'evidence': f.evidence,
                'recommendation': f.recommendation,
                'confidence': f.confidence
            }
            for f in findings
        ],
        'total_findings': len(findings),
        'report': detector.generate_report()
    }
