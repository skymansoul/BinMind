from enum import StrEnum
import logging
import re
from dataclasses import dataclass, field

from typing import Optional
logger = logging.getLogger(__name__)

class BreakpointType(StrEnum):
    EXECUTION = "execution"
    WRITE = "write"
    READ_WRITE = "read_write"
    IO = "io"
    UNKNOWN = "unknown"

class DetectionMethod(StrEnum):
    DR_REGISTER_ACCESS = "dr_register_access"
    INT3_PATTERN = "int3_pattern"
    EXCEPTION_HANDLER_HOOK = "exception_handler_hook"
    TIMING_ANALYSIS = "timing_analysis"
    SELF_DEBUGGING = "self_debugging"
    ANTI_ANTI_DEBUG = "anti_anti_debug"

class RegisterState(StrEnum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    TAMPERED = "tampered"

@dataclass
class DrRegister:
    name: str = ""
    value: Any = None
    state: Any = None
    def decode_dr7(self) -> Dict[str, Any]:
        # Map DR7 control register bit fields to their decoded semantics.
        if self.name != "DR7":
            return {}
        return {
            'L0': bool(self.value & (1 << 0)),  'G0': bool(self.value & (1 << 1)),
            'L1': bool(self.value & (1 << 2)),  'G1': bool(self.value & (1 << 3)),
            'L2': bool(self.value & (1 << 4)),  'G2': bool(self.value & (1 << 5)),
            'L3': bool(self.value & (1 << 6)),  'G3': bool(self.value & (1 << 7)),
            'LE': bool(self.value & (1 << 8)),  'GE': bool(self.value & (1 << 9)),
            'GD': bool(self.value & (1 << 13)),
            'RW0': (self.value >> 16) & 3, 'LEN0': (self.value >> 18) & 3,
            'RW1': (self.value >> 20) & 3, 'LEN1': (self.value >> 22) & 3,
            'RW2': (self.value >> 24) & 3, 'LEN2': (self.value >> 26) & 3,
            'RW3': (self.value >> 28) & 3, 'LEN3': (self.value >> 30) & 3,
        }
    def rw_to_type(self, rw: int) -> BreakpointType:
        return {0: BreakpointType.EXECUTION, 1: BreakpointType.WRITE,
                2: BreakpointType.IO, 3: BreakpointType.READ_WRITE}.get(rw, BreakpointType.UNKNOWN)
    def len_to_bytes(self, le: int) -> int:
        return {0: 1, 1: 2, 2: 8, 3: 4}.get(le, 1)

class BreakpointFinding:
    __slots__ = ('finding_id', 'detection_method', 'severity', 'title', 'description', 'instruction_address', 'dr_register', 'evidence', 'remediation',)

    def __init__(self, finding_id, detection_method, severity, title, description, instruction_address=0, dr_register=None, evidence="", remediation=""):
        self.finding_id = finding_id
        self.detection_method = detection_method
        self.severity = severity
        self.title = title
        self.description = description
        self.instruction_address = instruction_address
        self.dr_register = dr_register
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'detection_method': self.detection_method.value,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'instruction_address': hex(self.instruction_address),
            'dr_register': self.dr_register,
            'evidence': self.evidence[:200],
            'remediation': self.remediation
        }

class DebugRegisterMonitor:
    """Monitors debug register reads and writes to detect hardware breakpoint instrumentation."""

    def __init__(self):
        self._dr_regs: dict[str, DrRegister] = {}
        for i in range(4):
            self._dr_regs[f"DR{i}"] = DrRegister(name=f"DR{i}")
        self._dr_regs["DR6"] = DrRegister(name="DR6")
        self._dr_regs["DR7"] = DrRegister(name="DR7")

    def detect_dr_access(self, instructions: list[Tuple[int, str]]) -> List[Dict[str, Any]]:
        # Scan instruction stream for MOV-to/from debug register patterns.
        accesses = []
        dr_pattern = re.compile(r'mov\s+(?:dr\d+|DR\d+)\s*,\s*(?:\w+)')
        dr_write_pattern = re.compile(r'mov\s+(?:\w+)\s*,\s*(?:dr\d+|DR\d+)')

        for addr, instr in instructions:
            if dr_pattern.search(instr):
                # Resolve source DR register from the read-direction MOV mnemonic.
                m = re.search(r'(dr\d+|DR\d+)', instr, re.I)
                reg = m.group(1).upper() if m else "DR?"
                accesses.append({
                    'address': addr, 'register': reg,
                    'type': 'read', 'instruction': instr.strip(),
                    'suspicion': 'debugger_detection_attempt'
                })
            elif dr_write_pattern.search(instr):
                # Resolve destination DR register from the write-direction MOV mnemonic.
                m = re.search(r'(dr\d+|DR\d+)', instr, re.I)
                reg = m.group(1).upper() if m else "DR?"
                accesses.append({
                    'address': addr, 'register': reg,
                    'type': 'write', 'instruction': instr.strip(),
                    'suspicion': 'hw_breakpoint_hook'
                })
        return accesses

    def check_dr7_integrity(self, instructions: list[Tuple[int, str]]) -> Dict[str, Any]:
        # Audit instruction stream for DR7 zeroing via XOR, which disables all breakpoint enable flags at once.
        findings = []
        for addr, instr in instructions:
            if 'xor' in instr.lower() and 'dr' in instr.lower():
                findings.append({
                    'address': addr, 'instruction': instr.strip(),
                    'issue': 'dr_zeroing', 'description': 'XOR-based DR7 zeroing disables all hardware breakpoint local and global enable flags simultaneously.'
                })
        return {
            'total_instructions': len(instructions),
            'dr_integrity_violations': len(findings),
            'violations': findings
        }

class Int3PatternDetector:
    # Identify INT3 (0xCC) software breakpoints embedded within the instruction stream.
    def detect_int3_patterns(self, instructions: list[Tuple[int, str]]) -> Dict[str, Any]:

        # Locate all INT3 mnemonics and 0xCC byte literal patterns.
        findings = []
        for addr, instr in instructions:
            if instr.strip().startswith('int3') or instr.strip().startswith('int 3'):
                findings.append({
                    'address': addr, 'type': 'int3',
                    'description': 'INT3 mnemonic indicates a software breakpoint trap embedded in the instruction stream.'
                })
            if '0xcc' in instr.lower():
                findings.append({
                    'address': addr, 'type': 'int3_byte',
                    'description': 'Literal 0xCC byte confirms an embedded INT3 breakpoint instruction.'
                })

        # Compute INT3 instruction density relative to total instruction count.
        int3_count = len(findings)
        total = max(1, len(instructions))
        density = int3_count / total

        return {
            'int3_count': int3_count,
            'density': round(density, 4),
            'is_suspicious': density > 0.05,
            'details': findings[:20]
        }
    def detect_int3_patterns_in_hex(self, hex_bytes: str) -> Dict[str, Any]:
        # Detect 0xCC byte sequences in raw hex to identify systematic anti-debug patching.
        cc_positions = [i // 2 for i in range(0, len(hex_bytes) - 1, 2)
                       if hex_bytes[i:i+2].lower() == 'cc']
        return {
            'total_int3': len(cc_positions),
            'positions': cc_positions[:50],
            'is_anti_debug_patch': len(cc_positions) > 3
        }

class ExceptionHandlerDetector:
    # Exception handler chain analysis exposes anti-hardware-breakpoint techniques through SEH/VEH inspection.

    def detect_seh_chain_tampering(self, instructions: list[Tuple[int, str]]) -> List[Dict[str, Any]]:
        """Detect Structured Exception Handler chain manipulation via FS:[0] access patterns on Windows."""








        findings = []
        for addr, instr in instructions:
            if 'fs:[0]' in instr.lower() or 'fs:[0x00]' in instr.lower():
                findings.append({
                    'address': addr, 'instruction': instr.strip(),
                    'type': 'seh_access',
                    'description': 'Direct FS:[0] segment access signals SEH chain manipulation for breakpoint interception.'
                })
        return findings

    def detect_veh_registration(self, instructions: list[Tuple[int, str]]) -> List[Dict[str, Any]]:
        # Flag AddVectoredExceptionHandler calls as structured exception interception mechanisms.
        findings = []
        for addr, instr in instructions:
            if 'AddVectoredExceptionHandler' in instr:
                findings.append({
                    'address': addr, 'instruction': instr.strip(),
                    'type': 'veh_registration',
                    'description': 'AddVectoredExceptionHandler registration enables first-chance exception interception capable of subverting hardware breakpoints.'
                })
        return findings

class HardwareBreakpointDetector:
    # Multi-vector hardware breakpoint detection orchestrator. Aggregates DR access enumeration, INT3 density analysis, and exception handler chain inspection into unified findings.

    def __init__(self):
        self.dr_monitor = DebugRegisterMonitor()
        self.int3_detector = Int3PatternDetector()
        self.eh_detector = ExceptionHandlerDetector()
        self._findings: list[BreakpointFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"HWB-{self._counter:04d}"

    def analyze(self, instructions: typing.Optional[List[Tuple[int, str]]] = None,
                hex_bytes: str = "",
                check_arm_hwbp: bool = False,
                **kwargs) -> Dict[str, Any]:
        # Execute comprehensive multi-vector hardware breakpoint detection pipeline.
        if instructions is None:
            instructions = []

        findings: list[BreakpointFinding] = []

        # Phase 1: Enumerate debug register access operations.
        dr_accesses = self.dr_monitor.detect_dr_access(instructions)
        for acc in dr_accesses:
            findings.append(BreakpointFinding(
                finding_id=self._next_id(),
                detection_method=DetectionMethod.DR_REGISTER_ACCESS,
                severity="high" if acc['type'] == 'write' else "medium",
                title=f"DR register {acc['type']} access: {acc['register']}",
                description=f"Instruction '{acc['instruction']}' performs {acc['register']} "
                           f"{'write indicating active hardware breakpoint manipulation' if acc['type'] == 'write' else 'read consistent with debugger presence detection'}.",
                instruction_address=acc['address'],
                dr_register=acc['register'],
                evidence=acc['instruction'],
                remediation="Obfuscate DR register access to defeat raw instruction-matching detectors. Route reads through shadow copies and suppress direct DR writes."
            ))

        # Phase 2: Validate DR7 control register integrity against zeroing attacks.
        dr7_check = self.dr_monitor.check_dr7_integrity(instructions)
        for v in dr7_check.get('violations', []):
            findings.append(BreakpointFinding(
                finding_id=self._next_id(),
                detection_method=DetectionMethod.DR_REGISTER_ACCESS,
                severity="high",
                title="DR7 control register integrity violation",
                description=v['description'],
                instruction_address=v['address'],
                evidence=v['instruction'],
                remediation="Eliminate direct XOR operations on DR7. Replace with conditional bitwise masking that preserves legitimate breakpoint state."
            ))

        # Phase 3: Compute INT3 instruction density and flag suspicious concentrations.
        int3_result = self.int3_detector.detect_int3_patterns(instructions)
        if int3_result['is_suspicious']:
            findings.append(BreakpointFinding(
                finding_id=self._next_id(),
                detection_method=DetectionMethod.INT3_PATTERN,
                severity="medium",
                title=f"Elevated INT3 instruction density (ratio={int3_result['density']})",
                description=f"Detected {int3_result['int3_count']} INT3 instructions. "
                           f"High density correlates with anti-debug software breakpoint patching strategies.",
                evidence=f"INT3 count: {int3_result['int3_count']}",
                remediation="Analyze INT3 placement context to differentiate legitimate trap handlers from anti-debug patching before taking corrective action."
            ))

        # Phase 4: Inspect raw hex for 0xCC byte sequences characteristic of anti-debug patches.
        if hex_bytes:
            hex_int3 = self.int3_detector.detect_int3_patterns_in_hex(hex_bytes)
            if hex_int3['is_anti_debug_patch']:
                findings.append(BreakpointFinding(
                    finding_id=self._next_id(),
                    detection_method=DetectionMethod.INT3_PATTERN,
                    severity="high",
                    title=f"Hex-level INT3 (0xCC) byte sequence detected: {hex_int3['total_int3']} occurrences",
                    description="High concentration of 0xCC bytes in raw hex indicates systematic anti-debug patching rather than legitimate software breakpoints.",
                    evidence=f"INT3 positions: {hex_int3['positions'][:10]}",
                    remediation="Isolate patched regions for deeper semantic analysis. NOP-sled detection serves as a complementary anti-debug indicator."
                ))

        # Phase 5: Audit exception handler chains for breakpoint interception mechanisms.
        seh_findings = self.eh_detector.detect_seh_chain_tampering(instructions)
        for sf in seh_findings:
            findings.append(BreakpointFinding(
                finding_id=self._next_id(),
                detection_method=DetectionMethod.EXCEPTION_HANDLER_HOOK,
                severity="high",
                title="SEH chain tampering detected",
                description=sf['description'],
                instruction_address=sf['address'],
                evidence=sf['instruction'],
                remediation="Validate SEH chain integrity at runtime to detect unauthorized handler insertion before exception dispatch occurs."
            ))

        veh_findings = self.eh_detector.detect_veh_registration(instructions)
        for vf in veh_findings:
            findings.append(BreakpointFinding(
                finding_id=self._next_id(),
                detection_method=DetectionMethod.EXCEPTION_HANDLER_HOOK,
                severity="medium",
                title="Vectored Exception Handler registration detected",
                description=vf['description'],
                instruction_address=vf['address'],
                evidence=vf['instruction'],
                remediation="Audit registered VEH handlers for breakpoint-masking behavior. Diff handler lists against known-good baselines."
            ))

        self._findings.extend(findings)

        return {
            'success': True,
            'total_instructions': len(instructions),
            'total_findings': len(findings),
            'findings': [f.to_dict() for f in findings],
            'stats': {
                'dr_accesses': len(dr_accesses),
                'int3_count': int3_result['int3_count'],
                'seh_accesses': len(seh_findings),
                'veh_registrations': len(veh_findings),
            }
        }

def detect_hardware_breakpoints(
    instructions: typing.Optional[List[Tuple[int, str]]] = None,
    hex_bytes: str = "", **kwargs
) -> Dict[str, Any]:
    # Convenience wrapper for single-call hardware breakpoint detection pipeline.
    detector = HardwareBreakpointDetector()
    return detector.analyze(instructions=instructions, hex_bytes=hex_bytes)

__all__ = ["HardwareBreakpointDetector", "DebugRegisterMonitor", "Int3PatternDetector",
           "ExceptionHandlerDetector", "BreakpointFinding", "BreakpointType",
           "DetectionMethod", "DrRegister", "detect_hardware_breakpoints"]
