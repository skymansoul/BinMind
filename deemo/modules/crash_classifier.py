import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CrashType(Enum):
    WRITE_AFTER_FREE = "write_after_free"
    READ_AFTER_FREE = "read_after_free"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER_DEREF = "null_pointer_deref"
    DOUBLE_FREE = "double_free"
    STACK_OVERFLOW = "stack_overflow"
    HEAP_CORRUPTION = "heap_corruption"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    UNKNOWN = "unknown"


class ExploitPrimitive(Enum):
    ARBITRARY_WRITE = "arbitrary_write"
    ARBITRARY_READ = "arbitrary_read"
    CODE_EXECUTION = "code_execution"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_LEAK = "information_leak"


@dataclass
class CrashAnalysisResult:
    crash_type: CrashType
    primitives: List[ExploitPrimitive]
    severity: str
    confidence: float
    exploitability_score: int
    recommended_template: Optional[str] = None
    analysis_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'crash_type': self.crash_type.value,
            'primitives': [p.value for p in self.primitives],
            'severity': self.severity,
            'confidence': self.confidence,
            'exploitability_score': self.exploitability_score,
            'recommended_template': self.recommended_template,
            'analysis_details': self.analysis_details
        }


@dataclass
class ExploitPrototype:
    template_name: str
    code: str
    placeholders: Dict[str, str] = field(default_factory=dict)
    requirements: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_name': self.template_name,
            'code': self.code,
            'placeholders': self.placeholders,
            'requirements': self.requirements
        }


class CrashClassifier:
    
    def __init__(self):
        self.crash_patterns = {
            CrashType.WRITE_AFTER_FREE: [
                r'write to freed memory',
                r'write after free',
                r'heap-use-after-free.*write',
                r'UAF.*write'
            ],
            CrashType.READ_AFTER_FREE: [
                r'read from freed memory',
                r'read after free',
                r'heap-use-after-free.*read',
                r'UAF.*read'
            ],
            CrashType.USE_AFTER_FREE: [
                r'use-after-free',
                r'UAF',
                r'heap-use-after-free'
            ],
            CrashType.BUFFER_OVERFLOW: [
                r'buffer overflow',
                r'heap buffer overflow',
                r'stack buffer overflow',
                r'out-of-bounds write',
                r'out of bounds write'
            ],
            CrashType.NULL_POINTER_DEREF: [
                r'null pointer dereference',
                r'nullptr deref',
                r'dereference of null pointer'
            ],
            CrashType.DOUBLE_FREE: [
                r'double free',
                r'free of already freed pointer'
            ],
            CrashType.STACK_OVERFLOW: [
                r'stack overflow',
                r'stack smashing',
                r'canary check failed'
            ],
            CrashType.HEAP_CORRUPTION: [
                r'heap corruption',
                r'corrupted chunk',
                r'invalid chunk size'
            ],
            CrashType.INTEGER_OVERFLOW: [
                r'integer overflow',
                r'int overflow',
                r'unsigned integer overflow'
            ],
            CrashType.FORMAT_STRING: [
                r'format string',
                r'printf format',
                r'%s.*write'
            ]
        }
        
        self.type_to_primitives = {
            CrashType.WRITE_AFTER_FREE: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.CODE_EXECUTION],
            CrashType.READ_AFTER_FREE: [ExploitPrimitive.ARBITRARY_READ, ExploitPrimitive.INFORMATION_LEAK],
            CrashType.USE_AFTER_FREE: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.CODE_EXECUTION],
            CrashType.BUFFER_OVERFLOW: [ExploitPrimitive.CONTROL_FLOW_HIJACK, ExploitPrimitive.CODE_EXECUTION],
            CrashType.NULL_POINTER_DEREF: [ExploitPrimitive.INFORMATION_LEAK],
            CrashType.DOUBLE_FREE: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.CODE_EXECUTION],
            CrashType.STACK_OVERFLOW: [ExploitPrimitive.CONTROL_FLOW_HIJACK, ExploitPrimitive.CODE_EXECUTION],
            CrashType.HEAP_CORRUPTION: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.CODE_EXECUTION],
            CrashType.INTEGER_OVERFLOW: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.INFORMATION_LEAK],
            CrashType.FORMAT_STRING: [ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.INFORMATION_LEAK]
        }
        
        self.template_mapping = {
            CrashType.WRITE_AFTER_FREE: 'fastbin_attack',
            CrashType.USE_AFTER_FREE: 'fastbin_attack',
            CrashType.DOUBLE_FREE: 'double_free_attack',
            CrashType.BUFFER_OVERFLOW: 'rop_chain',
            CrashType.STACK_OVERFLOW: 'stack_smash',
            CrashType.FORMAT_STRING: 'format_string_write',
            CrashType.HEAP_CORRUPTION: 'tcache_poisoning'
        }
    
    def classify_crash(self, crash_data: Dict[str, Any]) -> CrashAnalysisResult:
        crash_type = self._detect_crash_type(crash_data)
        primitives = self.type_to_primitives.get(crash_type, [])
        severity = self._determine_severity(crash_type, primitives)
        confidence = self._calculate_confidence(crash_data)
        exploitability = self._calculate_exploitability(crash_type, primitives)
        template = self.template_mapping.get(crash_type)
        
        return CrashAnalysisResult(
            crash_type=crash_type,
            primitives=primitives,
            severity=severity,
            confidence=confidence,
            exploitability_score=exploitability,
            recommended_template=template,
            analysis_details=self._extract_details(crash_data)
        )
    
    def _detect_crash_type(self, crash_data: Dict[str, Any]) -> CrashType:
        crash_info = crash_data.get('crash_info', '')
        stack_trace = crash_data.get('stack_trace', '')
        error_message = crash_data.get('error_message', '')
        
        all_text = f"{crash_info} {stack_trace} {error_message}".lower()
        
        for crash_type, patterns in self.crash_patterns.items():
            for pattern in patterns:
                if pattern.lower() in all_text:
                    logger.debug(f"匹配到崩溃类型: {crash_type.value}")
                    return crash_type
        
        return CrashType.UNKNOWN
    
    def _determine_severity(self, crash_type: CrashType, primitives: List[ExploitPrimitive]) -> str:
        if ExploitPrimitive.CODE_EXECUTION in primitives:
            return 'critical'
        if ExploitPrimitive.CONTROL_FLOW_HIJACK in primitives:
            return 'critical'
        if ExploitPrimitive.PRIVILEGE_ESCALATION in primitives:
            return 'critical'
        if ExploitPrimitive.ARBITRARY_WRITE in primitives:
            return 'high'
        if ExploitPrimitive.ARBITRARY_READ in primitives:
            return 'high'
        if ExploitPrimitive.INFORMATION_LEAK in primitives:
            return 'medium'
        
        return 'low'
    
    def _calculate_confidence(self, crash_data: Dict[str, Any]) -> float:
        confidence = 0.5
        
        if crash_data.get('crash_info'):
            confidence += 0.2
        
        if crash_data.get('stack_trace'):
            confidence += 0.2
        
        if crash_data.get('registers'):
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _calculate_exploitability(self, crash_type: CrashType, primitives: List[ExploitPrimitive]) -> int:
        score = 0
        
        base_scores = {
            CrashType.WRITE_AFTER_FREE: 85,
            CrashType.USE_AFTER_FREE: 80,
            CrashType.DOUBLE_FREE: 85,
            CrashType.BUFFER_OVERFLOW: 90,
            CrashType.STACK_OVERFLOW: 95,
            CrashType.HEAP_CORRUPTION: 75,
            CrashType.FORMAT_STRING: 70,
            CrashType.INTEGER_OVERFLOW: 60,
            CrashType.NULL_POINTER_DEREF: 30,
            CrashType.READ_AFTER_FREE: 50,
            CrashType.UNKNOWN: 20
        }
        
        score += base_scores.get(crash_type, 20)
        
        if ExploitPrimitive.CODE_EXECUTION in primitives:
            score += 10
        if ExploitPrimitive.ARBITRARY_WRITE in primitives:
            score += 5
        
        return min(100, score)
    
    def _extract_details(self, crash_data: Dict[str, Any]) -> Dict[str, Any]:
        details = {}
        
        if crash_data.get('registers'):
            details['registers'] = crash_data['registers']
        
        if crash_data.get('crash_address'):
            details['crash_address'] = hex(crash_data['crash_address'])
        
        if crash_data.get('instruction'):
            details['instruction'] = crash_data['instruction']
        
        if crash_data.get('stack_trace'):
            details['stack_frames'] = len(crash_data['stack_trace'].split('\n'))
        
        return details
    
    def generate_exploit_prototype(self, analysis: CrashAnalysisResult) -> Optional[ExploitPrototype]:
        if not analysis.recommended_template:
            return None
        
        template_code = self._get_template_code(analysis.recommended_template)
        
        placeholders = {}
        if analysis.analysis_details.get('crash_address'):
            placeholders['CRASH_ADDRESS'] = analysis.analysis_details['crash_address']
        
        if analysis.analysis_details.get('registers'):
            registers = analysis.analysis_details['registers']
            if 'rip' in registers:
                placeholders['RIP'] = registers['rip']
            if 'rsp' in registers:
                placeholders['RSP'] = registers['rsp']
        
        return ExploitPrototype(
            template_name=analysis.recommended_template,
            code=template_code,
            placeholders=placeholders,
            requirements=self._get_template_requirements(analysis.recommended_template)
        )
    
    def _get_template_code(self, template_name: str) -> str:
        templates = {
            'fastbin_attack': '''# Fastbin Attack Exploit Template
def exploit_fastbin_attack(target):
    # Allocate chunks
    chunk1 = malloc(0x68)
    chunk2 = malloc(0x68)
    
    # Free chunk1 (puts into fastbin)
    free(chunk1)
    
    # Overwrite chunk1's fd pointer via UAF
    # [TODO: Use vulnerability to write to freed chunk]
    uaf_write(chunk1, target_address)
    
    # Reallocate - will return target_address
    chunk3 = malloc(0x68)
    chunk4 = malloc(0x68)  # This should be target_address
    
    # Now chunk4 points to target, we can write arbitrary data
    write(chunk4, payload)
''',
            'double_free_attack': '''# Double Free Attack Exploit Template
def exploit_double_free(target):
    # Allocate chunks
    chunk1 = malloc(0x80)
    
    # Double free (vulnerability)
    free(chunk1)
    free(chunk1)  # Second free - bug
    
    # Allocate to get chunk1 back with controlled fd
    chunk2 = malloc(0x80)  # Gets chunk1
    chunk3 = malloc(0x80)  # Gets chunk1 again with fake fd
    
    # Now we can control allocation targets
    write(chunk3, target_address)
    
    # Next allocation will be at target
    chunk4 = malloc(0x80)  # Allocated at target_address
''',
            'rop_chain': '''# ROP Chain Exploit Template
def exploit_rop(buffer):
    # Build ROP chain
    rop = b''
    
    # [TODO: Fill with ROP gadgets]
    rop += p64(pop_rdi_ret)
    rop += p64(bin_sh_addr)
    rop += p64(system_addr)
    
    # Payload: padding + ROP chain
    payload = b'A' * padding_length
    payload += rop
    
    # Send payload
    send_payload(buffer, payload)
''',
            'stack_smash': '''# Stack Overflow Exploit Template
def exploit_stack_overflow(buffer):
    # Calculate offsets
    padding = 104  # [TODO: Calculate actual offset]
    
    # Build payload
    payload = b'A' * padding
    
    # If ASLR is bypassed, use direct address
    payload += p64(shellcode_address)
    
    # If using shellcode
    # payload += shellcode
    
    # Send payload
    send_payload(buffer, payload)
''',
            'format_string_write': '''# Format String Write Exploit Template
def exploit_format_string(target_addr, value):
    # Calculate offset to target
    offset = 6  # [TODO: Find actual offset]
    
    # Build format string payload
    payload = f'%{value}x%{offset}$n'
    
    # Prepend target address
    payload = p64(target_addr) + payload.encode()
    
    # Send payload
    send_payload(payload)
''',
            'tcache_poisoning': '''# TCache Poisoning Exploit Template
def exploit_tcache_poisoning(target):
    # Allocate chunks
    for i in range(7):
        chunks[i] = malloc(0x20)
    
    # Free chunks to fill tcache
    for i in range(7):
        free(chunks[i])
    
    # Poison tcache via vulnerability
    # Write fake chunk metadata
    poison_tcache(chunks[0], target)
    
    # Allocate to get target
    result = malloc(0x20)  # Should be at target
'''
        }
        
        return templates.get(template_name, '# No template available')
    
    def _get_template_requirements(self, template_name: str) -> List[str]:
        requirements = {
            'fastbin_attack': ['UAF vulnerability', 'libc leak', 'heap spray'],
            'double_free_attack': ['Double free vulnerability', 'libc leak'],
            'rop_chain': ['Buffer overflow', 'ROP gadgets', 'libc leak'],
            'stack_smash': ['Stack overflow', 'No PIE or PIE bypass'],
            'format_string_write': ['Format string vulnerability', 'Write access'],
            'tcache_poisoning': ['Heap corruption', 'tcache manipulation']
        }
        
        return requirements.get(template_name, [])


def analyze_crash(crash_data: Dict[str, Any]) -> CrashAnalysisResult:
    classifier = CrashClassifier()
    return classifier.classify_crash(crash_data)


def generate_exploit_from_crash(crash_data: Dict[str, Any]) -> Optional[ExploitPrototype]:
    classifier = CrashClassifier()
    analysis = classifier.classify_crash(crash_data)
    return classifier.generate_exploit_prototype(analysis)'