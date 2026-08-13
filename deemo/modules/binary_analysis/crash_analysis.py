# Bridge: core.crash_analysis with test-compatible API
from core.crash_analysis import *
import re as _re
from typing import Dict, Any
from typing import List, Optional

REGISTER_PATTERNS = {
    'equals': _re.compile(r'(\w{2,6})\s*=\s*(0x[0-9a-fA-F]+)'),
    'colon': _re.compile(r'(\w{2,6})\s*:\s*(0x[0-9a-fA-F]+)'),
    'space': _re.compile(r'(\w{2,6})\s+(0x[0-9a-fA-F]+)'),
}

REGISTER_NAMES = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip',
}


def parse_registers_from_text(text):
    """Parse register values from crash dump text."""
    result = {}
    if not isinstance(text, str):
        return result
    for name, pattern in REGISTER_PATTERNS.items():
        for match in pattern.finditer(text):
            reg = match.group(1).lower()
            val = match.group(2)
            if reg in REGISTER_NAMES:
                result[reg] = val
    return result


class CrashAnalyzer:
    """Crash analysis wrapper class."""
    def __init__(self, crash_data=None):
        self.crash_data = crash_data or {}

    def analyze(self, crash_data=None):
        data = crash_data or self.crash_data
        return analyze_crash_for_exploit(data)

    def parse_crash_info(self, data):
        regs = parse_registers_from_text(str(data.get('registers', '')))
        return {
            'registers': regs,
            'program_output': data.get('output', ''),
        }

    def heuristic_analysis(self, data):
        text = str(data)
        exploitability = 'none'
        vuln_type = 'unknown'
        if 'canary' in text.lower() or '__stack_chk' in text:
            exploitability = 'medium'
            vuln_type = 'stack_canary'
        if 'free()' in text or 'double free' in text.lower():
            exploitability = 'high'
            vuln_type = 'double_free'
        if '%n' in text or '%x' in text or '%s' in text:
            exploitability = 'high'
            vuln_type = 'format_string'
        if 'rip' in text.lower() or 'eip' in text.lower() or 'segfault' in text.lower():
            exploitability = 'medium'
        return {'exploitability': exploitability, 'vulnerability_type': vuln_type}
