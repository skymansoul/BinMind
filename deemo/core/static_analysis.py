"""
Static binary analysis: dangerous function detection, string scanning,
import table review. No external disassembler required — works from
raw bytes and radare2 output.
"""

import logging
import re
import subprocess
from typing import Dict, List

from config import R2_PATH, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

# Functions that commonly indicate a vulnerability surface
DANGEROUS_FUNCTIONS = {
    # memory corruption
    'gets':     ('buffer-overflow', 'Critical', 'CWE-242'),
    'strcpy':   ('buffer-overflow', 'High', 'CWE-120'),
    'strcat':   ('buffer-overflow', 'High', 'CWE-120'),
    'sprintf':  ('buffer-overflow', 'High', 'CWE-120'),
    'vsprintf': ('buffer-overflow', 'High', 'CWE-120'),
    'scanf':    ('buffer-overflow', 'Medium', 'CWE-120'),
    'memcpy':   ('buffer-overflow', 'Medium', 'CWE-119'),
    'read':     ('buffer-overflow', 'Medium', 'CWE-119'),
    # format string
    'printf':   ('format-string', 'Medium', 'CWE-134'),
    'fprintf':  ('format-string', 'Medium', 'CWE-134'),
    # integer issues
    'malloc':   ('integer-overflow', 'Low', 'CWE-190'),
    'calloc':   ('integer-overflow', 'Low', 'CWE-190'),
    # command injection
    'system':   ('command-injection', 'Critical', 'CWE-78'),
    'popen':    ('command-injection', 'Critical', 'CWE-78'),
    'execve':   ('command-injection', 'Critical', 'CWE-78'),
    # race conditions
    'fork':     ('race-condition', 'Low', 'CWE-362'),
    # privilege
    'setuid':   ('privilege-escalation', 'High', 'CWE-250'),
    'setgid':   ('privilege-escalation', 'High', 'CWE-250'),
}


def scan_imports(binary_path: str) -> List[Dict]:
    """Scan a binary's import table for dangerous functions via r2."""
    raw = _radare2_cmd(binary_path, ['iE'], timeout=60)
    found = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        for func, (vuln_type, severity, cwe) in DANGEROUS_FUNCTIONS.items():
            if func == line or line.endswith(f'.{func}'):
                found.append({
                    'function': line,
                    'vuln_type': vuln_type,
                    'severity': severity,
                    'cwe': cwe,
                    'description': f'Imports {func} — potential {vuln_type}',
                })
    return found


def scan_strings(binary_path: str) -> List[str]:
    """Extract printable strings from binary. Looks for suspicious patterns."""
    raw = _radare2_cmd(binary_path, ['izz'], timeout=60)
    strings = []
    for line in raw.splitlines():
        # izz output: addr length encoding string
        parts = line.split(None, 3)
        if len(parts) >= 4:
            s = parts[3]
            # filter non-printable
            if s.isprintable() and len(s) >= 4:
                strings.append(s)
    return strings


def find_suspicious_strings(strings: List[str]) -> List[Dict]:
    """Flag strings that look like they might be interesting."""
    patterns = {
        'hardcoded-password': r'(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]',
        'shell-command': r'(?i)(/bin/(ba)?sh|cmd\.exe|/bin/bash)',
        'url': r'https?://[^\s]+',
        'file-path': r'(?i)(/etc/(passwd|shadow)|C:\\Windows\\)',
        'stack-canary': r'(?i)(__stack_chk|stack.*canary)',
    }

    findings = []
    for s in strings:
        for category, pat in patterns.items():
            if re.search(pat, s):
                findings.append({'string': s[:120], 'category': category})
    return findings


def _radare2_cmd(path: str, cmds: List[str], timeout: int = 300) -> str:
    cmd = [R2_PATH, '-q', '-e', 'io.color=false']
    for c in cmds:
        cmd.extend(['-c', c])
    cmd.append(path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except FileNotFoundError:
        return ''
    except subprocess.TimeoutExpired:
        return ''
