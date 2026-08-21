name: str = ""
import logging, os, re, subprocess
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SyscallPattern:
    name: str
    sequence: str
    severity: str = ""
    description: str = ""
    mitre_id: str = ""

class SyscallPatternMatcher:
    kDANGEROUS_PATTERNS = [
        SyscallPattern("priv_escalation", ["dup2","execve"], "CRITICAL",
                        "Privilege escalation: dup2 redirect fd then exec shell", "T1068"),
        SyscallPattern("reverse_shell", ["socket","connect","dup2","execve"], "CRITICAL",
                        "Reverse shell: socket->connect->dup2->exec", "T1071"),
        SyscallPattern("file_read_exec", ["open","read","mmap","mprotect"], "HIGH",
                        "File read-execute: open->read->mmap->mprotect", "T1105"),
        SyscallPattern("process_injection", ["ptrace","mmap","write"], "CRITICAL",
                        "Process injection: ptrace->mmap->write shellcode", "T1055"),
        SyscallPattern("dll_hijack", ["open","dlopen","dlsym"], "MEDIUM",
                        "DLL hijack: open malicious lib->load->resolve", "T1574"),
        SyscallPattern("keylogger", ["open","read","write","ioctl"], "MEDIUM",
                        "Keylogger: open /dev/input->read->process->forward", "T1056"),
    ]

    def __init__(self, binary_path: str): self.binary_path = os.path.abspath(binary_path)

    def extract_syscalls(self) -> Set[str]:
        syscalls = set()
        try:
            r = subprocess.run(['r2','-q','-c','aaaa; pD $SS @ $S; q',self.binary_path],
                capture_output=True, text=True, timeout=120, encoding='utf-8', errors='replace')
            for pattern in ['syscall','int 0x80','svc #0','sc #0']:
                if pattern in r.stdout.lower(): syscalls.add('syscall_instruction')
            r2 = subprocess.run(['r2','-q','-c','iij; q',self.binary_path],
                capture_output=True, text=True, timeout=60, encoding='utf-8', errors='replace')
            import json as _json
            imports = _json.loads(r2.stdout) if r2.stdout.strip() else []
            for imp in imports:
                name = imp.get('name',''); lib = imp.get('lib','')
                if 'libc' in lib.lower() or not lib: syscalls.add(name)
        except Exception:
            logger.debug("Syscall extraction failure. Empty set returned.")
            pass
        return syscalls

    def match_patterns(self) -> List[Dict]:
        syscalls = self.extract_syscalls()
        matches = []
        for pat in self.kDANGEROUS_PATTERNS:
            matched = [s for s in pat.sequence if s in syscalls or s.replace('_','') in str(syscalls).lower()]
            coverage = len(matched) / len(pat.sequence) if pat.sequence else 0
            coverage = min(max(coverage, 0.0), 1.0)
            if coverage >= 0.5:
                matches.append({'pattern': pat.name, 'matched_syscalls': matched,
                                'coverage': round(coverage,2), 'severity': pat.severity,
                                'description': pat.description, 'mitre_id': pat.mitre_id})
        return sorted(matches, key=lambda m: m['coverage'], reverse=True)


def match_syscall_patterns(binary_path: str) -> Dict[str,Any]:
    matcher = SyscallPatternMatcher(binary_path)
    return {'success': True, 'matches': matcher.match_patterns()}
