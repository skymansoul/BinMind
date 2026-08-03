#!/usr/bin/env python3
import logging, re, subprocess, json as _json
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SyscallPattern:
    name: str = ""; sequence: List[str] = field(default_factory=list)
    severity: str = ""; description: str = ""; mitre_id: str = ""

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
                       "DLL hijack: open->load->resolve", "T1574"),
        SyscallPattern("keylogger", ["open","read","write","ioctl"], "MEDIUM",
                       "Keylogger: open /dev/input->read->process->forward", "T1056"),
        SyscallPattern("memfd_execute", ["memfd_create","write","execve"], "HIGH",
                       "Fileless execution via memfd: write payload then exec", "T1620"),
        # 新增: 容器逃逸模式
        SyscallPattern("container_escape", ["unshare","mount","chroot","execve"], "CRITICAL",
                       "Container escape: unshare namespace->mount host fs->chroot->exec", "T1611"),
        SyscallPattern("ebpf_load", ["bpf","map_create","map_update_elem"], "MEDIUM",
                       "eBPF program load: potential kernel code injection", "T1068"),
    ]

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)

    def extract_syscalls(self) -> Set[str]:
        syscalls = set()
        try:
            r = subprocess.run(
                ['r2','-q','-c','aaaa; /R syscall; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace')
            for pattern in ['syscall','int 0x80','svc #0','sc #0']:
                if pattern in r.stdout.lower(): syscalls.add('syscall_instruction')
            r2 = subprocess.run(
                ['r2','-q','-c','iij; q', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace')
            imports = _json.loads(r2.stdout) if r2.stdout.strip() else []
            for imp in imports:
                name = imp.get('name',''); lib = imp.get('lib','')
                if 'libc' in lib.lower() or not lib: syscalls.add(name)
        except Exception:
            logger.debug("Syscall extraction failure. Empty set returned.")
        return syscalls

    def match_patterns(self) -> List[Dict]:
        syscalls = self.extract_syscalls()
        syscalls_lower = str([s.lower() for s in syscalls])
        matches = []
        for pat in self.kDANGEROUS_PATTERNS:
            matched = [s for s in pat.sequence
                      if s.lower() in syscalls_lower or s.replace('_','').lower() in syscalls_lower]
            coverage = len(matched) / len(pat.sequence) if pat.sequence else 0
            coverage = min(max(coverage, 0.0), 1.0)
            if coverage >= 0.5:
                matches.append({'pattern': pat.name, 'matched_syscalls': matched,
                               'coverage': round(coverage,2), 'severity': pat.severity,
                               'description': pat.description, 'mitre_id': pat.mitre_id})
        return sorted(matches, key=lambda m: m['coverage'], reverse=True)

    def calculate_threat_score(self) -> float:
        """计算整体威胁评分——按严重级别加权求和所有匹配的覆盖率
        CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1"""
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        matches = self.match_patterns()
        if not matches: return 0.0
        total = sum(weights.get(m['severity'], 1) * m['coverage'] for m in matches)
        max_possible = sum(weights.get(m['severity'], 1) for m in matches)
        return total / max_possible if max_possible > 0 else 0.0


def match_syscall_patterns(binary_path: str) -> Dict[str, Any]:
    matcher = SyscallPatternMatcher(binary_path)
    matches = matcher.match_patterns()
    return {'success': True, 'matches': matches,
            'threat_score': matcher.calculate_threat_score()}
