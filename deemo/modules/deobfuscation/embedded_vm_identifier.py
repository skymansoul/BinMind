import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class VMInfo:
    vm_type: str = ''
    confidence: float = 0.0
    dispatch_addr: int = 0
    handler_table: int = 0
    num_instructions: int = 0
    binary_section: str = ''

    def __post_init__(self):
        self.vm_type = str(self.vm_type) if self.vm_type else ''
        self.confidence = float(self.confidence) if self.confidence is not None else 0.0
        self.dispatch_addr = int(self.dispatch_addr) if self.dispatch_addr is not None else 0
        self.handler_table = int(self.handler_table) if self.handler_table is not None else 0
        self.num_instructions = int(self.num_instructions) if self.num_instructions is not None else 0
        self.binary_section = str(self.binary_section) if self.binary_section else ''


_VM_PATTERNS = {
    'vmprotect': {
        'sigs':  [b'VMProtect', b'\xE8\x00\x00\x00\x00'],
        'disp':  r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*[\+\-]',
        'base':  0.9,
    },
    'themida': {
        'sigs':  [b'Themida', b'WinLicense', b'Oreans'],
        'disp':  r'mov\s+r\w+,\s*\[r\w+\s*[\+\-]',
        'base':  0.85,
    },
    'code_virtualizer': {
        'sigs':  [b'Code Virtualizer', b'CV\x00'],
        'disp':  r'push\s+r\w+\s*\n\s*mov\s+r\w+,\s*\[r\w+\]',
        'base':  0.8,
    },
    'custom_vm': {
        'sigs':  [],
        'disp':  r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*\*\s*[0-9]',
        'base':  0.4,
    },
}


class EmbeddedVMIdentifier:

    def __init__(self, binpath):
        if binpath is None:
            raise ValueError("binary path required")
        self._path = os.path.abspath(binpath)

    def identify(self):
        found = []
        try:
            with open(self._path, 'rb') as fh:
                raw = fh.read()
        except Exception as e:
            logger.warning(f"VM identify: cannot read {self._path}: {e}")
            return found

        asm = ''
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'pD $SS @ $S; q', self._path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace')
            asm = r.stdout
        except Exception:
            logger.debug("suppressed", exc_info=True)

        for vm_name, vm_info in _VM_PATTERNS.items():
            score = 0.0
            for sig in vm_info['sigs']:
                if sig in raw:
                    score += 0.3
            disp_matches = []
            if asm:
                disp_matches = list(re.finditer(vm_info['disp'], asm, re.IGNORECASE))
            if len(disp_matches) > 5:
                score += 0.5
            final_conf = vm_info['base'] * (1.0 + score)
            if final_conf > 1.0:
                final_conf = 1.0
            if score > 0:
                found.append(VMInfo(
                    vm_type=vm_name, confidence=final_conf,
                    dispatch_addr=disp_matches[0].start() if disp_matches else 0,
                    num_instructions=len(disp_matches) // 2 if disp_matches else 0))

        found.sort(key=lambda x: x.confidence, reverse=True)

        return found


def identify_embedded_vms(binpath):
    eng = EmbeddedVMIdentifier(binpath)
    vms = eng.identify()
    out = []
    for v in vms:
        out.append({
            'type': v.vm_type,
            'confidence': v.confidence,
            'instructions': v.num_instructions,
        })
    return {'success': True, 'vms': out}
