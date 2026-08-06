# UAF detection -- simple and robust
from __future__ import annotations
from typing import List
import re

def detect_uaf_with_aliases(code, func=''):
    findings = []
    free_pat = re.compile(r'free\s*\(\s*(\w+)\s*\)')
    for fm in free_pat.finditer(code):
        fv = fm.group(1)
        pos_after_free = fm.end()
        remainder = code[pos_after_free:]
        # Simple check: does fv appear anywhere in remainder?
        idx = remainder.find(fv)
        while idx >= 0:
            # Make sure it is a full word match (not substring of longer name)
            before_ok = (idx == 0 or not remainder[idx-1].isalnum() and remainder[idx-1] != '_')
            after_idx = idx + len(fv)
            after_ok = (after_idx >= len(remainder) or not remainder[after_idx].isalnum() and remainder[after_idx] != '_')
            if before_ok and after_ok:
                # Check this is not inside another free() call
                ctx_before = remainder[max(0,idx-8):idx]
                if 'free(' not in ctx_before and 'free (' not in ctx_before:
                    findings.append({
                        'type': 'use-after-free',
                        'function': func,
                        'variable': fv,
                        'severity': 'Critical',
                        'cwe': 'CWE-416',
                        'confidence': 0.85,
                        'description': 'UAF: %s used after free()' % fv,
                    })
                    break
            idx = remainder.find(fv, idx + 1)
    return findings
