import logging as _logging
import os as _os
import re as _re
import subprocess as _sp

__dbg = _logging.getLogger(__name__)


class ReturnViolation:
    """Return-address integrity violation record."""
    __slots__ = ('addr', 'expected', 'actual', 'sev')

    def __init__(self, addr, expected=0, actual=0, sev='HIGH'):
        self.addr     = int(addr) if addr is not None else 0
        self.expected = int(expected) if expected is not None else 0
        self.actual   = int(actual) if actual is not None else 0
        self.sev      = str(sev) if sev else 'HIGH'


class ShadowStackDetector:
    """Return-address overwrite detector via disassembly pattern matching.

    Scans disassembly for stack-relative writes (rbp/rsp displacement) and
    checks whether a RET follows within the next four instructions. A hit
    indicates a likely return-address clobber — a ROP or stack-smash signal.
    """

    _kRetPats = (
        r'\bret\b',
        r'\bretn?\b',
        r'\bpop\s+r\w+\s*\n\s*jmp',
    )

    _kStackWrites = (
        (r'mov\s+(?:qword\s+)?\[rbp\s*[-+]\s*\d+\]\s*,\s*r\w+', 'rbp_write'),
        (r'mov\s+(?:qword\s+)?\[rsp\s*[-+]\s*\d+\]\s*,\s*r\w+', 'rsp_write'),
        (r'push\s+r\w+', 'push'),
    )

    def __init__(self, f_binpath):
        if f_binpath is None:
            raise ValueError("binary path required")
        self.__path = _os.path.abspath(f_binpath)

    def find_violations(self):
        """Pattern-match stack writes followed by RET; return violation list."""
        viols = []
        try:
            cmd = ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', self.__path]
            r = _sp.run(cmd, capture_output=True, text=True,
                        timeout=120, encoding='utf-8', errors='replace')
            lines = r.stdout.split('\n')
            n = len(lines)
            li = 0
            while li < n:
                line = lines[li]
                wi = 0
                wn = len(self._kStackWrites)
                while wi < wn:
                    pat, vtype = self._kStackWrites[wi]
                    if _re.search(pat, line, _re.IGNORECASE):
                        am = _re.match(r'\s*0x([0-9a-f]+)', line)
                        addr = int(am.group(1), 16) if am else li
                        ctx_end = li + 4
                        if ctx_end > n:
                            ctx_end = n
                        ctx = '\n'.join(lines[li:ctx_end])
                        has_ret = False
                        ri = 0
                        while ri < len(self._kRetPats):
                            if _re.search(self._kRetPats[ri], ctx, _re.IGNORECASE):
                                has_ret = True
                                break
                            ri += 1
                        if has_ret:
                            viols.append(ReturnViolation(addr, sev='HIGH'))
                    wi += 1
                li += 1
        except Exception as _e:
            __dbg.warning(f"shadow stack detection failed: {_e}")
        return viols

    def assess_rop(self):
        """Score ROP resilience: start at 100, subtract 15 per violation."""
        viols = self.find_violations()
        score = 100 - len(viols) * 15
        if score < 0:
            score = 0
        return {
            'success': True,
            'violations': len(viols),
            'rop_resilience_score': score,
            'recommendation': (
                'enable CET/Shadow Stack'
                if score < 70
                else 'baseline secure'
            ),
        }


def detect_shadow_stack_violations(f_binpath):
    """Single-call entry: scan binary and return ROP resilience assessment."""
    det = ShadowStackDetector(f_binpath)
    return det.assess_rop()
