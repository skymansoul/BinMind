import logging as _logging
import os as _os
import re as _re
import subprocess as _sp

__dbg = _logging.getLogger(__name__)


class ReturnViolation:
    # 返回地址完整性违规记录
    __slots__ = ('addr', 'expected', 'actual', 'sev')

    def __init__(self, addr, expected=0, actual=0, sev='HIGH'):
        self.addr     = int(addr) if addr is not None else 0
        self.expected = int(expected) if expected is not None else 0
        self.actual   = int(actual) if actual is not None else 0
        self.sev      = str(sev) if sev else 'HIGH'


class ShadowStackDetector:
    # 通过反汇编模式匹配检测返回地址覆盖

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
        # 模式匹配栈写后跟 RET，返回违规列表
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
        # 评估 ROP 韧性：满分 100，每条违规扣 15
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
    # 单次调用入口：扫描二进制并返回 ROP 韧性评估
    det = ShadowStackDetector(f_binpath)
    return det.assess_rop()
