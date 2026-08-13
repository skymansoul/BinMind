"""
F-SCORE 格式字符串误报削减 — 6阶段级联验证管道。
Stage F: 格式字面量 | Stage S: sanitizer | Stage C: 编译器守护
Stage O: 输出上下文 | Stage R: 引用追溯 | Stage E: 可利用性评估
原则: 仅编译期字面量可证安全→FILTER。用户可控无危险符→降级,不删除。
参考: scut/team teso, gcc -Wformat-security, CWE-134
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class FmtVerdict(Enum):
    SAFE_LITERAL = "safe_literal"
    SAFE_SANITIZED = "safe_sanitized"
    LIKELY_FP = "likely_fp"
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"


@dataclass
class FmtVerifyResult:
    func_name: str; fmt_func: str; fmt_arg: str
    verdict: FmtVerdict; confidence: float; reason: str
    is_literal: bool = False; is_user_controlled: bool = False
    output_target: str = "stdout"
    dangerous_specs: List[str] = field(default_factory=list)
    stage: str = ""


@dataclass
class FmtVerifyStats:
    total: int = 0; safe_literal: int = 0; safe_sanitized: int = 0
    likely_fp: int = 0; confirmed: int = 0; uncertain: int = 0


# 格式函数 => {fmt_pos, output}
_FMT = {'printf':(0,'stdout'),'fprintf':(1,'file'),'dprintf':(1,'fd'),
    'sprintf':(1,'buffer'),'snprintf':(2,'buffer'),'syslog':(1,'syslog'),
    'vsyslog':(1,'syslog'),'err':(1,'stderr'),'errx':(1,'stderr'),
    'warn':(0,'stderr'),'warnx':(0,'stderr'),'setproctitle':(0,'proc')}

_USER_SRC = {'argv','getenv','read','fread','recv','recvfrom','recvmsg',
    'fgets','gets','scanf','fscanf','sscanf','getc','fgetc','getchar'}

_SANITIZERS = {'safe_printf','safe_fprintf','checked_sprintf',
    'log_printf','debug_printf','trace_printf','format_and_print','print_formatted'}

_LITERAL_RE = re.compile(r'"([^"\\]|\\.)*"')
_QUOTE_RE = re.compile(r"'([^'\\]|\\.)*'")


class FmtVerifier:
    """F-SCORE 6阶段格式字符串验证器。"""

    def verify(self, findings: List[dict],
               code: str = "", func_name: str = "") -> Tuple[List[dict], FmtVerifyStats]:
        stats = FmtVerifyStats(total=len(findings))
        refined = []
        _map = {FmtVerdict.SAFE_LITERAL: 'safe_literal',
                FmtVerdict.SAFE_SANITIZED: 'safe_sanitized',
                FmtVerdict.LIKELY_FP: 'likely_fp',
                FmtVerdict.CONFIRMED: 'confirmed',
                FmtVerdict.UNCERTAIN: 'uncertain'}
        for f in findings:
            r = self._verify_one(f, code, func_name)
            setattr(stats, _map[r.verdict], getattr(stats, _map[r.verdict]) + 1)
            f['fmt_verdict'] = r.verdict.value
            f['fmt_stage'] = r.stage; f['fmt_reason'] = r.reason
            f['confidence'] = r.confidence
            if r.verdict in (FmtVerdict.SAFE_LITERAL, FmtVerdict.SAFE_SANITIZED):
                f['severity'] = 'Info'
            elif r.verdict == FmtVerdict.CONFIRMED:
                f['severity'] = 'Critical'
                if r.dangerous_specs: f['dangerous_specs'] = r.dangerous_specs
            elif r.verdict == FmtVerdict.LIKELY_FP:
                f['severity'] = 'Low'
            refined.append(f)
        return refined, stats

    def _verify_one(self, f: dict, code: str, _fn: str) -> FmtVerifyResult:
        fmt_func = f.get('fmt_func', f.get('format_func', ''))
        fmt_arg = f.get('arg', f.get('format_arg', ''))
        # F→S→C cascade (early-exit on clear verdict)
        for stage_fn in [self._chk_literal, self._chk_sanitized, self._chk_compiler]:
            r = stage_fn(code, fmt_func, fmt_arg, f)
            if r: return r
        # O: output context
        output = _FMT.get(fmt_func, (0, 'stdout'))[1]
        # R: reference trace
        is_user = self._trace_user(code, fmt_arg)
        # E: exploitability
        return self._assess(fmt_func, fmt_arg, code, is_user, output)

    # Stage F: LITERAL ──────────────────────────

    def _chk_literal(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code or not func: return None
        pat = re.compile(re.escape(func) + r'\s*\((.*?)\)', re.DOTALL)
        for m in pat.finditer(code):
            args = self._split(m.group(1))
            pos = _FMT.get(func, (0,))[0]
            if pos < len(args):
                val = args[pos].strip()
                if _LITERAL_RE.match(val) or _QUOTE_RE.match(val):
                    return FmtVerifyResult(
                        func_name=f.get('function',''), fmt_func=func, fmt_arg=val,
                        verdict=FmtVerdict.SAFE_LITERAL, confidence=0.99,
                        is_literal=True, reason=f"literal: {val[:40]}", stage='F')
        return None

    # Stage S: SANITIZED ────────────────────────

    def _chk_sanitized(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code: return None
        for sn in _SANITIZERS:
            if sn in code and func == 'printf':
                return FmtVerifyResult(
                    func_name=f.get('function',''), fmt_func=func, fmt_arg=arg,
                    verdict=FmtVerdict.SAFE_SANITIZED, confidence=0.90,
                    reason=f"wrapper: {sn}", stage='S')
        return None

    # Stage C: COMPILER_GUARD ───────────────────

    def _chk_compiler(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code: return None
        if re.search(r'__attribute__\s*\(\s*\(\s*format\s*\(', code):
            return FmtVerifyResult(
                func_name=f.get('function',''), fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.LIKELY_FP, confidence=0.65,
                reason="compiler-guarded: __attribute__((format))", stage='C')
        return None

    # Stage R: REFERENCE_TRACE ──────────────────

    def _trace_user(self, code: str, arg: str) -> bool:
        if not code or not arg: return False
        for src in _USER_SRC:
            if re.search(rf'{re.escape(arg)}\s*=.*\b{src}\b', code): return True
        return False

    # Stage E: EXPLOITABILITY ───────────────────

    def _assess(self, func, arg, code, is_user, output) -> FmtVerifyResult:
        dangerous, conf = [], 0.5
        fmt_content = self._extract_fmt(code, func)
        if fmt_content:
            try:
                from analysis.format_spec_scorer import FormatSpecAnalyzer
                specs = FormatSpecAnalyzer.parse_format_string(fmt_content)
                dangerous = [s.raw for s in specs if s.risk.value >= 3]
                if not dangerous and specs:
                    return FmtVerifyResult(
                        func_name="", fmt_func=func, fmt_arg=arg,
                        verdict=FmtVerdict.SAFE_LITERAL, confidence=0.95,
                        reason=f"no dangerous: {[s.raw for s in specs[:3]]}",
                        stage='E', is_literal=True)
                if dangerous: conf = 0.90
            except ImportError:
                pass

        if is_user and not fmt_content: conf = 0.85

        sev = {'stdout':'info_leak','stderr':'info_leak','file':'log_injection',
               'fd':'log_injection','buffer':'buffer_overflow',
               'syslog':'privilege_escalation','proc':'proc_title_spoof'}.get(output,'?')

        if is_user or dangerous:
            return FmtVerifyResult(
                func_name="", fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.CONFIRMED if (is_user and dangerous) else FmtVerdict.LIKELY_FP,
                confidence=conf, is_user_controlled=is_user,
                output_target=output, dangerous_specs=dangerous,
                reason=f"exploit: user={is_user}, dangerous={dangerous} → {sev}", stage='E')

        return FmtVerifyResult(
            func_name="", fmt_func=func, fmt_arg=arg,
            verdict=FmtVerdict.UNCERTAIN, confidence=0.40,
            reason=f"insufficient info → {sev}", stage='E')

    # helpers ───────────────────────────────────

    def _extract_fmt(self, code, func) -> str:
        m = re.search(re.escape(func) + r'\s*\(\s*"((?:[^"\\]|\\.)*)"', code)
        return m.group(1) if m else ""

    @staticmethod
    def _split(s: str) -> List[str]:
        d=0; args=[]; cur=[]
        for ch in s:
            if ch=='(' : d+=1; cur.append(ch)
            elif ch==')': d-=1; cur.append(ch)
            elif ch==',' and d==0: args.append(''.join(cur).strip()); cur=[]
            else: cur.append(ch)
        if cur: args.append(''.join(cur).strip())
        return args


def verify_fmt_candidates(findings: List[dict], code: str = "",
                          func_name: str = "") -> Tuple[List[dict], FmtVerifyStats]:
    """F-SCORE 格式字符串验证便捷入口。"""
    return FmtVerifier().verify(findings, code, func_name)
